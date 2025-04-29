#!/usr/bin/env python3
import hashlib, hmac, requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Hash import keccak, SHA256

# ⇒ добавляем это:
SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
# ────────────────────────────────────────────────────────────────────────

# ----- Configuration -----
MNEMONIC = "motor swarm typical timber alcohol claim gap physical merit craft autumn genre"
TRON_API_KEY = "eab8ef1e-293a-4085-a65f-e39752e46afb"
USDT_CONTRACT_ADDR = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # USDT TRC20 contract (base58)
# -------------------------

# BIP39 Seed derivation (PBKDF2-HMAC-SHA512)
seed = hashlib.pbkdf2_hmac('sha512', MNEMONIC.encode('utf-8'), b"mnemonic", 2048, dklen=64)

# BIP32 Master key derivation
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
master_priv = I[:32]
master_chain = I[32:]

# Helper function: CKD (Child Key Derivation) for private key (BIP32)
def derive_child(priv_key_bytes, chain_code, index):
    """Derive a child private key given parent key bytes, chain code, and index."""
    hardened = index >= 0x80000000
    # Prepare data for HMAC: 0x00 + priv for hardened, or compressed pub for non-hardened
    if hardened:
        data = b'\x00' + priv_key_bytes + index.to_bytes(4, 'big')
    else:
        # Get compressed public key from priv_key_bytes
        parent_priv_int = int.from_bytes(priv_key_bytes, 'big')
        parent_priv = ec.derive_private_key(parent_priv_int, ec.SECP256K1())
        parent_pub = parent_priv.public_key()
        # Compressed point: 33 bytes (0x02/0x03 + 32-byte X coordinate)
        pub_bytes = parent_pub.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.CompressedPoint
        )
        data = pub_bytes + index.to_bytes(4, 'big')
    # HMAC-SHA512 with parent chain code
    I = hmac.new(chain_code, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    # Calculate child private key: (IL + parent_priv) mod n
    IL_int = int.from_bytes(IL, 'big')
    curve_order = SECP256K1_ORDER
    if IL_int >= curve_order:
        # In rare case, derive next index
        return None, None, False
    parent_int = int.from_bytes(priv_key_bytes, 'big')
    child_int = (IL_int + parent_int) % curve_order
    if child_int == 0:
        return None, None, False
    child_priv = child_int.to_bytes(32, 'big')
    return child_priv, IR, True

# Derive keys for m/44'/195'/0'/0/0, 0/1, 0/2
# Indices with 0x80000000 added are hardened.
path_indices = [
    0x8000002C,  # 44'
    0x800000C3,  # 195'
    0x80000000,  # 0'
    0x00000000,  # 0  (external chain)
    # we'll vary the last index for additional addresses
]
derived_keys = []  # to store (pub_address, priv_key_hex, balance)
for addr_index in [0, 1, 2]:
    # Set the last index in path
    full_path = path_indices + [addr_index]
    priv_key = master_priv
    chain_code = master_chain
    for idx in full_path:
        priv_key, chain_code, ok = derive_child(priv_key, chain_code, idx)
        if not ok:
            # if derivation failed (very rare), skip to next index
            priv_key, chain_code, ok = derive_child(priv_key, chain_code, idx+1)
    # Compute TRON address from priv_key
    priv_int = int.from_bytes(priv_key, 'big')
    priv_obj = ec.derive_private_key(priv_int, ec.SECP256K1())
    pub_obj = priv_obj.public_key()
    # Uncompressed public key (65 bytes: 0x04 + X(32) + Y(32))
    pub_bytes = pub_obj.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    # Keccak-256 of the 64-byte raw public key (exclude the 0x04 prefix)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(pub_bytes[1:])  # skip 0x04
    h = keccak_hash.digest()
    # Take last 20 bytes and prepend 0x41
    addr_bytes = b'\x41' + h[-20:]
    # Compute checksum: first 4 bytes of double SHA256
    check = SHA256.new(SHA256.new(addr_bytes).digest()).digest()[:4]
    address_bytes = addr_bytes + check
    # Base58 encode
    ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    num = int.from_bytes(address_bytes, 'big')
    address = ""
    while num > 0:
        num, rem = divmod(num, 58)
        address = ALPHABET[rem] + address
    # Add leading '1' for each leading 0x00 byte
    for b in address_bytes:
        if b == 0:
            address = '1' + address
        else:
            break
    priv_hex = priv_key.hex()
    derived_keys.append((address, priv_hex))

# Prepare API request header with TronGrid API key
headers = {
    "Content-Type": "application/json",
    "TRON-PRO-API-KEY": TRON_API_KEY
}

# TRC20 balance check function
def get_usdt_balance(address):
    # Prepare parameter: 32-byte hex of address (without 0x41 prefix)
    # Decode base58 address to get last 20 bytes
    # (We can derive from our earlier computations instead to avoid decoding)
    # We'll recompute by reversing the base58 process for clarity:
    # Base58 decode:
    ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
    num = 0
    for ch in address:
        num = num * 58 + ALPHABET_INDEX[ch]
    # num now includes the 4-byte checksum at the end. Remove it:
    addr_bytes_with_prefix = num.to_bytes(25, 'big')
    tron_addr = addr_bytes_with_prefix[:-4]  # drop checksum
    # tron_addr should start with 0x41 for mainnet
    addr_hex = tron_addr[1:].hex()  # drop 0x41 for the parameter
    param = "000000000000000000000000" + addr_hex  # 24 leading zeros + address (40 hex chars)
    data = {
        "owner_address": address,
        "contract_address": USDT_CONTRACT_ADDR,
        "function_selector": "balanceOf(address)",
        "parameter": param,
        "visible": True
    }
    try:
        resp = requests.post("https://api.trongrid.io/wallet/triggerconstantcontract",
                             json=data, headers=headers, timeout=10)
        resp_json = resp.json()
    except Exception as e:
        return None  # in case of request failure
    # Parse the result
    if not resp_json.get("result", {}).get("result", False):
        # If result.result is False, the call failed (or address not activated, etc.)
        return 0
    constant_res = resp_json.get("constant_result")
    if not constant_res:
        return 0
    # constant_result is a list; the first element is the return data hex.
    balance_hex = constant_res[0]
    if balance_hex.startswith("0x"):
        balance_hex = balance_hex[2:]
    # Convert hex to int
    balance_int = int(balance_hex, 16)
    # Convert to float with 6 decimals (USDT has 6 decimals)
    balance_usdt = balance_int / 10**6
    return balance_usdt

# Fetch and display balances for each address
for addr, priv in derived_keys:
    balance = get_usdt_balance(addr)
    # Print address, private key, and balance
    print(f"Address: {addr}")
    print(f"Private Key: {priv}")
    if balance is None:
        print("USDT Balance: (unable to fetch)")
    else:
        # Format balance with 6 decimals
        print(f"USDT Balance: {balance:.6f}")
    print("-" * 40)