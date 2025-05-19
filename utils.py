import re

def escape_md(text: str) -> str:
    """Escape Markdown special characters."""
    if not isinstance(text, str):
        return text
    return re.sub(r'([*_\[\]()~`>#+-=|{}.!])', r'\\\1', text)
