import re  # регулярные выражения для экранирования

def escape_md(text: str) -> str:
    """Экранирует спецсимволы Markdown."""
    if not isinstance(text, str):
        return text
    # place '-' at the end of the character class to avoid creating ranges
    return re.sub(r'([*_\[\]()~`>#+=|{}.!-])', r'\\\1', text)

