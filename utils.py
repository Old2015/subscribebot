import re  # регулярные выражения для экранирования

def escape_md(text: str) -> str:
    """Экранирует спецсимволы Markdown."""
    if not isinstance(text, str):
        return text
    return re.sub(r'([*_\[\]()~`>#+-=|{}.!])', r'\\\1', text)

