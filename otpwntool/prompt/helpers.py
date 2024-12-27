
def get_tokens(text: str) -> list:
    """
    Get tokens from the input text.
    
    Args:
        text (str): The input text.
    
    Returns:
        list: A list of tokens extracted from the text.
    """
    tokens = text.split(' ')
    return tokens