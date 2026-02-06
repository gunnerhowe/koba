"""
Koba AI Containment SDK

One-line integration for AI safety:

    from koba import contain

    # Wrap any AI client
    client = contain(openai.OpenAI())

    # Use normally - Koba monitors everything
    response = client.chat.completions.create(...)
"""

from .wrapper import contain, KobaClient
from .config import configure

__version__ = "0.1.0"
__all__ = ["contain", "KobaClient", "configure"]
