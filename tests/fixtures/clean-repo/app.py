"""Tiny example module used as a clean-repo test fixture.

This file intentionally contains no credentials, tokens, or private keys.
It is here to give the scanner a non-empty Python file to walk over.
"""


def greet(name: str) -> str:
    """Return a friendly greeting."""
    return f"hello, {name}"


if __name__ == "__main__":
    print(greet("clean repo"))
