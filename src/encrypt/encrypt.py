"""Encryption of String"""

from cryptography.fernet import Fernet
from src.key.key import load_key




def encrypt_password(password: str) -> str:
    """
    Encrypts a password using Fernet encryption.
    Args:
        password (str): The password to encrypt.
    Returns:
        str: The encrypted password as a base64 encoded string.
    """
    key = load_key()
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()
