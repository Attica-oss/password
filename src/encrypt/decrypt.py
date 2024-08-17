"""Encryption of String"""

from cryptography.fernet import Fernet
from src.key.key import load_key


def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypts a password using Fernet encryption.
    Args:
        encrypted_password (str): The password to encrypt.
    Returns:
        str: The decrypted password as a base64 encoded string.
    """
    key = load_key()
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password.encode())
    return decrypted.decode()
