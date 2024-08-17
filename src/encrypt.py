"""Encryption of String"""

from pathlib import Path
from cryptography.fernet import Fernet

KEY_PATH:Path = Path.cwd() / "key.key"

def write_key() -> None:
    """
    Generates a key and saves it into a file securely.
    """
    key = Fernet.generate_key()

    if (KEY_PATH).exists():
        print("Key already exists.")
    with open(KEY_PATH, "wb") as key_file:
        key_file.write(key)

def load_key() -> bytes:
    """
    Loads the encryption key from the `key.key` file.
    Returns:
        bytes: The encryption key.
    """
    with open(Path.cwd() / "key.key", "rb") as key_file:
        return key_file.read()

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
