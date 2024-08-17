"""Encryption of hashed password"""
from pathlib import Path
import hashlib
import secrets
import base64
import pyargon2
from cryptography.fernet import Fernet


def write_key() -> None:
    """
    Generates a key and saves it into a file securely.
    """
    key = Fernet.generate_key()

    if (Path.cwd() / "key.key").exists():
        print("Key already exists.")
    with open(Path.cwd() / "key.key", "wb") as key_file:
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

def generate_salt() -> bytes:
    """
    Generates a random salt.
    Returns:
        bytes: The generated salt.
    """
    salt = secrets.token_bytes(16)
    return base64.b64encode(salt).decode('utf-8')

def argon_hashed(salt: bytes, password: bytes) -> bytes:
    """
    Hashes a password with Argon2 using the provided salt.
    Args:
        salt (bytes): The salt to use in hashing.
        password (str): The password to hash.
    Returns:
        bytes: The hashed password.
    """
    return pyargon2.hash(password, salt)

def hash_password(password: str) -> str:
    """
    Hashes and encrypts a password using Argon2 and SHA-256, then returns a secure string.
    Args:
        password (str): The password to hash.
    Returns:
        str: The hashed and encrypted password in the form `hash:salt`.
    """
    salt = generate_salt()
    argon_hash = argon_hashed(salt, password)

    # Encode the Argon2 hash before passing it to hashlib
    argon_hash_bytes = argon_hash.encode('utf-8')

    # SHA-256 hash of the Argon2 hashed password
    sha256_hash = hashlib.sha256(argon_hash_bytes).hexdigest()

    # Return a combination of the SHA-256 hash and the salt, base64 encoded for safety
    return f"{sha256_hash}:{salt}"

# Example usage:
if __name__ == "__main__":
    # write_key()
    load_key()
    MY_PASSWORD = "mysecretpassword"
    HASHED = hash_password(MY_PASSWORD)
    print(HASHED)
