"""Encryption of hashed password"""

import hashlib
import secrets
import base64
import pyargon2





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
