"""hash function"""

import hashlib
import secrets
import argon2


def generate_salt()->bytes:
    """Generate a random salt
    
    Returns:
        bytes: random salt
    """
    return secrets.token_bytes(16)






def hash_password(password:str)->str:
    """
    Hashes a password using SHA-256.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """


    # Generate a random salt
    salt = generate_salt()

    # Combine salt and password
    salted_password = salt + password.encode('utf-8')

    # Create an Argon2 password hasher
    ph = argon2.PasswordHasher()
    
    # Hash the password
    hashed_password = ph.hash(salted_password)


    # Create a new SHA-256 hash object
    hash_object = hashlib.sha256(hashed_password)

    # Get the hexadecimal representation of the hash
    hexadecimal_digest = hash_object.hexdigest()

    # Combine the hash and salt for storage (using a delimiter)
    return f"{hexadecimal_digest}:{salt.hex()}"

# Example usage:
if __name__ == "__main__":
    MY_PASSWORD = "mysecretpassword"
    HASHED= hash_password(MY_PASSWORD)
    print(HASHED)
