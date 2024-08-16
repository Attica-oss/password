"""hash function"""

import hashlib

def hash_password(password:str)->str:
    """
    Hashes a password using SHA-256.

    Args:
        password (str): The password to be hashed.

    Returns:
        str: The hashed password.
    """
    # Create a new SHA-256 hash object
    hash_object = hashlib.sha256()

    # Convert the password to bytes and update the hash object
    hash_object.update(password.encode('utf-8'))

    # Get the hexadecimal representation of the hash
    hexadecimal_representaion = hash_object.hexdigest()

    return hexadecimal_representaion

# Example usage:
if __name__ == "__main__":
    MY_PASSWORD = "mysecretpassword"
    HASHED= hash_password(MY_PASSWORD)
    print(HASHED)
