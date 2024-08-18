"""Testing encryption and decryption"""
from cryptography.fernet import Fernet

# def get_key():
#     """Generate a key for encryption and decryption"""
#     with open("/home/gmoun/Project/hashfunction/key.key",'rb',encoding="utf8") as file:
#         return file



def test_encryption_decryption():
    """test the encryption and decryption"""
    key = Fernet.generate_key()
    f = Fernet(key)
    password = "test_password"
    encrypted = f.encrypt(password.encode())
    decrypted = f.decrypt(encrypted)
    # print(f"Original: {password}")
    # print(f"Encrypted: {encrypted}")
    # print(f"Decrypted: {decrypted.decode()}")
    assert password == decrypted.decode()

# test_encryption_decryption()
