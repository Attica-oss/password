"""Saves the data to a polars dataframe"""
import os
import sys
import getpass
from time import sleep
import polars as pl
from src.hash.hash import hash_password #type: ignore
from src.encrypt import encrypt,decrypt

def greeting()->None:
    """Title to show"""
    print("""Passkey Manager v.0.0.1""")
    print("------------------------")
    os.system("echo AtticaSoft '(c)' 2024")

def clear()->None:
    """Clears the terminal"""
    if os.name == "nt":
        os.system("cls")
    os.system("clear")


def get_password()->None:
    """Gets the password from the user"""
    password = getpass.getpass("Enter the password: (press 'q' to exit) ")

    if password.lower() == 'q':
        answer = input("Are you sure you want to exit the application? [y/n]")
        if answer.lower() == 'y':
            print("Exiting the application....")
            sleep(1)
            sys.exit()
        clear()

    password2 = getpass.getpass("Re-enter the password:  (press 'q' to exit)")

    if password.lower() == 'q':
        print("Exiting the application....")
        sleep(1)
        sys.exit()

    if password == password2:
        print("Password Matched!")
        return password
    return "Passwords do not match. Please try again."



def encrypt_password(password:str)->bytes:
    """Encrypt the password for local storage"""
    return encrypt.encrypt_password(password)

def decrypt_password(encrypted:bytes)->str:
    """Decrypt the password for local usage"""
    return decrypt.decrypt_password(encrypted)

def get_user_data():
    """Prompts the user for username, password, and URL, with confirmation.
    
    Returns:
        tuple: A tuple containing the username, password, and URL.

    Example:
        >>> get_user_data()
        Enter your username: example_user
        Enter your password: *********
        Enter the URL: https://example.com
        Confirm if the Username: example_user and Url:
        https://example.com is correct [y/n]. Use 'q' to quit
        y
        ('example_user', 'hashed_password', 'https://example.com')
    
    """
    while True:
        service = input("Enter the service: ")
        clear()

        while True:
            password = get_password()
            break
        clear()
        username = input("Enter your username: ")
        clear()

        print(f"""Save the {service}'s password with user: {username} ? [y/n]. """)
        response = input().lower()
        if response == "y":
            print("saved the data!")
            return service, password, username
        if response == "q":
            print("Exiting the application....")
            sleep(3)
            sys.exit()

def create_dataframe(service:str, passkey:str, user_name:str)->pl.DataFrame:
    """Creates a Polars DataFrame from the given data.

Args:
        username (str): The username to store in the DataFrame.
        password (str): The password to store in the DataFrame (will be hashed).
        url (str): The URL to store in the DataFrame.

    Returns:
        pl.DataFrame: A Polars DataFrame with the given data.

    Example:
        >>> df = create_dataframe('example_user', 'my_password', 'https://example.com')
        >>> print(df)
           username  password                url
        0  example_user  hashed_password  https://example.com

    
    """
    data = {"service": [service], "key": [hash_password(passkey)], "user": [user_name]}
    return pl.DataFrame(data)


def main()->None:
    """The main"""
    greeting()
    user, pass_word, urls = get_user_data()
    print("""creating dataframe....""")
    sleep(3)
    df = create_dataframe(user, pass_word, urls)
    print(df)
    sleep(1)
    print(encrypt_password(pass_word))
    print("**********************")
    print(decrypt_password(pass_word))

if __name__ == "__main__":
    main()
