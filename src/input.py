"""User Interface"""

import os
import sys
import getpass
from time import sleep
import polars as pl
from src.hash.hash import hash_password  # type: ignore
from src.encrypt import encrypt, decrypt


def greeting():
    """Displays a title and options for the Passkey Manager."""
    print("""
Passkey Manager v.0.0.1
---------------------------
AtticaSoft (c) 2024

Select an option:
----- 1. Add Entry
----- 2. Find Entry by Service (To Do)
----- 3. Exit Application
""")


def clear_screen():
    """Clears the terminal screen."""
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")


def get_password(prompt="Enter the password (press 'q' to exit): "):
    """Prompts the user for a password, handling exits and mismatches."""
    while True:
        password = getpass.getpass(prompt)
        if password.lower() == "q":
            print("Exiting the application....")
            sleep(1)
            sys.exit()

        password2 = getpass.getpass("Re-enter the password: ")

        if password == password2:
            return password
        print("Passwords do not match! Try again?")
        choice = input("[y/n] ").lower()
        if choice == "n":
            print("Exiting the application....")
            sleep(1)
            sys.exit()
        elif choice != "y":
            print("Invalid answer: use [y/n]....")


def encrypt_password(password: str) -> bytes:
    """Encrypts the password for secure storage."""
    return encrypt.encrypt_password(password)


def decrypt_password(encrypted: bytes) -> str:
    """Decrypts the encrypted password for display."""
    return decrypt.decrypt_password(encrypted)


def get_user_data():
    """Prompts the user for service, username, and password, with confirmation.

    Returns:
        tuple: A tuple containing the service name, hashed password, and username.
    """
    while True:
        clear_screen()
        print("Add an entry")
        service = input("Enter the service: ")

        clear_screen()
        password = get_password()

        clear_screen()
        username = input("Enter your username: ")

        print(f"Save the {service}'s password with user: {username}? [y/n]")
        response = input().lower()
        if response == "y":
            hashed_password = hash_password(password)
            return service, hashed_password, username
        if response == "q":
            print("Exiting the application....")
            sleep(3)
            sys.exit()


def create_dataframe(service: str, hashed_password: str, username: str) -> pl.DataFrame:
    """Creates a Polars DataFrame from user data, storing password as a hash."""
    data = {"service": [service], "password": [hashed_password], "username": [username]}
    return pl.DataFrame(data)


def main():
    """The main function that runs the Passkey Manager."""
    greeting()

    while True:
        try:
            choice = int(input("Select an option: "))
            if choice == 1:
                clear_screen()
                user, hashed_password, urls = get_user_data()
                print("Creating dataframe....")
                sleep(3)
                df = create_dataframe(user, hashed_password, urls)
                print(df)
                sleep(1)
            elif choice == 2:
                clear_screen()
                print(NotImplementedError("Find Entry by Service Not Implemented Yet"))
                sleep(1)
            elif choice == 3:
                clear_screen()
                print("Exiting the application....")
                sleep(1)
                sys.exit()
            else:
                raise ValueError("Invalid choice. Please select 1, 2, or 3.")
        except ValueError as e:
            print(e)
            sleep(1)


if __name__ == "__main__":
    main()
