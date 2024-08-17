"""Saves the data to a polars dataframe"""
import os
import sys
import getpass
from time import sleep
import polars as pl
from hash import hash_password #type: ignore

def greeting()->None:
    """Title to show"""
    print("""Passkey Manager v.0.0.1""")
    print("------------------------")
    os.system("echo AtticaSoft '(c)' 2024")


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
        username = input("Enter your username: ")
        os.system("clear")

        while True:
            password = getpass.getpass("Enter the password: (press 'q' to exit) ")

            if password.lower() == 'q':
                answer = input("Are you sure you want to exit the application? [y/n]")
                if answer.lower() == 'y':
                    print("Exiting the application....")
                    sleep(1)
                    sys.exit()
                os.system("clear")
                continue

            password2 = getpass.getpass("Re-enter the password:  (press 'q' to exit)")

            if password.lower() == 'q':
                print("Exiting the application....")
                sleep(1)
                sys.exit()
          
            if password == password2:
                break
            print("Passwords do not match. Please try again.")

        url = input("Enter the URL: ")
        os.system("clear")

        print(f"""Confirm if the
              Username: {username} and the 
              Url: {url} is correct [y/n].
              Use 'q' to quit""")
        response = input().lower()
        if response == "y":
            return username, password, url
        if response == "q":
            print("Exiting the application....")
            sleep(3)
            sys.exit()

def create_dataframe(user_name:str, passkey:str, link:str)->pl.DataFrame:
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
    data = {"username": [user_name], "key": [hash_password(passkey)], "url": [link]}
    return pl.DataFrame(data)

if __name__ == "__main__":
    greeting()
    user, pass_word, urls = get_user_data()
    print("""creating dataframe....""")
    sleep(3)
    df = create_dataframe(user, pass_word, urls)
    print(df)
