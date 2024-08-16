"""Saves the data to a polars dataframe"""

import sys
import getpass
from time import sleep
import polars as pl
from hash import hash_password #type: ignore





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
        password = getpass.getpass("Enter your password: ")
        url = input("Enter the URL: ")

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
    data = {"username": [user_name], "password": [hash_password(passkey)], "url": [link]}
    return pl.DataFrame(data)

if __name__ == "__main__":
    print("""Passkey Manager v.0.0.1""")
    print("""AtticaSoft (c) 2024""")
    print("------------------------")
    user, pass_word, urls = get_user_data()
    print("""creating dataframe....""")
    sleep(3)
    df = create_dataframe(user, pass_word[5:], urls)
    print(df)
