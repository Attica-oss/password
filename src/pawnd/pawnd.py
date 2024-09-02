""" Application to check if Password have been Pwned!"""

import hashlib
import csv
from pathlib import Path
import requests
import polars as pl

from src.encrypt.decrypt import decrypt_password


def request_api_data(query_char: str) -> requests.Response:
    """Request the API data

    Args:
        query_char (str): The first 5 characters of the password

    Returns:
        requests.Response: The response from the API
    
    """
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url,timeout=10)
    if res.status_code != 200:
        raise RuntimeError(
            f"Error fetching: {res.status_code} check the API and retry."
        )
    return res


def get_password_leak_count(hashes, hash_to_check) -> int:
    """gets the count of leaks from the API

    Args:
        hashes (requests.Response): The response from the API
        hash_to_check (str): The hash to check

    Returns:
        int: The count of leaks
    
    """

    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    """
    check if the password is in the response data

    Args:
        password (str): The password to check

    Returns:
        int: The count of leaks
    """

    passwordsha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5char, tail = passwordsha1[:5], passwordsha1[5:]
    response = request_api_data(first5char)
    return get_password_leak_count(response, tail)


def open_csv(filename):
    """Open the csv file"""
    with open(filename, mode="r", newline="", encoding="utf8") as file:
        reader = csv.reader(file, delimiter=",")
        # store the headers in a separate variable,
        _ = next(reader)

        # output list to store all rows
        passwords = []
        for row in reader:
            passwords.append(row[1])
        return passwords


def load_csv(filename: Path) -> list:
    """loads the csv

    Args:
        filename (Path): The path to the csv file

    Returns:
        list: The list of passwords
    
    """
    return (
        pl.read_csv(filename)
        .select(pl.col("password").str.replace("\n", ""))
        .to_series()
        .to_list()
    )


def pawned(file):
    """the main file"""
    passwords = load_csv(file)
    for i in passwords:
        decode = decrypt_password(i)
        count = pwned_api_check(decode)
        if count:
            print(f"{decode} has been found {count} times...")
        else:
            print(f"{i} has NOT been found.")
    return "done."
