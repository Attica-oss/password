"""Password Manager"""
import os
import sys
from pathlib import Path
import getpass
from time import sleep
from typing import Tuple, Optional
import logging
from dataclasses import dataclass
import polars as pl

from src.hash.hash import hash_password
from src.encrypt import encrypt, decrypt
from src.pawnd.pawnd import pawned

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
@dataclass
class Config:
    """Configuration for the application"""
    csv_path: Path = Path("/home/gmoun/Project/hashfunction/src/key/saved_data.csv")

config = Config()

class PasswordManager:
    """Password Manager"""
    def __init__(self):
        self.df: Optional[pl.DataFrame] = None

    def clear_screen(self):
        """Clears the screen depending on the OS"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def greeting(self):
        """Greeting message"""
        print("""
Passkey Manager v.0.0.2
---------------------------
AtticaSoft (c) 2024

Select an option:
----- 1. Add Entry
----- 2. Find Entry by Service
----- 3. Password Pwned?
----- 4. Exit Application
""")

    def get_password(self, prompt: str = "Enter the password (press 'q' to exit): ") -> str:
        while True:
            password = getpass.getpass(prompt)
            if password.lower() == "q":
                self.exit_application()
            
            password2 = getpass.getpass("Re-enter the password: ")
            
            if password == password2:
                return password
            
            print("Passwords do not match! Try again?")
            if input("[y/n] ").lower() != "y":
                self.exit_application()

    def encrypt_password(self, password: str) -> bytes:
        return encrypt.encrypt_password(password)

    def decrypt_password(self, encrypted: bytes) -> str:
        return decrypt.decrypt_password(encrypted)

    def get_user_data(self) -> Tuple[str, bytes, str, str]:
        """
        Retrieves user data for a new password entry, including the service, password, and username.
        
        Prompts the user to input the service, password, and username, and then confirms whether to save the entry.
        
        Returns a tuple containing the service, encrypted password, hashed password, and username if the user confirms.
        
        If the user declines, exits the application.
        
        Parameters:
        None
        
        Returns:
        Tuple[str, bytes, str, str]: A tuple containing the service, encrypted password, hashed password, and username.
        """
        self.clear_screen()
        print("Add an entry")
        service = input("Enter the service: ")
        
        self.clear_screen()
        password = self.get_password()
        
        self.clear_screen()
        username = input("Enter your username: ")
        
        print(f"Save the {service}'s password with user: {username}? [y/n]")
        if input().lower() == "y":
            hashed_password = hash_password(password)
            encrypted_password = self.encrypt_password(password)
            return service, encrypted_password, hashed_password, username
        else:
            self.exit_application()

    def create_dataframe(self,
                         service: str,
                         password: bytes,
                         hashed_password: str,
                         username: str) -> pl.DataFrame:
        """ Creates a DataFrame with the given service,
        password, hashed password, and username. """
        return pl.DataFrame(
            {"service": [service], "password": [password],
             "hashed": [hashed_password], "username": [username]}
        )

    def save_df_csv(self, df: pl.DataFrame) -> None:
        """
        Saves a DataFrame to a CSV file.

        Parameters:
        df (pl.DataFrame): The DataFrame to save.

        Returns:
        None
        """
        try:
            if config.csv_path.exists():
                existing_df = pl.read_csv(config.csv_path)
                combined_df = pl.concat([existing_df, df],how="vertical")
            else:
                combined_df = df
            combined_df.write_csv(config.csv_path)
            logging.info("Data saved successfully to %s", config.csv_path)
        except Exception as e:
            logging.error(f"Error saving data: {e}")
            print("An error occurred while saving data. Please check the logs.")

    def find_entry(self, service: str) -> None:
        try:
            if self.df is None:
                self.df = pl.read_csv(config.csv_path)
            
            result = self.df.filter(pl.col("service") == service)
            if result.shape[0] == 0:
                print(f"No entry found for service: {service}")
            else:
                print(result.select(["service", "username"]))
                # Note: We don't display the password for security reasons
        except Exception as e:
            logging.error(f"Error finding entry: {e}")
            print("An error occurred while searching for the entry. Please check the logs.")

    def check_pwned(self) -> None:
        try:
            result = pawned(str(config.csv_path))
            print(result)
        except Exception as e:
            logging.error(f"Error checking pwned passwords: {e}")
            print("An error occurred while checking pwned passwords. Please check the logs.")

    def exit_application(self):
        """
        Exits the application by printing an exit message,
        pausing for a brief period, and then terminating the system process.
        
        Parameters:
        None
        
        Returns:
        None
        """
        print("Exiting the application....")
        sleep(1)
        sys.exit()

    def run(self):
        while True:
            self.clear_screen()
            self.greeting()
            try:
                choice = int(input("Select an option: "))
                if choice == 1:
                    service, password, hashed_password, username = self.get_user_data()
                    df = self.create_dataframe(service, password, hashed_password, username)
                    self.save_df_csv(df)
                elif choice == 2:
                    service = input("Enter the service name to search: ")
                    self.find_entry(service)
                elif choice == 3:
                    self.check_pwned()
                elif choice == 4:
                    self.exit_application()
                else:
                    raise ValueError("Invalid choice. Please select 1, 2, 3 or 4.")
            except ValueError as e:
                print(e)
                sleep(1)

if __name__ == "__main__":
    password_manager = PasswordManager()
    password_manager.run()
