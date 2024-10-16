# -------------------------------------------------------------------------------#
#                       Simple password manager                                 #
#                           By Rasmus Wiuff                                     #
# Based on https://thepythoncode.com/article/build-a-password-manager-in-python #
# -------------------------------------------------------------------------------#

import json
import hashlib
import getpass
import os
import pyperclip
import sys
from cryptography.fernet import Fernet


# Function for Hashing the Master Password.
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()


# Function to encrypt a password.
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()


# Function to decrypt a  password.
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()


# Function to register you.
def register(master_password):
    # Encrypt the master password before storing it
    hashed_master_password = hash_password(master_password)
    user_data = {'username': "User",
                 'master_password': hashed_master_password}
    file_name = 'user_data.json'

    if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration complete!!\n")


# Function to log you in.
def login(entered_password):
    with open('user_data.json', 'r') as file:
        user_data = json.load(file)

    stored_password_hash = user_data.get('master_password')
    entered_password_hash = hash_password(entered_password)

    if entered_password_hash == stored_password_hash:
        print("\n[+] Login Successful..\n")
    else:
        print(
            "\n[-] Invalid credentials.\n")
        sys.exit()


# Function to view saved sites.
def view_sites():
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            print("Logins you saved...\n")
            for x in view:
                print(x['site'])
            print('\n')
    except FileNotFoundError:
        print("\n[-] You have not saved any logins!\n")


# Function to add (save password).
def add_login(site, username, password, cipher):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        # If passwords.json doesn't exist, initialize it with an empty list
        data = []
    else:
        # Load existing data from passwords.json
        try:
            with open('passwords.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            # Handle the case where passwords.json is empty or invalid JSON.
            data = []

    # Encrypt the password
    encrypted_password = encrypt_password(cipher, password)

    # Create a dictionary to store the site and password
    password_entry = {'site': site, 'username': username, 'password': encrypted_password}
    data.append(password_entry)

    # Save the updated list back to passwords.json
    with open('passwords.json', 'w') as file:
        json.dump(data, file, indent=4)


# Function to retrieve a saved password.
def get_login(site, cipher):
    # Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        return None

    # Load existing data from passwords.json
    try:
        with open('passwords.json', 'r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    # Loop through all the sites and check if the requested site exists.
    for entry in data:
        if entry['site'] == site:
            # Decrypt and return the password
            decrypted_password = decrypt_password(cipher, entry['password'])
            username = entry['username']
            return username, decrypted_password

    return None


def main():
    # Load or generate the encryption key.
    key_filename = 'encryption_key.key'
    if os.path.exists(key_filename):
        with open(key_filename, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(key_filename, 'wb') as key_file:
            key_file.write(key)
    cipher = Fernet(key)
    file = 'user_data.json'
    if os.path.exists(file) and os.path.getsize(file) != 0:
        print("\n[+] Found user")
        master_password = getpass.getpass("Enter your master password: ")
        login(master_password)
        print("\n[+] Login successful")
    else:
        print("\n[+] Creating user")
        master_password = getpass.getpass("Enter your master password: ")
        register(master_password)
    # Various options after a successful Login.
    while True:
        print("1. Add Login")
        print("2. Get Login")
        print("3. View Saved Logins")
        print("4. Quit")
        match input("Enter your choice: "):
            case '1':  # If a user wants to add a password
                site = input("Enter site: ")
                username = input("Enter username: ")
                password = getpass.getpass("Enter password: ")
                # Encrypt and add the password
                add_login(site, username, password, cipher)
                print("\n[+] Password added!\n")
            case '2':  # If a User wants to retrieve a password
                site = input("Enter site: ")
                username, decrypted_password = get_login(site, cipher)
                if site and decrypted_password:
                    pyperclip.copy(decrypted_password)
                    print(f"\n[+] Username for {site}: {username}")
                    print(f"\n[+] Password for {site}: {decrypted_password}")
                    print("\n[+] Password copied to clipboard.\n")
                else:
                    print("\n[-] Password not found! Did you save the password?"
                          "\n[-] Use option 3 to see the sites you saved.\n")
            case '3':  # If a user wants to view saved sites
                view_sites()
            case '4':  # If a user wants to quit the password manager
                break
