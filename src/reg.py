import json
import os
import bcrypt
import getpass

from .encryption import *
from .networking import *

# from encrypt import *
# from decrypt import *
# from broadcast import *
# from receive_cert import *
# from listen import *
# from send_cert import *

# File to store user data
USER_FILE = 'users.json'
CONTACTS_FILE = 'contacts.json'

def print_logo():
    print("   _____                            ______ _ _        _______                   __")
    print("  / ____|                          |  ____(_) |      |__   __|                 / _|")
    print(" | (___   ___  ___ _   _ _ __ ___  | |__   _| | ___     | |_ __ __ _ _ __  ___| |_ ___ _ __")
    print("  \___ \ / _ \/ __| | | | '__/ _ \ |  __| | | |/ _ \    | | '__/ _` | '_ \/ __|  _/ _ \ '__|")
    print("  ____) |  __/ (__| |_| | | |  __/ | |    | | |  __/    | | | | (_| | | | \__ \ ||  __/ |")
    print(" |_____/ \___|\___|\__,_|_|  \___| |_|    |_|_|\___|    |_|_|  \__,_|_| |_|___/_| \___|_|")

def menu(name):
    print("(1) -> Add a new contact")
    print("(2) -> List Contacts")
    print("(3) -> Send a file")
    print("(4) -> Receive a file")
    print("(5) -> Exit")
    command = input("\n->  ")

    if command == '1':
        add_contact(name)
    elif command == '2':
        list_contacts(name)
    elif command == '3':
        print("todo: send file\n")
        send_email = input("Enter the email of the contact you want to send a file to: ")
        send_file = input("Enter the relative filepath of the file you wish to send: ")
        with open(CONTACTS_FILE, 'r') as file:
            data = json.load(file)
            for email, details in data.items():
                if (email == send_email):
                    ip = details.get('ip')
                    cert_path = details.get('cert_path')
            send(ip, send_file, cert_path)
        menu(name)
    elif command == '4':
        receive_email = input("Enter the email of the user sending you a file: ")
        with open(CONTACTS_FILE, 'r') as file:
            data = json.load(file)
            for email, details in data.items():
                if (email == receive_email):
                    cert_path = details.get('cert_path')
        receive(name + '.crt', name + '.key')
        menu(name)
    elif command == '5':
        exit() 
    else:
        print("Error: invalid selection\n")
        menu(name)


def add_contact(email):
    myemail = email + "@email.com"
    choice = input("\n\n(c) to create a new contact on your system," 
                   "or (d) to add your contact on somebody else's machine: ")
    if (choice == 'c' or choice == 'C'):
        contact_email = input("\nEnter the contact's email: ")
        
        users = load_users()

        # Check if the user exists
        if contact_email in users:
            print("email already exists in your contacts!")
            return

        broadcast_message("ADD CONTACT: " + contact_email, 12345)
        contact_ip = receive_cert()
        if contact_ip == 'x':
            print('serial number of certificate did not match known value, untrusted certificate')
            os.sys.remove('x.crt')
            menu(email)
        else:
            print("Valid certificate received...n")

        cert_path = contact_ip + ".crt"

        if contact_ip and cert_path:
        # Save the new contact's details in the contacts dictionary
            contacts = load_contacts()
            contacts[contact_email] = {'ip': contact_ip, 'cert_path': cert_path}
            save_contacts(contacts)
            print(f"Contact '{contact_email}' with IP {contact_ip} and certificate '{cert_path}' added successfully.")
        else:
            print("Failed to add contact. No response or certificate not trusted.")

    else:
        print(f"listening for broadcast with email: {myemail}")
        broadcast = listen_for_broadcast(myemail, 0)
        if (broadcast[0] == 'f'):
            print(f"Error listening for new contact.\n message =  {broadcast[0]} \n ip = {broadcast[1]}\n")
            return
        else:
            print(f"calling send cert with ip = {broadcast[1]}") 
            send_cert(broadcast[1], email + '.crt')

            

    menu(email)


def load_users():
    # Check if the user file exists
    if os.path.exists(USER_FILE):
        # Open the file in read mode
        with open(USER_FILE, 'r') as file:
            # Load and return the JSON data from the file
            return json.load(file)
    # Return an empty dictionary if the file does not exist
    return {}

# this function saves the user data back to a JSON file.
def save_users(users):
    # Open the file in write mode
    with open(USER_FILE, 'w') as file:
        # Write the users dictionary as JSON into the file
        # .dump() method provided by the json module, used to seritalize a Python object
        # into a Json-formatted string, and write it to a file-like object
        json.dump(users, file, indent=4)

def register_user():
    # Load existing users
    users = load_users()

    # Prompt the user to enter a username
    fullName = input("Please Enter Full Name: ")
    email = input("Please Enter Email Address: ")
    
    # Check if the full name or email already exists
    if fullName in users:
        print("A user with this full name already exists.")
        return
    
    # Check if the email already exists in the users dictionary
    # flag used to keep track of whether the email address has been found in the existing user data
    email_exists = False
    for user_info in users.values():
        if user_info['email'] == email:
            # If a match is found, it sets the email_exists flag to True.
            email_exists = True
            break
    
    if email_exists:
        print("A user with this email already exists.")
        return
    
    # Prompt the user to enter a password, securely hiding the input
    password = getpass.getpass("Enter password: ")
    
    # Prompt the user to re-enter the password for confirmation
    passwordConfirmation = getpass.getpass("Re-enter password: ")
    
    # Use a while loop to keep asking for the password until it matches the confirmation
    while password != passwordConfirmation:
        print("Passwords do not match. Please try again.")
        password = getpass.getpass("Enter password: ")
        passwordConfirmation = getpass.getpass("Re-enter password: ")
        # If the loop exits, passwords match, and you can proceed to hash the password
    
    # The password provided by the user is encoded to bytes, as bcrypt operates on bytes.
    password_bytes = password.encode('utf-8')
    
    # bcrypt.gensalt() generates a new salt for each password. 
    # This salt will be used in the hashing process to ensure that 
    # each password hash is unique, even if two users have the same password.
    salt = bcrypt.gensalt()
    
    # bcrypt.hashpw() takes the encoded password and the generated salt to produce a hashed password. 
    # The hashing process includes the salt automatically, so the result is a salted hash that can be stored securely.
    hashed_password = bcrypt.hashpw(password_bytes, salt)


    users[fullName] = {'email': email, 'password': hashed_password.decode('utf-8')}

    # Save the updated users dictionary to the file
    save_users(users)
    print(f"User {fullName} registered successfully.")


def verify_password(stored_user_password_hash, entered_password):
    return bcrypt.checkpw(entered_password.encode('utf-8'), stored_user_password_hash.encode('utf-8'))

def user_login():
    login_max = 3
    login_attempts = 0

    users = load_users()
    user_email = input("Enter Email Address: ")

    # Initialize user_full_name as None
    user_full_name = None

    # Search for the user by email and get their full name
    for name, user_data in users.items():
        if user_data['email'] == user_email:
            user_full_name = name
            break

    if user_full_name is None:
        print("Email not recognized.")
        return None

    stored_password_hash = users[user_full_name]['password']

    while login_attempts < login_max:
        password = getpass.getpass("Enter password: ")
        password_bytes = password.encode('utf-8')
        if bcrypt.checkpw(password_bytes, stored_password_hash.encode('utf-8')):
            print("Login successful!")
            return user_full_name  # Return the user's full name
        else:
            print("Password does not match.")
            login_attempts += 1
            if login_attempts == login_max:
                print("Maximum login attempts reached.")
                return None

    return None  # Return None if login was not successful

def save_contacts(contacts):
    with open(CONTACTS_FILE, 'w') as file:
        json.dump(contacts, file, indent=4)


def load_contacts():
    if os.path.exists(CONTACTS_FILE):
        with open(CONTACTS_FILE, 'r') as file:
            return json.load(file)
    return {}

def list_contacts(name):
    with open(CONTACTS_FILE, 'r') as file:
        data = json.load(file)
        print("\n\nContacts:\n")
        for email, details in data.items():
            ip = details.get('ip')
            cert_path = details.get('cert_path')
            print(f"{email} : {ip} : {cert_path}")
        print("\n")
        menu(name)
