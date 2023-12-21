from src.reg import *

if __name__ == "__main__":
    users = load_users()

    if users:
        user_full_name = user_login()
        if user_full_name:
            print_logo()
            menu(user_full_name)
    else:
        print("No users are registered with this client.")
        if input("Do you want to register a new user (y/n)? ").lower() == 'y':
            register_user()
