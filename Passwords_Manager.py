import secrets, bz2, base64
from logging import warning, error
from string import ascii_lowercase, ascii_uppercase, digits, punctuation

current_user = input("Enter username: ") + "\n"

def encrypt_file(encrypt: bool):
    with open(text_file, "r") as file:
        data = file.read()
    if encrypt:
        with open(text_file, "wb") as file:
            data = data.encode()
            data = bz2.compress(data)
            data = base64.b64encode(data)
            file.write(data)
    else:
        with open(text_file, "wb") as file:
            try:
                data = base64.b64decode(data)
                data = bz2.decompress(data)
                file.write(data)
            except Exception:
                pass

def load_text_file():
    global passwords, lines
    try:
        if not base64.b64encode(base64.b64decode(open(text_file, "r").read())) == open(text_file, "rb").read():
            encrypt_file(True)
    except Exception:
        pass
    encrypt_file(False)
    global current_user
    if current_user in lines:
        index = lines.index(current_user)
        for i, j in zip(lines[index-2].split(), lines[index-1].split()):
            passwords[i] = j
    else:
        print("User not found!")
        create = input("Would you like to create a user as {}?(Y/N) ".format(current_user.removesuffix("\n")))
        if "y" == create.lower():
            master_pass = input("Enter a master password for your user: ")
            passwords["master"] = master_pass
            write_to_file(password_for="master", password=master_pass, username=current_user)
        else:
            quit()
    encrypt_file(True)

def ask_master_password():
    """Asks the user for a specific password in order to access the password manager.
    Exits the process if the password is entered incorrectly 5 times."""
    if "master" not in passwords:
        passwords["master"] = input("Enter a master password: ")
        write_to_file(password_for="master", password=passwords["master"])
        print("Welcome, {}! What would you like to do today?\n(A)dd password, "
      "(G)et password, (L)ist commands, (Ch)ange password, (U)sername change, (D)elete password, (NU)New User, (SW)itch User, (DU)Delete User or (Q)uit".format(current_user.removesuffix('\n')))

    else:
        master_pass = input("Enter Master Password: ")
        for _ in range(4):
            if master_pass != passwords["master"]:
                warning(" [Wrong Password!]")
                status = "NO"
                master_pass = input("Enter Master Password: ")
            else:
                status = "YES"
                print("Welcome, {}! What would you like to do today?\n(A)dd password, "
      "(G)et password, (L)ist commands, (Ch)ange password, (U)sername change, (D)elete password, (NU)New User, (SW)itch User, (DU)Delete User or (Q)uit".format(current_user.removesuffix('\n')))
                break
        if status == "NO":
            error(" [Password Entered Incorrectly 5 Times! System Crash - Terminating Process]")
            quit()


def generate_password():
    """Generates a random password.
     Asks for special confirmation, in case the user wants to add a different password."""
     
    char = list(ascii_lowercase + ascii_uppercase + digits + punctuation)
    len_pwd = int(input("Enter length of password: "))
    generated = ""
    for _ in range(len_pwd):
        generated += secrets.choice(char)
    print(f"Password Generated: {generated}")
    while True:
        confirm = input("Press 'd' to change password or any other key to continue: ")
        if "d" in confirm.lower():
            generated = ""
            for _ in range(len_pwd):
                generated += secrets.choice(char)
            print(f"Password Generated: {generated}")
        else:
            return generated


def write_to_file(password_for="", password="", username=current_user):
    """Writes the given password name and password to a text file."""
    encrypt_file(False)
    if password_for and password:
        passwords[password_for] = password
    with open(text_file, "r") as file:
        lines = file.readlines()
        if username in lines:
            user_index = lines.index(username)
            lines = [item.removesuffix("\n") for item in lines]
            lines[user_index-2] = " ".join(list(passwords.keys()))
            lines[user_index-1] = " ".join(list(passwords.values()))
            lines[user_index] = username
            lines = [item + "\n" for item in lines]
        else:
            lines.append(password_for + " \n")
            lines.append(password + " \n")
            lines.append(username)
    with open(text_file, "w") as file:
        file.writelines(lines)
    encrypt_file(True)
    print("Password Added!")


def is_password_name_valid(pwd_for: str):
    """Doesn't allow the program to have two same password names.
    If a password already exists with the same name, then it restricts the program from entering the same name 
    and asks to enter a copy of the password name with a number attached to it."""
    
    if pwd_for in passwords:
        print(f"Sorry! Can't add password for {pwd_for} as it already exists!")
        for i in range(len(passwords)):
            new_pass = pwd_for.join(str(i))
            if new_pass not in passwords:
                break
        add_new = input(f"Would you like to create a password for {new_pass}? ")
        if "y" in add_new.lower():
            return new_pass
        else:
            return False
    else:
        return pwd_for
                            
def create_password(pwd_for, change=False):
    if not change:
        pass_name = is_password_name_valid(pwd_for)
    else:
        pass_name = True
    if pass_name:
        custom_or_generate = input("Add Custom Password or Generate New Password(C/G): ")
        if "g" in custom_or_generate.lower():
            generated = generate_password()
            write_to_file(password_for=pass_name, password=generated)
        elif "c" in custom_or_generate.lower():
            pwd = input("Enter Password: ")
            write_to_file(password_for=pass_name, password=pwd) 
        

def main():
    global current_user
    user_input = input(">>> ").lower()
    if "a" == user_input:
        pwd_name = input("Enter password for: ")
        create_password(pwd_name)
    elif "g" == user_input:
        get_pass_for = input("Get password for: ")
        if get_pass_for in passwords:
            print(passwords[get_pass_for])
        else:
            print(f"Sorry! You have not created a password for {get_pass_for}")
            ask_for_new_pass = input("Would you like to create a new password for that?(Y/N) ")
            if "y" in ask_for_new_pass.lower():
                create_password(get_pass_for)
    elif "ch" == user_input:
        change_pass_for = input("Change password for: ")
        if change_pass_for in passwords:
            name_or_pass = input("Change name or password?(N/P) ")
            if name_or_pass == "p":
                create_password(change_pass_for, change=True)
            elif name_or_pass == "n":
                pass_name = input("Enter new password name: ")
                if is_password_name_valid(pass_name):
                    passwords[pass_name] = passwords[change_pass_for]
                    del passwords[change_pass_for]
                    write_to_file(password_for=pass_name)
        else:
            print(f"Sorry! You have not created a password for {change_pass_for}")
            ask_for_new_pass = input("Would you like to create a new password for that?(Y/N) ")
            if "y" in ask_for_new_pass.lower():
                create_password(change_pass_for)
    elif "d" == user_input:
        del_pass_for = input("Delete password for: ")
        if del_pass_for in passwords:
            if "y" in input(f"Are you sure you want to delete the password for {del_pass_for}?(Y/N) "):
                del passwords[del_pass_for]
                write_to_file()
        else:
            print(f"Sorry! You have not created a password for {del_pass_for}")
            ask_for_new_pass = input("Would you like to create a new password for that?(Y/N) ")
            if "y" in ask_for_new_pass.lower():
                create_password(del_pass_for)
    elif "u" == user_input:
        write_to_file(username=input("Enter new username: "))
    elif "l" == user_input:
        print("""(L)ist Commands - Use this command to know the functions of this password manager.
(G)et password - Use this function to retrieve the password of a particular item.
(Ch)ange password - Use this function to change the name of a password or to change the password itself.
(A)dd password - Use this function to add a new custom or generated password to your passwords manager.
(D)elete password - Use this function to delete a certain password permanently. (Note: You cannot retrieve this password in any way)
(Q)uit - Press 'q' to exit the passwords manager.
(U)sername Change - Use this function to change your username!
(NU)New User - Add a new user to the password manager (Note: You will need to restart the manager to apply the changes!)
(SW)itch users - Use this command to switch the user who is currently using the passwords manager.
(DU)Delete user - Use this command to delete a user from the password manager.""")
    elif "nu" == user_input:
        passwords.clear()
        passwords["master"] = input("Enter a master password: ")
        current_user = input("Enter username: ") + "\n"
        write_to_file(password_for="master", password=passwords["master"], username=current_user)
        print("Restart the manager to make the changes!"), quit()
    elif "sw" == user_input:
        passwords.clear()
        user_changed = input("Enter username: ") + "\n"
        if user_changed != current_user:
            current_user = user_changed
            ask_master_password()
        else:
            print("[!] The username you have entered is the current user which is being used by you.")
            
    elif "du" == user_input:
        delete_user = input("Enter the username of the user you want to delete: ")
        if delete_user != current_user and str(delete_user + "\n") in lines:
            index = lines.index(delete_user + "\n")
            temp_pass = {}
            for pf, p in zip(lines[index-2].split(), lines[index-1].split()):
                temp_pass[pf] = p
            master_pass = input("Enter the master password of the user you want to delete: ")
            if master_pass == temp_pass["master"]:
                lines.remove(lines[index-2])
                lines.remove(lines[index-1])
                temp_pass.clear()
                passwords.clear()
                with open(text_file, "w") as f:
                    f.writelines(lines)
            print("User Deleted!")
    elif "q" == user_input:
        quit()


if __name__ == "__main__":
    text_file = r"D:\\Vihaan Files\\Coding\\Hello2\\Manger.idc"
    with open(text_file, "r") as r:
        lines = r.readlines()
        passwords = {}

    load_text_file()
    ask_master_password()

    while True:
        main()
