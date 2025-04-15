import re
import os
import argon2
import logging
from argon2 import PasswordHasher

MAX_ATTEMPTS = 3
PASSWORD_FILE_NAME = "HASHED_PASSWORD"
LOGGER = logging.getLogger(__name__)
inputFile = ""
def main():
    if init_logger():
        user_names = get_validated_name()
        int1 = get_integer(1)
        int2 = get_integer(2)
        add_multiply_result = add_multiply_two_integers(int1, int2)
        input_filename = get_file_name(True, "input")
        output_filename = get_file_name(False, "output")
        get_and_verify_password()
        write_output(output_filename, user_names, int1, int2, add_multiply_result, input_filename)

def init_logger():
    initialize_correctly = False
    try:
        handler = logging.FileHandler("./LOGGER")
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        LOGGER.addHandler(handler)
        LOGGER.setLevel(logging.INFO)
        initialize_correctly = True
    except (PermissionError, IOError) as e:
        print("Logger Failed to Initialize. Please Try Again.")

    return initialize_correctly

def get_validated_name():
    while True:
        print("First and last name should be a maximum of 50 characters each.")
        print("Only one capital letter at the beginning is allowed.")
        print("After first capital, only letters a-z permitted.")
        first_name = input("Enter first name: ")
        last_name = input("Enter last name: ")

        if verify_name(first_name) and verify_name(last_name):
            return [first_name, last_name]
        else:
            print("Invalid name format! Please try again.")

def verify_name(name):
    pattern = r"^[A-Z][a-z]{1,49}$"
    return bool(re.match(pattern, name))

def get_integer(num):
    while True:
        print("Valid integers are in range -2147483648 to 2147483647")
        prompt = f"Enter integer #{num}: "
        line = input(prompt)
        words = line.split()

        if words:
            entered_int = words[0]
            if validate_integer(entered_int):
                try:
                    return int(entered_int)
                except ValueError:
                    pass

        print("Invalid integer! Please try again.")

def validate_integer(input_str):
    pattern = r"^0$|^-?([1-9][0-9]{0,9})$"
    return bool(re.match(pattern, input_str)) and (-(2**31) <= int(input_str) <= (2**31 - 1))

def add_multiply_two_integers(num1, num2):
    return [num1 + num2, num1 * num2]

def get_file_name(check_if_file_exists, file_type):
    global inputFile
    while True:
        print("Valid filenames length must be between 1 and 50 characters. And end with a .txt extension")
        prompt = f"Enter a valid {file_type} filename: "
        line = input(prompt)
        words = line.split()
        if words:
            entered_filename = words[0]
            if validate_file_name(entered_filename):
                if file_type == "input":
                    inputFile = entered_filename
                    if not check_if_file_exists or os.path.exists(entered_filename):
                        return entered_filename
                elif file_type == "output":
                    if entered_filename == inputFile:
                        print("Error! file names match.")
                        continue
                    else:
                        if not check_if_file_exists or os.path.exists(entered_filename):
                            return entered_filename

        print("Invalid filename! Please try again.")

def validate_file_name(filename):
    pattern = r"^[A-Za-z0-9]{1,50}\.txt$"
    return bool(re.match(pattern, filename))

def get_and_verify_password():
    matching_password = False
    while not matching_password:
        get_hashed_password()
        matching_password = verify_password()

def get_hashed_password():
    valid_password_written = False
    while not valid_password_written:
        print("Valid password: At least one uppercase, one lowercase, one digit, one special character(?!,:;-{}()[]'\"), and is at least 10 characters long.")
        entered_password = input("Enter valid password: ")
        words = entered_password.split()

        if words:
            entered_password = words[0]
            if check_and_write_password(entered_password):
                valid_password_written = True
            else:
                print("Invalid Password! Please try again.")

def check_and_write_password(entered_password):
    pattern = r"^(?=.*[A-Z])(?=.*\d)(?=.*[a-z])(?=.*[?!,:;\-{}()\[\]'\"])(?!.*[a-z]{4})[A-Z\da-z?!,:;\-{}()\[\]'\"]{10,}"
    result = False

    if entered_password and re.match(pattern, entered_password):
        try:
            # Use Argon2 for password hashing
            ph = PasswordHasher()
            hashed_password = ph.hash(entered_password)

            with open(PASSWORD_FILE_NAME, 'w') as file:
                file.write(hashed_password)
            result = True
        except Exception as e:
            LOGGER.info(str(e))

    return result

def verify_password():
    matching_password = False
    file_ok = False
    hashed_password = None

    try:
        with open(PASSWORD_FILE_NAME, 'r') as file:
            hashed_password = file.readline().strip()
        file_ok = True
    except FileNotFoundError as e:
        LOGGER.info(str(e))

    if file_ok and hashed_password:
        confirmed_attempts = 0
        ph = PasswordHasher()

        while not matching_password and confirmed_attempts < MAX_ATTEMPTS:
            entered_password = input("Confirm password: ")
            words = entered_password.split()

            if words:
                entered_password = words[0]
                if validate_password_matches(entered_password, hashed_password):
                    matching_password = True
                else:
                    print("Invalid Password! Please try again.")
                    confirmed_attempts += 1

    return matching_password

def validate_password_matches(entered_password, hashed_password):
    is_valid_password = False

    if entered_password and hashed_password:
        try:
            ph = PasswordHasher()
            is_valid_password = ph.verify(hashed_password, entered_password)
        except argon2.exceptions.VerifyMismatchError:
            pass

    return is_valid_password

def write_output(output_filename, user_names, int1, int2, add_multiply_result, input_filename):
    try:
        with open(output_filename, 'w') as fw:
            fw.write(f"First Name: {user_names[0]}\n")
            fw.write(f"Last Name: {user_names[1]}\n")
            fw.write(f"Integer #1: {int1}\n")
            fw.write(f"Integer #2: {int2}\n")
            fw.write(f"Adding Result: {add_multiply_result[0]}\n")
            fw.write(f"Multiply Result: {add_multiply_result[1]}\n")
            fw.write("Input File Contents:\n")
            write_input_to_output(fw, input_filename)
    except IOError as e:
        LOGGER.info(str(e))

def write_input_to_output(fw, input_filename):
    try:
        with open(input_filename, 'r') as input_file:
            for line in input_file:
                fw.write(line)
    except IOError as e:
        LOGGER.info(str(e))
if __name__ == "__main__":
    main()