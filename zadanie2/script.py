import subprocess
import os
import shutil

C_EXECUTABLE = "./zadanie2"  # Replace with your compiled C executable path
HESLA_CSV = "hesla.csv"
HESLA_CSV_BAK = "hesla.csv.bak"
INFO_TXT = "info.txt"
MAKE_COMMAND = ["make", "compile"]
def test_compilation():
    """Tests if the C code can be compiled using 'make'."""
    print("\n--- Testing Compilation ---")
    try:
        process = subprocess.run(
            MAKE_COMMAND,
            check=True,  # Raise an exception if make fails
            capture_output=True,
            text=True
        )
        print("Compilation PASSED.")
        return True
    except subprocess.CalledProcessError as e:
        print("Compilation FAILED!")
        print(f"Return Code: {e.returncode}")
        print(f"STDOUT:\n{e.stdout}")
        print(f"STDERR:\n{e.stderr}")
        print("\n--- Compilation Test Failed - Exiting ---")
        exit(1)
        return False
    except FileNotFoundError:
        print(f"Error: '{MAKE_COMMAND}' command not found. Make sure 'make' is installed and in your PATH.")
        print("\n--- Compilation Test Failed - Exiting ---")
        exit(1)
        return False
def backup_hesla_csv():
    """Creates a backup of hesla.csv."""
    if os.path.exists(HESLA_CSV):
        shutil.copyfile(HESLA_CSV, HESLA_CSV_BAK)
        print(f"Backup created: {HESLA_CSV_BAK}")
    else:
        print(f"Warning: {HESLA_CSV} not found, test might not be in a clean state.")

def restore_hesla_csv():
    """Restores hesla.csv from backup."""
    if os.path.exists(HESLA_CSV_BAK):
        shutil.copyfile(HESLA_CSV_BAK, HESLA_CSV)
    else:
        print(f"Warning: Backup {HESLA_CSV_BAK} not found, cannot restore.")

def run_test(username, password, otp_key, expected_output, test_name):
    """Runs the C program with given inputs and checks the output."""
    process = subprocess.Popen(
        [C_EXECUTABLE],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    inputs = f"{username}\n{password}\n{otp_key}\n"
    stdout, stderr = process.communicate(input=inputs)
    actual_output = stdout.strip()

    if stderr:
        print(f"STDERR:\n{stderr}")

    if expected_output in actual_output:
        return True
    else:
        print(f"Test '{test_name}' FAILED: Expected '{expected_output}', got '{actual_output}'")
        print(f"STDOUT:\n{stdout}")
        print(f"\n--- Contents of {HESLA_CSV} on FAILURE ---")
        with open(HESLA_CSV, 'r') as f:
            print(f.read())
        exit(1) # Exit immediately on failure to inspect output
        return False

def get_user_data_from_csv(username):
    """Reads hesla.csv and returns user data (password_hash, keys_list) or None if not found."""
    if not os.path.exists(HESLA_CSV):
        return None

    with open(HESLA_CSV, 'r') as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 3 and parts[0] == username:
                return {'password_hash': parts[1], 'keys': parts[2].split(",")}
    return None


def get_users_from_info_txt():
    """Reads info.txt and returns a list of user dictionaries (username, password)."""
    users = []
    if not os.path.exists(INFO_TXT):
        print(f"Warning: {INFO_TXT} not found. No users loaded from info.txt.")
        return users

    with open(INFO_TXT, 'r') as f:
        for line in f:
            line = line.strip()
            if line and ":" in line:
                username, password = line.split(":", 1)
                users.append({'username': username, 'password': password})
    return users

def check_key_removed(username, password, used_otp_key):
    """Checks if the used OTP key is removed from hesla.csv for a given username."""
    initial_data = get_user_data_from_csv(username)
    if initial_data is None:
        print(f"Warning: User '{username}' not found in {HESLA_CSV} before check.")
        return False
    initial_keys = initial_data['keys']

    run_test(username, password, used_otp_key, "ok", f"Check Key Removal - Using Key: {used_otp_key}")

    final_data = get_user_data_from_csv(username)
    if final_data is None:
        print(f"Warning: User '{username}' not found in {HESLA_CSV} after test.")
        return False
    final_keys = final_data['keys']

    if used_otp_key in initial_keys and used_otp_key not in final_keys:
        return True
    elif used_otp_key in initial_keys and used_otp_key in final_keys:
        print(f"Error: Key '{used_otp_key}' was NOT removed from user '{username}'.")
        return False
    elif used_otp_key not in initial_keys:
        print(f"Warning: Key '{used_otp_key}' was not initially in user '{username}'s key list.")
        return False
    else:
        print(f"Unexpected state when checking key removal for user '{username}' and key '{used_otp_key}'.")
        return False

def check_login_fails_no_keys_left(username, password):
    """Tests if login fails after all OTP keys are used and removed."""
    initial_data = get_user_data_from_csv(username)
    if initial_data is None:
        print(f"Warning: User '{username}' not found in {HESLA_CSV} before check.")
        return False
    initial_keys = initial_data['keys']

    if not initial_keys or not initial_keys[0]: # Check if keys list is empty or contains only empty string
        print(f"Info: User '{username}' already has no keys at start of test.")
        return True # Assume pass if no keys to begin with


    for key in list(initial_keys): # Iterate over a copy to avoid modification issues
        run_test(username, password, key, "ok", f"{username} - Using Key: {key} (to deplete keys)")

    # Now try to login again with any key (even a previously valid one) - should fail
    test_result_no_keys = run_test(username, password, initial_keys[0], "chyba", f"{username} - Login Fails - No Keys Left (using key '{initial_keys[0]}')")

    final_data = get_user_data_from_csv(username)
    if final_data is None:
        print(f"Warning: User '{username}' not found in {HESLA_CSV} after test.")
        return False
    final_keys = final_data['keys']

    keys_list_empty_check = not final_keys or not final_keys[0] # Check if list is empty or contains only empty string

    if test_result_no_keys and keys_list_empty_check:
        return True
    else:
        print(f"Test FAILED: Login did NOT fail after using all keys for '{username}', or key list is not empty.")
        return False

def verify_hesla_csv_structure(initial_csv_content):
    """Verifies if hesla.csv structure is correct after tests, comparing to initial content."""
    current_csv_content = []
    with open(HESLA_CSV, 'r') as f:
        current_csv_content = f.readlines()

    if len(initial_csv_content) != len(current_csv_content):
        print(f"FAIL: hesla.csv line count changed. Initial: {len(initial_csv_content)}, Current: {len(current_csv_content)}")
        exit(1)
        return False

    all_lines_match = True
    for i in range(len(initial_csv_content)):
        initial_line = initial_csv_content[i].strip()
        current_line = current_csv_content[i].strip()

        initial_parts = initial_line.split(":")
        current_parts = current_line.split(":")

        if len(initial_parts) != 3 or len(current_parts) != 3:
            print(f"FAIL: Line {i+1} - Incorrect number of parts (expected 3, got {len(current_parts)}). Line content: '{current_line}'")
            exit(1)
            all_lines_match = False
            continue # Move to next line to check other lines

        if initial_parts[0] != current_parts[0] or initial_parts[1] != current_parts[1]: # Check username and password hash
            print(f"FAIL: Line {i+1} - Username or password hash mismatch for user '{initial_parts[0]}'.")
            exit(1)
            all_lines_match = False

    if all_lines_match:
        return True
    else:
        return False


if __name__ == "__main__":
    if not test_compilation():
        exit(1)
    if not os.path.exists(C_EXECUTABLE):
        print(f"Error: C executable '{C_EXECUTABLE}' not found. Compile your C code first.")
        exit(1)
    if not os.path.exists(HESLA_CSV):
        print(f"Error: {HESLA_CSV} file not found. Create it first with user data.")
        exit(1)
    if not os.path.exists(INFO_TXT):
        print(f"Error: {INFO_TXT} file not found. Create it first with user data.")
        exit(1)
    users = get_users_from_info_txt()
    if not users:
        print("Warning: No users loaded from info.txt. Tests might be limited.")

    backup_hesla_csv()
    initial_hesla_csv_content = []
    with open(HESLA_CSV, 'r') as f:
        initial_hesla_csv_content = f.readlines()


    test_results = []

    for user_data in users:
        username = user_data['username']
        password = user_data['password']
        user_csv_data = get_user_data_from_csv(username)
        if user_csv_data:
            otp_keys = user_csv_data['keys']
        else:
            otp_keys = None
        
        if otp_keys and otp_keys != [""]:
            first_key = otp_keys[0] if otp_keys else None
            last_key = otp_keys[-1] if otp_keys else None

            # --- Test Cases for each user ---

            # 1. Successful login with valid key (first key)
            if first_key:
                test_results.append(run_test(username, password, first_key, "ok", f"{username} - Valid Login {password} - First Key: {first_key}"))
                test_results.append(verify_hesla_csv_structure(initial_hesla_csv_content))
                restore_hesla_csv() # Restore before key removal check to keep tests independent
                test_results.append(check_key_removed(username, password, first_key))
                restore_hesla_csv() # Restore after key removal check

            # 2. Successful login with valid key (last key)
            if last_key and last_key != first_key:
                test_results.append(run_test(username, password, last_key, "ok", f"{username} - Valid Login - Last Key: {last_key}"))
                restore_hesla_csv()
                test_results.append(check_key_removed(username, password, last_key))
                restore_hesla_csv()

            # 3. Successful login with all valid keys individually
            for key in otp_keys:
                test_results.append(run_test(username, password, key, "ok", f"{username} - Valid Login - Key: {key}"))
                restore_hesla_csv()
                test_results.append(check_key_removed(username, password, key))
                restore_hesla_csv() # Restore after each key test

            # 4. Failed login with invalid key
            test_results.append(run_test(username, password, "invalid_otp_key", "chyba", f"{username} - Invalid Login - Invalid Key"))
            restore_hesla_csv() # Restore for next tests

            # 5. Test using all keys and login failure when no keys left
            test_results.append(check_login_fails_no_keys_left(username, password))
            test_results.append(verify_hesla_csv_structure(initial_hesla_csv_content))

        else:
            print(f"Warning: No OTP keys found for user '{username}' in {HESLA_CSV}. Skipping OTP key tests for this user.")
            input("Press enter if expected behaviour to continue")


        # 6. Failed login with incorrect password (test password validation still works)
        test_results.append(run_test(username, "wrongpassword", "123456", "chyba", f"{username} - Invalid Login - Wrong Password"))


    # 7. Verify hesla.csv structure after all tests
    test_results.append(verify_hesla_csv_structure(initial_hesla_csv_content))


    # --- Summarize Results ---
    print("\n--- Test Summary ---")
    passed_count = sum(test_results)
    total_tests = len(test_results)
    print(f"Total Tests: {total_tests}")
    print(f"Tests Passed: {passed_count}")
    print(f"Tests Failed: {total_tests - passed_count}")

    if passed_count == total_tests:
        print("\nAll tests PASSED!")
    else:
        print("\nSome tests FAILED.")

    restore_hesla_csv() # Final restore to ensure clean state.
    print("Testing complete.")