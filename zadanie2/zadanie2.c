#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1

#define ERROR_INVALID_PARSING 2     
#define ERROR_INVALID_HASH_SIZE 3  
#define ERROR_INVALID_INPUT_PARAMS 4 
#define ERROR_INVALID_AUTH_KEY 5  
#define ERROR_INVALID_AUTH_KEY_IND 6

#define USERS_COUNT 10

#define INFO_FILE "info.txt"
#define FILE_NAME "hesla.csv"
#define LINE_SIZE 256

#define MAX_AUTH_KEYS 10
#define AUTH_KEY_SIZE 8

#define HASH_SIZE 32
#define SALT "s0m3D3f@u1tS@lt"
#define HASH_FUNCTION "$2b$"

#define ASCII_START 33
#define ASCII_END 126
#define ASCII_RANGE (ASCII_END - ASCII_START + 1)
#define CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CHARSET_SIZE (sizeof(CHARSET) - 1) 

// struct to store user info from file
struct UserInfo {
    char *name;
    char *hashedPassword;
    char **auth_passwords;
    int num_auth_keys;
};

#pragma region Definitions
    void dynamic_scan(char **buffer);
    struct UserInfo *read_user_info_from_csv(const char *name);
    int parse_user_info(const char *line, struct UserInfo *usersInfo);
    char *generate_hashed_password(const char *password);
    void freeUserInfo(struct UserInfo *userInfo);
    int deleteOneTimeAuthKeyFromSystem(const char *authKey, const char *user);
    char **read_file_by_line();
    int write_user_info_into_csv(struct UserInfo userInfo[USERS_COUNT]);
    int checkAuthKey(const char *authKey, const char **userAuthKeys, int numKeys);
    char **createAuthKeys(const int userIndex);
    int parseUserInfo(struct UserInfo *user, char *line, int userIndex);
    int verify_user_credentials(const char *name, const char *password, const char *auth_key);
    void repeat_password_to_fixed_size(const char *password, char output[HASH_SIZE + 1]);
#pragma endregion

int main() {  
    char *name =  NULL;
    char *password;
    char *auth_key;

    // get user name
    printf("meno: ");
    dynamic_scan(&name);
    if(name == NULL) {
        printf("chyba\n");
        return EXIT_FAILURE;
    }

    // get user password
    printf("heslo: ");
    dynamic_scan(&password);
    if(password == NULL) {
        printf("chyba\n");

        free(name);

        return EXIT_FAILURE;
    }

    // get user one-time authentication key
    printf("overovaci kluc: ");
    dynamic_scan(&auth_key);
    if(auth_key == NULL) {
        printf("chyba\n");

        free(name);
        free(password);

        return EXIT_FAILURE;
    }
    
    // verify user using 2FA
    int isVerified = verify_user_credentials(name, password, auth_key);
    if(isVerified != 0) {
        printf("chyba\n");
    } else {
        printf("ok\n");
    }

    // free allocated memory
    free(name);
    free(password);
    free(auth_key);

    return EXIT_SUCCESS;
}


#pragma region CoreUtilities
    /**
     * Verifies user credentials by checking the hashed password and authentication key.
     * @return an error code or success.
     */
    int verify_user_credentials(const char *name, const char *password, const char *auth_key) {
        // Read user info from CSV
        struct UserInfo *userInfo = read_user_info_from_csv(name);
        if (!userInfo) {
            return EXIT_FAILURE;
        }
        
        // Hash the provided password
        char *hashedPassword = generate_hashed_password(password);
        if (!hashedPassword) {
            freeUserInfo(userInfo);
            free(userInfo);
            return EXIT_FAILURE;
        }

        // Compare stored and entered hashed passwords
        if (strcmp(userInfo->hashedPassword, hashedPassword) != 0) {
            free(hashedPassword);
            freeUserInfo(userInfo);
            free(userInfo);
            return EXIT_FAILURE;
        }

        // Check authentication key (2FA)
        if (checkAuthKey(auth_key, (const char **)userInfo->auth_passwords, userInfo->num_auth_keys) != EXIT_SUCCESS) {
            free(hashedPassword);
            freeUserInfo(userInfo);
            free(userInfo);
            return EXIT_FAILURE;
        }

        // delete used authentication key
        if(deleteOneTimeAuthKeyFromSystem(auth_key, name) != 0) {
            free(hashedPassword);
            freeUserInfo(userInfo);
            free(userInfo);
            return EXIT_FAILURE;
        }
    
        free(hashedPassword);
        freeUserInfo(userInfo);
        free(userInfo);
    
        return EXIT_SUCCESS;
    }
#pragma endregion

#pragma region Input/Output Functions
    /*
        Dynamically reads input from stdin (Bash or terminal).
        Reads the next character, reallocates buffer, and appends the new character.
        Continues until newline ('\n') is encountered.
    */
    void dynamic_scan(char **buffer) {
        int ch;
        size_t length = 0;

        // to avoid undefined behavior
        *buffer = NULL;

        while ((ch = getchar()) != '\n' && ch != EOF) {
            // reallocate memory for one additional character
            char *temp = realloc(*buffer, (length + 1) * sizeof(char));
            if (temp == NULL) {
                free(*buffer);
                *buffer = NULL; // avoid dangling pointer
                return;
            }
            *buffer = temp;
            
            // store the character
            (*buffer)[length++] = ch;
        }

        // add null terminator at the end
        char *temp = realloc(*buffer, (length + 1) * sizeof(char));
        if (temp == NULL) {
            free(*buffer);
            *buffer = NULL;
            return;
        }

        *buffer = temp;
        (*buffer)[length] = '\0';
    }

    /*
        Reads user information from a CSV file line by line.
        Parses each line into a UserInfo struct and checks for a matching username.
        Returns a dynamically allocated UserInfo struct if a match is found.
        Frees memory for non-matching entries and ensures proper file handling.
    */
    struct UserInfo *read_user_info_from_csv(const char *name) {
        FILE *passwordFile = fopen(FILE_NAME, "r");
        if (!passwordFile) {
            perror("Error opening file");
            return NULL;
        }
    
        char line[LINE_SIZE];
        bool isfirstLine = true;
        
        // read .csv file line-by-line and check for correct user
        while (fgets(line, sizeof(line), passwordFile)) {
            // skip header
            if (isfirstLine) { 
                isfirstLine = false;
                continue;
            }
    
            // parse user info from the line
            struct UserInfo *userInfo = calloc(1, sizeof(struct UserInfo));
            if (!userInfo) {
                fclose(passwordFile);
                return NULL;
            }
            
            // parse user info from line into UserInfo struct
            int flag = parse_user_info(line, userInfo);
            if (flag != 0) {
                free(userInfo);
                continue;
            }
    
            // verify if this is the correct user
            if (strcmp(userInfo->name, name) == 0) {
                fclose(passwordFile);
                return userInfo;
            }
            
            // free allocated memory for next user(line)
            freeUserInfo(userInfo);
            free(userInfo);
        }
    
        fclose(passwordFile);
        return NULL;
    }  
    

    /*
        Read file line-by-line 
        @return  pointer to array[USER_COUNT][LINE_SIZE] or NULL
    */
    char **read_file_by_line() {
        // open file, if file doesn`t exist -> return NULL
        FILE *file = fopen(INFO_FILE, "r");
        if (!file) {
            return NULL;
        }

        // allocate memory for user lines
        char **lines = malloc(USERS_COUNT * sizeof(char *));
        if (!lines) {
            fclose(file);
            return NULL;
        }

        int userInd = 0;
        char buffer[LINE_SIZE];

        // process file line-byline
        while (fgets(buffer, LINE_SIZE, file) && userInd < USERS_COUNT) {
            // allocate and copy data from buffer
            lines[userInd] = strdup(buffer);
            if (!lines[userInd]) {
                break;
            }

            userInd++;
        }

        fclose(file);
        return lines;
    }
    
    /**
     * Writes an array of UserInfo structs into a CSV file, overwriting existing content.
     * @return EXIT_SUCCESS on success or EXIT_FAILURE if an error occurs.
     */
    int write_user_info_into_csv(struct UserInfo userInfo[USERS_COUNT]) {
        FILE *csvFile = fopen(FILE_NAME, "w");
        if (!csvFile) {
            return EXIT_FAILURE;
        }

        // write a header for csvFile
        fprintf(csvFile, "Username:Hashed Password:OTP_KEYS\n");
        
        int validUsers = 0;
        for (int i = 0; i < USERS_COUNT; i++) {
            // if (!userInfo || !userInfo[i]) {
            //     continue;
            // }
            // check if user data is valid
            if (!userInfo[i].name || !userInfo[i].hashedPassword) {
                continue;
            }
            
            // write user name and hashed password
            fprintf(csvFile, "%s:%s:", userInfo[i].name, userInfo[i].hashedPassword);
    
            // write authentication keys
            for (int j = 0; j < userInfo[i].num_auth_keys; j++) {
                if (userInfo[i].auth_passwords[j]) {
                    if(j == userInfo[i].num_auth_keys - 1 || (j < userInfo[i].num_auth_keys - 1 && !userInfo[i].auth_passwords[j + 1])) {
                        fprintf(csvFile, "%s", userInfo[i].auth_passwords[j]);
                    } else {
                        fprintf(csvFile, "%s,", userInfo[i].auth_passwords[j]);
                    }
                } else {
                    // empty field for missing auth keys
                    // fprintf(csvFile, ",");
                }
            }
            
            // new line for next user
            fprintf(csvFile, "\n");

            validUsers++;
        }
    
        fclose(csvFile);
        // if writen users != USERS_COUNT -> error else success 
        return (validUsers == USERS_COUNT) ? EXIT_SUCCESS : EXIT_FAILURE;
    }
#pragma endregion

#pragma region HelpFunctions
    /**
     * Frees the memory allocated for a UserInfo struct.
     * 
     * @param userInfo A pointer to the UserInfo struct to be freed.
     */
    void freeUserInfo(struct UserInfo *userInfo) {
        if (!userInfo) return;
        
        if (userInfo->name) {
            free(userInfo->name);
            userInfo->name = NULL;
        }
        
        if (userInfo->hashedPassword) {
            free(userInfo->hashedPassword);
            userInfo->hashedPassword = NULL;
        }
        
        if (userInfo->auth_passwords) {
            for (int i = 0; i < userInfo->num_auth_keys; i++) {
                if (userInfo->auth_passwords[i]) {
                    free(userInfo->auth_passwords[i]);
                    userInfo->auth_passwords[i] = NULL;
                }
            }
            free(userInfo->auth_passwords);
            userInfo->auth_passwords = NULL;
        }
        
        userInfo->num_auth_keys = 0;
    }
    
#pragma endregion

#pragma region Parse
    /**
     * Parses a CSV line into a UserInfo struct, extracting the name, 
     * hashed password, and authentication keys. Returns an error code or EXIT_SUCCESS.
     */
    int parse_user_info(const char *line, struct UserInfo *usersInfo) {
        if (!line || !usersInfo) {
            return ERROR_INVALID_INPUT_PARAMS;
        }
    
        char *copy = strdup(line);  // Duplicate the line
        if (!copy) {
            return EXIT_FAILURE;
        }
    
        char *ptr = copy;  // Use a separate pointer for parsing
    
        usersInfo->name = strdup(strsep(&ptr, ":"));
        if (!usersInfo->name) {
            free(copy);
            return EXIT_FAILURE;
        }
    
        usersInfo->hashedPassword = strdup(strsep(&ptr, ":"));
        if (!usersInfo->hashedPassword) {
            free(copy);
            free(usersInfo->name);
            return EXIT_FAILURE;
        }
        
        // Initialize auth keys array
        usersInfo->auth_passwords = NULL;
        usersInfo->num_auth_keys = 0;

        while (ptr && *ptr != '\0') {
            char *authKey = strsep(&ptr, ",\n");
            if (authKey && *authKey != '\0') {
                // Increase key count and reallocate memory
                usersInfo->num_auth_keys++;
                usersInfo->auth_passwords = realloc(usersInfo->auth_passwords, usersInfo->num_auth_keys * sizeof(char *));
                if (!usersInfo->auth_passwords) {
                    free(copy);
                    free(usersInfo->name);
                    free(usersInfo->hashedPassword);
                    return EXIT_FAILURE;
                }

                // Store the key
                usersInfo->auth_passwords[usersInfo->num_auth_keys - 1] = strdup(authKey);
                if (!usersInfo->auth_passwords[usersInfo->num_auth_keys - 1]) {
                    free(copy);
                    free(usersInfo->name);
                    free(usersInfo->hashedPassword);
                    for (int i = 0; i < usersInfo->num_auth_keys - 1; i++) {
                        free(usersInfo->auth_passwords[i]);
                    }
                    free(usersInfo->auth_passwords);
                    return EXIT_FAILURE;
                }
            }
        }
        
        free(copy);  // Free the original duplicate
        return EXIT_SUCCESS;
    }
    
#pragma endregion

#pragma region Auth-Key
    /**
     * Checks if an authentication key exists in the user's stored keys.
     * @return an error code or success.
     */
    int checkAuthKey(const char *authKey, const char **userAuthKeys, int numKeys) {
        // Verify authKey input parameter
        if (!authKey || strlen(authKey) != AUTH_KEY_SIZE) {
            return ERROR_INVALID_AUTH_KEY;
        }

        // Verify userKeys input parameter
        if (!userAuthKeys) {
            return ERROR_INVALID_INPUT_PARAMS;
        }
        
        // iterate through the user's authentication keys and compare with the provided key
        for (int i = 0; i < numKeys; i++) {
            // ensure userAuthKeys[i] is not NULL and compare input authKey with system authKey
            if (userAuthKeys[i] && strcmp(userAuthKeys[i], authKey) == 0) {
                return EXIT_SUCCESS;
            }
        }

        return EXIT_FAILURE;
    }

    /**
     * Creates an array of one-time authentication keys for a user.
     * @return array of one-time authentication keys for a user or  NULL on failure.
     */
    char **createAuthKeys(const int userIndex) {
        // validate user index
        if (userIndex < 0) {
            return NULL;
        }
    
        char **auth_passwords = calloc(MAX_AUTH_KEYS, sizeof(char *));
        if (!auth_passwords) {
            return NULL;
        }
    
        for (int i = 0; i < MAX_AUTH_KEYS; i++) {
            // allocate memory for temp authKey, free previous authKey if allocation failed
            char *authKey = calloc(AUTH_KEY_SIZE + 1, sizeof(char));
            if (!authKey) {
                for (int j = 0; j < i; j++) {
                    free(auth_passwords[j]);
                }
                free(auth_passwords);
                return NULL;
            }
            
            //create one-time auth-key
            snprintf(authKey, AUTH_KEY_SIZE + 1, "usr%dkey%d", userIndex % 10, i % 10);
            
            // store it and free temp authkey
            auth_passwords[i] = strdup(authKey);
            free(authKey);
        }
    
        return auth_passwords;
    }

    /**
     * Deletes a one-time authentication key from the user's stored keys by index.
     * @return an error code or success.
     */
    int deleteOneTimeAuthKeyFromSystem(const char *authKey, const char *user) {
        // check if userAuthKeys is valid
        if(user == NULL || authKey == NULL) {
            return ERROR_INVALID_INPUT_PARAMS;
        }

        // open file to read it content
        FILE *fileInput = fopen(FILE_NAME, "r");
        if (!fileInput) {
            return EXIT_FAILURE;
        }
        char lines[USERS_COUNT][LINE_SIZE];
        struct UserInfo users[USERS_COUNT]; 

        // read usera-info line-by-line and store it into UserInfo array 
        int userInd = 0;
        bool isFirstLine = true;
        while (userInd < USERS_COUNT && fgets(lines[userInd], sizeof(lines[userInd]), fileInput)) {
            if (isFirstLine) {
                isFirstLine = false;
                continue;
            }
            
            // parse user info from line into UserInfo struct
            int flag = parse_user_info(lines[userInd], &users[userInd]);
            if (flag != 0) {
                continue;
            }

            // if we find user
            if(strcmp(users[userInd].name, user) == 0) {
                for(int i = 0; i < users[userInd].num_auth_keys; i++) {
                    // if entered auth key for this user exist
                    if(strcmp(users[userInd].auth_passwords[i], authKey) == 0) {
                        // free from memory and assign new value
                        free(users[userInd].auth_passwords[i]);
                        users[userInd].auth_passwords[i] = '\0';
                    }
                }
            }
            userInd++;
        }

        fclose(fileInput);
        // write it all into csv file with corrected data
        write_user_info_into_csv(users);

        for (int i = 0; i < userInd; i++) {
            freeUserInfo(&users[i]);
        }

        return EXIT_SUCCESS;
    }
#pragma endregion

#pragma region HashFunction
    /**
     * Function that repeats @param password to fit HASH_SIZE and store it into @param output
     */
    void repeat_password_to_fixed_size(const char *password, char output[HASH_SIZE + 1]) {
        int pass_len = strlen(password);
        int i, j = 0;
    
        // fill the output buffer with repeated password
        for (i = 0; i < HASH_SIZE; i++) {
            output[i] = password[j++];
            // restart from beginning when password ends
            if (j >= pass_len) j = 0;
        }
    
        output[HASH_SIZE] = '\0';
    }

    /**
     * Applies a bitwise NOT operation to every character in the @param input string
     * and stores the result in the @param output string.
     */
    void apply_bitwise_not(const char *input, char output[HASH_SIZE + 1]) {
        for (int i = 0; i < HASH_SIZE; i++) {
            // apply bitwise not operation
            output[i] = ~input[i];
        }
        output[HASH_SIZE] = '\0';
    }

    /**
     * Applies XOR for each input character with salt
     */
    void hash_password(const char *input, char output[HASH_SIZE + 1]) {
        int salt_len = strlen(SALT);
        
        // XOR each character with salt (repeats if shorter)
        for (int i = 0; i < HASH_SIZE; i++) {
            output[i] = input[i] ^ SALT[i % salt_len];
        }
        output[HASH_SIZE] = '\0';
    }

    
    /**
     * Converts hash output to only printable ASCII characters and prints debug info.
     */
    void convert_to_alphanumeric_ascii(char *output) {
        for (int i = 0; i < HASH_SIZE; i++) {
            char old_char = output[i];
            output[i] = CHARSET[abs(output[i]) % CHARSET_SIZE];
        }
    }


    /**
     * Generates a hashed password by repeating, inverting, and XOR-ing the input.
     */
    char *generate_hashed_password(const char *password) {
        if (!password) {
            return NULL;
        }
    
        // allocate memory for transformation steps
        char repeated_password[HASH_SIZE + 1];
        char not_applied[HASH_SIZE + 1];
        char *hashed_password = calloc(HASH_SIZE + 1, sizeof(char));
    
        if (!hashed_password) {
            return NULL;
        }
    
        // repeat password to fit HASH_SIZE
        repeat_password_to_fixed_size(password, repeated_password);
    
        // apply bitwise NOT transformation
        apply_bitwise_not(repeated_password, not_applied);
    
        // apply XOR with the salt
        hash_password(not_applied, hashed_password);

        // convert to ascii representation
        convert_to_alphanumeric_ascii(hashed_password);
    
        return hashed_password;
    }

#pragma endregion
