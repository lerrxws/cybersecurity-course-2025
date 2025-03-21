#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>

#define LINE_SIZE 256

#define ERROR_CODE   -1
#define SUCCESS_CODE 1
#define PERMISSION_DENIED 2 
#define EXIT_CODE 3
#define OK_CODE 4

#define PERM_READ    4  
#define PERM_WRITE   2  
#define PERM_EXEC    1 
#define PERM_STRING  4 

#define PARENT_DIRECTORY ".."
#define CURRENT_DIRECTORY "."
#define ROOT_DIRECTORY "/"

#define USER "user"

// represents a file or directory in the virtual file system
typedef struct File {
    char *name;
    char *ownerName;
    bool isDirectory;
    int permissions;

    struct File *subfiles;
    struct File *parentDirectory;
    
    struct File *next;
    struct File *previous;
    
} File;

// represents a node in a parsed file path (linked list)
typedef struct FileNode {
    char *name;
    struct FileNode *next;
} FileNode;

// enum for supported command types
typedef enum {
    CMD_UNKNOWN,
    CMD_LS,      
    CMD_CD,       
    CMD_MKDIR,    
    CMD_TOUCH,    
    CMD_RM,       
    CMD_CHMOD,    
    CMD_CHOWN,
    CMD_VYPIS,
    CMD_SPUSTI,
    CMD_ZAPIS,    
    CMD_EXIT      
} CommandType;

// represents a parsed user command
typedef struct {
    CommandType command;
    char *arg1;
    char *arg2;
} Command;

#pragma region Definitions
    // Command handling
    int handle_command(Command command, File **current);
    CommandType get_command_type(const char *command);
    int parse_command(const char *line, Command *cmd);
    void free_command_args(Command *cmd);

    // FileNode handling
    FileNode* createFileNode(const char *name);
    FileNode *addFileNode(FileNode **head, const char *name);
    void printFileList(FileNode *head);
    void freeFileList(FileNode *head);

    // File handling
    File* createFile(const char *name, const char *owner, bool isDirectory, int permissions);
    void addFile(File *parent, File *newFile);
    void freeFileSystem(File *file);

    // Permissions
    int permissionStringToInt(const char *permStr);
    char* permissionIntToString(int perm);
    bool hasPermission(const File *file, int requestedPerm);

    // Path and file retrieval
    File *get_file_in_directory(const File *currentDirectory, const char *name);
    int get_file_by_path(const File *directory, const FileNode *path, const int permissions, File **result);
    int extract_directory(const File *directory, const FileNode *path, const int permissions, File **result);
    FileNode *readDirectory(const char *path);

    // Command implementations
    int ls_command(const File *current, const FileNode *path);
    int cd_command(File **current, const FileNode *path);
    int touch_command(const File *current, const FileNode *path);
    int mkdir_command(const File *current, const FileNode *path);
    int rm_command(const File *current, const FileNode *path);
    int delete_file(File *parent, File *file);
    int chmod_command(const File *current, const FileNode *path, const int permissions);
    int chown_command(const File *current, const FileNode *path, const char *user);
    int vypis_command(const File *current, const FileNode *path);
    int spusti_command(const File *current, const FileNode *path);
    int zapis_command(const File *current, const FileNode *path);
    int create(const File *current, const FileNode *path, bool isDirectory);
#pragma endregion

File *root = NULL;

int main() {
    // Initialization
    char *line = NULL;
    long unsigned int lineSize = 0;
    File *current;
    FileNode *path;
    Command command = { CMD_UNKNOWN, NULL, NULL }; 
    int flag;

    // create root directory and set it as current directory
    root = createFile("/", USER, true, (PERM_READ | PERM_WRITE | PERM_EXEC));
    current = root;

     // main loop: prompt user until they choose to quit
    while(command.command != CMD_EXIT) {
        printf("# ");
        getline(&line, &lineSize, stdin); // read user input
        line[strcspn(line, "\n")] = '\0'; // remove trailing newline

        // parse user input
        parse_command(line, &command);

        // execute the command and get STATUS_CODE
        flag = handle_command(command, &current);
        if(flag == OK_CODE) printf("ok\n");
        else if (flag == PERMISSION_DENIED) printf("chyba prav\n");
        else if(flag == ERROR_CODE) printf("chyba\n");
        else if(flag == EXIT_CODE){
            free_command_args(&command);
            break; // exit loop
        } 

        free_command_args(&command); // clean up arguments
    }

    free(line);
    freeFileSystem(root);

    return SUCCESS_CODE;
}

#pragma region Command Handling
    /**
     * Hanles user command and execute the corresponding operation
     * 
     * @return status code;
     */
    int handle_command(Command command, File **current) {
        int result; // status code
        FileNode *path = NULL; // pointer for path

        switch (command.command) {
            case CMD_LS:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = ls_command(*current, path);
        
                break;
            case CMD_CD:
                // parse path and exec command (reassign current)
                path = readDirectory(command.arg1);
                result = cd_command(current, path);

                break;
            case CMD_TOUCH:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = touch_command(*current, path);

                break;
            case CMD_MKDIR:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = mkdir_command(*current, path);

                break;
            case CMD_RM:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = rm_command(*current, path);

                break;
            case CMD_VYPIS:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = vypis_command(*current, path);

                break;
            case CMD_SPUSTI:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = spusti_command(*current, path);

                break;
            case CMD_ZAPIS:
                // parse path and exec command
                path = readDirectory(command.arg1);
                result = zapis_command(*current, path);

                break;
            case CMD_CHMOD:
                // convert permission argument to int
                char *endptr;
                errno = 0;
                int chmodInt = (int)strtol(command.arg1, &endptr, 10);

                // validate converting result
                if (errno == ERANGE || chmodInt > INT_MAX || chmodInt < INT_MIN) return ERROR_CODE;
                if (endptr == command.arg1 || *endptr != '\0') return ERROR_CODE;

                // parse path and exec command
                path = readDirectory(command.arg2);
                result = chmod_command(*current, path, chmodInt);

                break;
            case CMD_CHOWN:
                // parse path and exec command
                path = readDirectory(command.arg2);
                result = chown_command(*current, path, command.arg1);

                break;
            case CMD_EXIT:
                result = EXIT_CODE;
                break;
            default:
                result = ERROR_CODE;
        }

        // free parsed path
        if(path != NULL) freeFileList(path);

        return result;
    }

    /**
     * Parses a single line of input into a structured Command.
     *
     * @return STATUS_CODE.
     */
    int parse_command(const char *line, Command *cmd) {
        // validate input
        if(!line || !cmd) return ERROR_CODE;

        // allocate memory and copy line into tmpLine
        char *tmpLine = strdup(line);
        if (!tmpLine) return ERROR_CODE;

        // tokenize the command line string (first word = command)
        char *token = strtok(tmpLine, " ");
        cmd->command = (token) ? get_command_type(token) : CMD_UNKNOWN;

        // parse arg1
        token = strtok(NULL, " ");
        cmd->arg1 = (token) ? strdup(token) : NULL;

        // parse arg2
        token = strtok(NULL, " ");
        cmd->arg2 = (token) ? strdup(token) : NULL;

        free(tmpLine);

        return SUCCESS_CODE;
    }

    #pragma region Command Struct Handling
        /**
         * Frees memory allocated for command arguments
         */
        void free_command_args(Command *cmd) {
            if (cmd->arg1) {
                free(cmd->arg1); // free first argument
                cmd->arg1 = NULL;
            }
            if (cmd->arg2) {
                free(cmd->arg2); // free second argument
                cmd->arg2 = NULL;
            }
        }
    #pragma endregion

    #pragma region Handle Command Enum
        /**
         * Maps a string command to its corresponding CommandType enum.
         * 
         * @return the matching CommandType, or CMD_UNKNOWN if no match is found.
         */
        CommandType get_command_type(const char *command) {
            if (strcmp(command, "ls") == 0) return CMD_LS;
            if (strcmp(command, "cd") == 0) return CMD_CD;
            if (strcmp(command, "mkdir") == 0) return CMD_MKDIR;
            if (strcmp(command, "touch") == 0) return CMD_TOUCH;
            if (strcmp(command, "rm") == 0) return CMD_RM;
            if (strcmp(command, "chmod") == 0) return CMD_CHMOD;
            if (strcmp(command, "chown") == 0) return CMD_CHOWN;
            if (strcmp(command, "zapis") == 0) return CMD_ZAPIS;
            if (strcmp(command, "vypis") == 0) return CMD_VYPIS;
            if (strcmp(command, "spusti") == 0) return CMD_SPUSTI;
            if (strcmp(command, "quit") == 0) return CMD_EXIT;
            return CMD_UNKNOWN;
        }
    #pragma endregion

#pragma endregion

#pragma region File Handling
    /**
     * Creates a new File structure (either a file or a directory).
     *
     * @return Pointer to the newly allocated File structure, or NULL on failure.
     */
    File* createFile(const char *name, const char *owner, bool isDirectory, int permissions) {
        File *newFile = (File*)malloc(sizeof(File));
        if (!newFile) return NULL;

        newFile->name = strdup(name);
        newFile->ownerName = strdup(owner);
        newFile->isDirectory = isDirectory;
        newFile->permissions = permissions;
        newFile->subfiles = NULL;
        newFile->parentDirectory = NULL;
        newFile->next = NULL;
        newFile->previous = NULL;

        return newFile;
    }

    /** 
     * Adds a new file or directory to the parent's subfile list 
     */
    void addFile(File *parent, File *newFile) {
        // validate input
        if (!parent || !parent->isDirectory || !newFile) return;

        // assign parent directory
        newFile->parentDirectory = parent;

        // if parentDir has no files -> assign newFile as first
        if (!parent->subfiles) parent->subfiles = newFile; 
        else {
            // find the last subfile
            File *temp = parent->subfiles;
            while (temp->next) {
                temp = temp->next;
            }

            // link the new file at the end
            temp->next = newFile; 
            newFile->previous = temp; 
        }
    }

    
    /**
     * Recursively frees the entire file system starting from the given file
     */
    void freeFileSystem(File *file) {
        // validate input
        if (!file) return;

        // free file metadata
        free(file->name);
        free(file->ownerName);

        // recursively free subfiles
        File *current = file->subfiles;
        while (current) {
            File *nextFile = current->next;
            freeFileSystem(current);
            current = nextFile;
        }

        free(file); // free current file
    }

#pragma endregion

#pragma region Handle FileNode Struct
    /**
     * Create new FileNode
     */
    FileNode* createFileNode(const char *name) {
        FileNode *newNode = (FileNode*)malloc(sizeof(FileNode));
        if (!newNode) {
            perror("Memory allocation failed");
            exit(EXIT_FAILURE);
        }
        newNode->name = strdup(name);
        newNode->next = NULL;

        return newNode;
    }

    /**
     *  Function to add a file node to the linked list
     */
    FileNode *addFileNode(FileNode **head, const char *name) {
        FileNode *newNode = createFileNode(name);
        if (*head == NULL) {
            *head = newNode;
        } else {
            FileNode *temp = *head;
            while (temp->next) {
                temp = temp->next;
            }
            temp->next = newNode;
        }
        return *head;
    }

    /**  
     * Function to free allocated memory 
    */
    void freeFileList(FileNode *head) {
        if(head == NULL) {
            return;
        }

        FileNode *temp;
        while (head) {
            temp = head;
            head = head->next;
            if(temp->name != NULL) {
                free(temp->name);
            }
            free(temp);
        }
    }

#pragma endregion

#pragma region Handle File Permissions
    /**
     * Converts a permission string (e.g. "rwx", "rw-", "r--") to an integer bitmask.
     * 
     * @return Integer representation using bitmask flags.
     */
    int permissionStringToInt(const char *permStr) {
        int perm = 0;
        
        if (permStr[0] == 'r') perm |= PERM_READ;
        if (permStr[1] == 'w') perm |= PERM_WRITE;
        if (permStr[2] == 'x') perm |= PERM_EXEC;
        
        return perm;
    }

    /**
     * Converts a permission integer (bitmask) to a string like "rwx" or "r--".
     * Uses a static buffer to avoid dynamic memory allocation.
     * 
     * @return Pointer to a static string representation (e.g. "rw-").
     */
    char* permissionIntToString(int perm) {
        static char permStr[PERM_STRING];
    
        permStr[0] = (perm & PERM_READ) ? 'r' : '-';
        permStr[1] = (perm & PERM_WRITE) ? 'w' : '-';
        permStr[2] = (perm & PERM_EXEC) ? 'x' : '-';
        permStr[3] = '\0';
    
        return permStr;
    }

    /**
     * Checks if a file has the requested permissions.
     */
    bool hasPermission(const File *file, int requestedPerm) {
        return (file->permissions & requestedPerm) == requestedPerm;
    }

#pragma endregion

#pragma region Path and File Retrieval
    /**
     * Retrieves a file by name from the given directory.
     * 
     * @return a pointer to the file if found, otherwise NULL.
     */
    File *get_file_in_directory(const File *currentDirectory, const char *name) {
        // validate input and ensure the current file is a directory and name is not NULL
        if(currentDirectory == NULL || !currentDirectory->isDirectory || name == NULL) return NULL;

        // get first subfile
        File *currentSubFile = currentDirectory->subfiles;
        // traverse the subfile list until the target file is found or the end is reached
        while(currentSubFile != NULL) {
            // If the current subfile's name matches the target name, return a pointer to it
            if(strcmp(currentSubFile->name, name) == 0) return currentSubFile;

            // go to next subfile
            currentSubFile = currentSubFile->next;
        }

        return NULL;
    }

    /**
     * Resolves a path from a directory and assign it into @param result
     * Checks permissions along the way
     * @return STATUS_CODE
     */
    int get_file_by_path(const File *directory, const FileNode *path, const int permissions, File **result) {
        // validate input and ensure the starting point is a directory
        if (!directory || !directory->isDirectory) return ERROR_CODE;
        if (!path) {
            // if path is not present -> return current directory
            *result = (File *)directory;
            return SUCCESS_CODE;
        }

        // new pointer for path for safe traverse
        const FileNode *node = path;
        if(!node) return ERROR_CODE;

        File *current;
        // check for absolute path as start
        if(strcmp(node->name, ROOT_DIRECTORY) == 0) {
            current = root;
            node = node->next;
        // check for parent path as start
        } else if(strcmp(node->name, PARENT_DIRECTORY) == 0) {
            current = directory->parentDirectory;
            node = node->next;
        } else current = (File *)directory; // if path is not absolute or parent reference, use current directory as base

        while (node) {
            // skip current directory
            if(strcmp(node->name, CURRENT_DIRECTORY) == 0) {
                node = node->next;
                continue;
            }

            // Move up to parent or get subfile/directory
            current = (strcmp(node->name, PARENT_DIRECTORY) == 0) // check if parent dir
                    ? current->parentDirectory // to parent
                    : get_file_in_directory(current, node->name); // to subfile/dir

            if (!current) return ERROR_CODE; // not found
            if(!hasPermission(current, permissions) && node->next) return PERMISSION_DENIED; // do not have permissions
            if (node->next && !current->isDirectory) return ERROR_CODE; // intermediate path component must be a directory

            // go to next path-node
            node = node->next;
        }

        // store the resolved file/directory in the output pointer
        *result = (File *)current;
        return SUCCESS_CODE;
    }

    /**
     * Resolves the directory from a given path, excluding the final node
     * @return STATUS_CODE
     */
    int extract_directory(const File *directory, const FileNode *path, const int permissions, File **result) {
        // validate input and ensure the starting point is a directory
        if (!path || !directory || !directory->isDirectory) return ERROR_CODE;

        const FileNode *node = path;
        File *current;

        // handle absolute and parent-based paths
        if(strcmp(node->name, ROOT_DIRECTORY) == 0) {
            current = root;
            node = node->next;
        } else if(strcmp(node->name, PARENT_DIRECTORY) == 0) {
            current = directory->parentDirectory;
            node = node->next;
        } else current = (File *)directory;

        // traverse path until the second-to-last node
        while(node && node->next) {
            // skip current dir
            if(strcmp(node->name, CURRENT_DIRECTORY) == 0) {
                node = node->next;
                continue;
            }

            // Move up to parent or get subfile/directory
            current = (strcmp(node->name, PARENT_DIRECTORY) == 0) // check if parent dir
                    ? current->parentDirectory // to parent
                    : get_file_in_directory(current, node->name); // to subfile/dir

            // must be a valid directory and have required permissions
            if(!current || !current->isDirectory ) return ERROR_CODE;
            if(!hasPermission(current, permissions)) return PERMISSION_DENIED;
            
            // go to next path-node
            node = node->next;
        }

        if(!node) return ERROR_CODE;

        // store the resolved file/directory in the output pointer
        *result = (File *)current;
        return SUCCESS_CODE;
    }

    /**
     * Parse and tokenize path
     * 
     * @return the head of the linked list or NULL on failure.
     */
    FileNode *readDirectory(const char *path) {
        // validate input
        if(!path) return NULL;

        FileNode *head = NULL;

        // check for a single-level path
        if (strchr(path, '/') == NULL) {
            addFileNode(&head, path);
            return head;
        }

        // check fpr abdolute path
        if (path[0] == ROOT_DIRECTORY[0]) {
            addFileNode(&head, ROOT_DIRECTORY);
            if(head == NULL) return NULL;
        } 

        // copy path string for safe tokenization   
        char *copy = strdup(path);
        if (!copy) return NULL;

        // tokenize the path by '/'
        char *token = strtok(copy, "/");
        while (token != NULL) {
            // create a node for each part
            addFileNode(&head, token);
            token = strtok(NULL, "/");
        }

        free(copy);
        return head;
    }

#pragma endregion

#pragma region Command Implementations
    /**
     * Changes the current working directory if the path is valid and executable
     * 
     * @return STATUS_CODE
     */
    int cd_command(File **current, const FileNode *path) {
        // validate input
        if(!root || !(*current)) return ERROR_CODE; 

        // no path = stay in current directory
        if(!path) return SUCCESS_CODE;

        // resolve target directory with exec permission
        File *dir;
        int res = get_file_by_path(*current, path, PERM_EXEC, &dir);

        if(res == ERROR_CODE || !dir || !dir->isDirectory) return ERROR_CODE; // validate result and ensure it's a directory
        if(res == PERMISSION_DENIED || !hasPermission(dir, PERM_EXEC)) return PERMISSION_DENIED;  // check final exec permission

        // update current directory
        *current = dir;

        return SUCCESS_CODE;
    }
    /** 
     * Executes the 'ls' command on a path or current dir
     * 
     * @return STATUS_CODE 
     */
    int ls_command(const File *current, const FileNode *path) {
        // validate input
        if(!root || !current) return ERROR_CODE;

        // resolve target file with exec permission
        File *endpoint;
        int res = get_file_by_path(current, path, PERM_WRITE, &endpoint);
        if(res == ERROR_CODE || !endpoint) return ERROR_CODE; // validate result and ensure it's a directory
        else if(res == PERMISSION_DENIED || !hasPermission(endpoint, PERM_READ)) return PERMISSION_DENIED;   // check final exec permission

        // print info about file
        if(!endpoint->isDirectory) {
            printf("%s %s %s\n", endpoint->name, endpoint->ownerName, permissionIntToString(endpoint->permissions));
            return SUCCESS_CODE;
        }
        
        // print all files in directory
        File *file = endpoint->subfiles;
        while (file) {
            printf("%s %s %s\n", file->name,
                                file->ownerName,
                                permissionIntToString(file->permissions));
            
            // go to next file-node
            file = file->next;
        }

        return SUCCESS_CODE;
    }

    #pragma region Create File or Directory
        /**
         *  Creates a new file or directory at the specified path 
         * 
         * @return STATUS_CODE
        */
        int create(const File *current, const FileNode *path, bool isDirectory) {
            // validate input
            if(!root || !current || !path) return ERROR_CODE;

            File *dir;
            // extract the target directory where file/dir should be created
            int res = extract_directory(current, path, PERM_WRITE, &dir);
            if(res == ERROR_CODE || !dir || !dir->isDirectory) return ERROR_CODE;
            else if (res == PERMISSION_DENIED) return PERMISSION_DENIED;

            // find last node in path (name of the new file/dir)
            const FileNode *node = path;
            while (node && node->next) {
                node = node->next;
            }
            if(!node) return ERROR_CODE;

            // create file only if it doesn't already exist
            File *file = (!get_file_in_directory(dir, node->name))
            ? createFile(node->name, USER, isDirectory, (PERM_READ | PERM_WRITE | PERM_EXEC))
            : NULL; 
            
            if(!file) return ERROR_CODE;

            // add new file to the parent directory
            addFile(dir, file);

            return SUCCESS_CODE;
        }

        /**
         *  Creates a regular file at the given path 
         *
         * @return STATUS_CODE
         */
        int touch_command(const File *current, const FileNode *path) {
            return create(current, path, false);
        }

        /**
         *  Creates a directory at the given path 
         *
         * @return STATUS_CODE
         */
        int mkdir_command(const File *current, const FileNode *path) {
            return create(current, path, true);;
        }

    #pragma endregion
    
    #pragma region Remove
        /**
         *  Handles the 'rm' command to delete a file or an empty directory
         *
         * @return STATUS_CODE
         */
        int rm_command(const File *current, const FileNode *path) {
            // validate inputs
            if(!root || !current || !path) return ERROR_CODE;

            int res;

            File *file;
            // get the target file
            res = get_file_by_path(current, path, PERM_READ, &file); // check every node for read permissions
            if(res == ERROR_CODE || !file) return ERROR_CODE;
            else if(res == PERMISSION_DENIED) return PERMISSION_DENIED;
            
            File *dir;
            //get the parent directory of the file
            res = extract_directory(current, path, PERM_WRITE, &dir); // check every node for write permissions
            if(res == ERROR_CODE || !dir || !dir->isDirectory) return ERROR_CODE;
            else if(res == PERMISSION_DENIED) return PERMISSION_DENIED;

            return delete_file(dir, file);
        }

        /**
         *  Deletes a file or an empty directory from the parent directory
         *
         * @return STATUS_CODE
         */
        int delete_file(File *parent, File *file) {
            // validate inputs
            if(!parent || !parent->isDirectory
                || !parent->subfiles
            ) return ERROR_CODE;

            // can't delete non-empty directories or unrelated files
            if(!file || (file->isDirectory && file->subfiles) 
                || !file->parentDirectory || file->parentDirectory != parent 
            ) return ERROR_CODE;

            // check write permissions on both parent and target file
            if(!hasPermission(parent, PERM_WRITE) || !hasPermission(file, PERM_WRITE)) return PERMISSION_DENIED;

            // make sure the file actually belongs to the parent
            File *check = get_file_in_directory(parent, file->name);
            if(!check || check != file) return ERROR_CODE;

            // Update pointers
            if(!file->previous) parent->subfiles = file->next;
            else file->previous = file->next;

            file->next = NULL;
            freeFileSystem(file);

            return SUCCESS_CODE;
        }
    #pragma endregion

    /** 
     * Checks if a file is readable
     * 
     * @return STATUS_CODE
     */
    int vypis_command(const File *current, const FileNode *path) {
        // validate inputs
        if(!root || !current || !path) return ERROR_CODE;

        File *file;
        int res = get_file_by_path(current, path, PERM_READ, &file); // get file
        if(res == ERROR_CODE || !file || file->isDirectory) return ERROR_CODE;  // validate result
        else if(res == PERMISSION_DENIED ||!hasPermission(file, PERM_READ)) return PERMISSION_DENIED; // validate permissions

        return OK_CODE;
    }

    /** 
     * Checks if a file is executable
     * 
     * @return STATUS_CODE
     */
    int spusti_command(const File *current, const FileNode *path) {
        // validate inputs
        if(!root || !current || !path) return ERROR_CODE;

        File *file;
        int res = get_file_by_path(current, path, PERM_READ, &file); // get file
        if(res == ERROR_CODE || !file || file->isDirectory) return ERROR_CODE;  // validate result
        else if(res == PERMISSION_DENIED ||!hasPermission(file, PERM_EXEC)) return PERMISSION_DENIED; // validate permissions

        return OK_CODE;
    }

    /** 
     * Checks if a file is writable (zapis)
     * 
     * @return STATUS_CODE
     */
    int zapis_command(const File *current, const FileNode *path) {
        // validate inputs
        if(!root || !current || !path) return ERROR_CODE;

        File *file;
        int res = get_file_by_path(current, path, PERM_READ, &file); // get file
        if(res == ERROR_CODE || !file) return ERROR_CODE;  // validate result
        else if(res == PERMISSION_DENIED ||!hasPermission(file, PERM_WRITE)) return PERMISSION_DENIED; // validate permissions

        return OK_CODE;
    }


    /**
     *  Changes file permissions if user has write access 
     * 
     * @return STATUS_CODE
     */
    int chmod_command(const File *current, const FileNode *path, const int permissions) {
        // validate inputs
        if(!root || !current || !path) return ERROR_CODE;
        // ensure permission value is in valid range (0–7)
        if(permissions < 0 || permissions > 7) return ERROR_CODE;

        File *file;
        int res = get_file_by_path(current, path, PERM_WRITE, &file); // get file
        if(res == ERROR_CODE || !file) return ERROR_CODE; // validate result
        else if(res == PERMISSION_DENIED) return PERMISSION_DENIED; // validate permissions

        file->permissions = permissions; // reassign permissions
        
        return SUCCESS_CODE;
    }

    /** 
     * Changes file ownership if user has write access
     * 
     * @return STATUS_CODE 
     */
    int chown_command(const File *current, const FileNode *path, const char *user) {
        // validate inputs
        if(!root || !current || !path || !user) return ERROR_CODE;

        File *file;
        int res = get_file_by_path(current, path, PERM_WRITE, &file); // get file
        if(res == ERROR_CODE || !file) return ERROR_CODE; // validate result
        else if(res == PERMISSION_DENIED) return PERMISSION_DENIED; // validate permissions

        // allocate new memory for owner string
        char *copy = strdup(user);
        if (!copy) return ERROR_CODE;

        if (file->ownerName) free(file->ownerName); // free old owner name
        file->ownerName = copy; // assign new owner name
        
        return SUCCESS_CODE;
    }

#pragma endregion
