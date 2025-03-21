# 🗂️ Virtual File System Implementation

## Overview
This project implements a simple virtual file system in C that simulates basic Unix-like file operations. The file system supports operations such as creating files and directories, navigating through directories, changing file permissions, and more.

## ✨ Features
- ✅ **File & Directory Management**: Create, navigate, and delete files and directories
- ✅ **Permission System**: Unix-like permission system (read, write, execute)
- ✅ **User Ownership**: File ownership management
- ✅ **Path Resolution**: Support for absolute and relative paths
- ✅ **Memory Management**: Clean allocation and deallocation of resources
- ✅ **Testing Framework**: Comprehensive test suite included

## 🚀 Supported Commands

| Command | Description | Example |
|---------|-------------|---------|
| `ls [path]` | List files in a directory | `ls /some/path` |
| `cd [path]` | Change current directory | `cd /some/path` |
| `mkdir [path]` | Create a new directory | `mkdir new_dir` |
| `touch [path]` | Create a new file | `touch new_file` |
| `rm [path]` | Remove a file or empty directory | `rm file_to_remove` |
| `chmod [permissions] [path]` | Change file permissions | `chmod 7 some_file` |
| `chown [username] [path]` | Change file ownership | `chown user some_file` |
| `vypis [path]` | Check if file is readable | `vypis some_file` |
| `spusti [path]` | Check if file is executable | `spusti some_file` |
| `zapis [path]` | Check if file is writable | `zapis some_file` |
| `quit` | Exit the program | `quit` |

## 🔐 Permission System

The file system uses a simplified Unix-like permission system with three permission types:
- **Read (4)**: Allows reading file contents or listing directory contents
- **Write (2)**: Allows modifying file contents or creating/deleting files in a directory
- **Execute (1)**: Allows executing a file or accessing a directory

Permissions are represented as an integer from 0-7:
- `0`: No permissions (---)
- `1`: Execute only (--x)
- `2`: Write only (-w-)
- `3`: Write and execute (-wx)
- `4`: Read only (r--)
- `5`: Read and execute (r-x)
- `6`: Read and write (rw-)
- `7`: All permissions (rwx)

## 🛠️ Compilation & Setup

### Compiling the Program
Use the included Makefile for easy compilation:

```sh
make
```

Alternatively, compile manually:

```sh
gcc -o zadanie3 zadanie3.c
```

### Running the Program
```sh
./zadanie3
```

The program provides a command prompt where you can enter file system commands.

## 🧪 Testing

The project includes a comprehensive test script (`test.sh`) to verify functionality:

```sh
# Run easy tests
./test.sh e

# Run medium tests
./test.sh m

# Run hard tests
./test.sh h

# Run all tests
./test.sh a
```

Tests verify various aspects of the file system:
- File creation and deletion
- Directory navigation
- Permission checks
- Path resolution
- Error handling

## 📋 Code Structure

The code is organized into several functional regions:
- **Command Handling**: Parsing and routing user commands
- **File Handling**: Creating, managing, and navigating files and directories
- **Path Resolution**: Resolving file paths and extracting components
- **Permission Management**: Checking and modifying file permissions

## 👨‍💻 Implementation Details

### File System Structure
The virtual file system is implemented as a linked list structure with each file or directory containing pointers to:
- Parent directory
- Next and previous files in the same directory
- Subfiles (for directories)

### Path Resolution
The system supports both:
- Absolute paths (starting with `/`)
- Relative paths (relative to current directory)
- Special paths like `..` (parent directory) and `.` (current directory)

## 💡 Future Improvements
- 🔹 Add symbolic link support
- 🔹 Implement file content storage
- 🔹 Add multi-user support with groups
- 🔹 Enhance error reporting with more detailed messages
- 🔹 Add support for wildcards in file operations

## 🔄 Acknowledgements
This project was developed as a programming assignment focused on file systems, linked list data structures, and memory management in C.