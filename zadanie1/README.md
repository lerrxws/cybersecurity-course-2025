# 🔐 Custom AES Implementation

## Overview
This project implements a custom variant of the Advanced Encryption Standard (AES) algorithm with a unique twist - replacing the standard S-Box substitution with a simple left bit rotation. This modified encryption algorithm maintains the core AES structure including 10 rounds of transformation while introducing a novel substitution approach.

## ✨ Key Features

- **Modified AES Algorithm**: Implements the core AES structure with a custom substitution step
- **Comprehensive Encryption/Decryption**: Complete pipeline for secure file transformation
- **Key Expansion**: Derives round keys from user-provided master key
- **Padding**: Ensures proper block alignment for any input size
- **Memory-Safe Implementation**: Validated with Valgrind for leak-free operation
- **Command-Line Interface**: Simple and intuitive user experience

## 🔄 How It Works

### Encryption Process
```
┌─────────────────────────┐
│ Plaintext (16-byte blocks) │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│         Padding         │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│     Key Expansion       │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│   Initial AddRoundKey   │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│      Rounds 1-9:        │
│  ┌───────────────────┐  │
│  │ Bit Rotation Sub  │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │    Shift Rows     │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │   Mix Columns     │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │   Add Round Key   │  │
│  └───────────────────┘  │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│       Round 10:         │
│  ┌───────────────────┐  │
│  │ Bit Rotation Sub  │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │    Shift Rows     │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │   Add Round Key   │  │
│  └───────────────────┘  │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│    Ciphertext Output    │
└─────────────────────────┘
```

### Decryption Process
```
┌─────────────────────────┐
│ Ciphertext (16-byte blocks) │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│     Key Expansion       │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│   Initial AddRoundKey   │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│      Rounds 1-9:        │
│  ┌───────────────────┐  │
│  │ Inverse ShiftRows │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │  Inverse Bit Sub  │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │   Add Round Key   │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │ Inverse MixCols   │  │
│  └───────────────────┘  │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│       Round 10:         │
│  ┌───────────────────┐  │
│  │ Inverse ShiftRows │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │  Inverse Bit Sub  │  │
│  └─────────┬─────────┘  │
│            ▼            │
│  ┌───────────────────┐  │
│  │   Add Round Key   │  │
│  └───────────────────┘  │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│      Remove Padding     │
└─────────────┬───────────┘
              ▼
┌─────────────────────────┐
│    Plaintext Output     │
└─────────────────────────┘
```

## 🚀 Usage

### Encryption
```sh
./zadanie1 -s -p <key> -i <input_file> -o <output_file>
```
- `-s`: Encryption mode
- `-p <key>`: Your secret key
- `-i <input_file>`: File to encrypt
- `-o <output_file>`: Destination for encrypted data

### Decryption
```sh
./zadanie1 -d -p <key> -i <input_file> -o <output_file>
```
- `-d`: Decryption mode
- `-p <key>`: Same key used for encryption
- `-i <input_file>`: Encrypted file
- `-o <output_file>`: Destination for decrypted data

## 🧪 Automated Testing Suite

The project includes a comprehensive Bash test script that validates the implementation with a variety of test cases. This script was kindly contributed by a fellow student from the 2025 Cybersecurity course.

### Test Script Features:
- Tests encryption and decryption with various passwords (including empty, special characters, and Unicode)
- Verifies different parameter ordering combinations
- Validates proper error handling for invalid inputs
- Performs hash verification to ensure data integrity through the encryption/decryption cycle
- Provides clear pass/fail indicators for each test case

### Running the Tests:
```sh
# Make sure the test script has execute permissions
chmod +x test_aes.sh

# Run the test suite
./test_aes.sh
```

The script will output detailed results for each test case and provide a summary of passed tests at the end.

## 🔍 Technical Details

### Key Innovations

- **Bit Rotation Substitution**: Instead of using the standard AES S-Box, our implementation performs a left bit rotation for substitution, creating a unique encryption profile
- **Full AES Structure**: Despite the modified substitution, the implementation maintains the essential AES structure including ShiftRows, MixColumns, and AddRoundKey operations
- **Binary Processing**: Works with any file type, not just text, processing data in binary mode for universal application

### Security Considerations

- This implementation serves educational purposes, demonstrating AES principles with a custom substitution
- The bit rotation substitution provides less diffusion than the standard S-Box, making this implementation suitable for academic exploration rather than high-security applications
- For production environments, standard AES implementations are recommended

## 📋 Requirements
- C compiler (GCC recommended)
- Standard C libraries
- Bash shell (for running the test script)

## 🛠️ Building the Project
```sh
gcc -o zadanie1 zadanie1.c -Wall -Wextra
```
or
```sh
make zadanie1
```

## 👨‍💻 Author
Valeriia Buhaiova  
Cybersecurity Course, Task 1  
Date: 2025-02-28

## 🙏 Acknowledgments
Special thanks to the kind and talented fellow student from the 2025 Cybersecurity course who contributed the comprehensive test script that has been invaluable for validating this implementation.
