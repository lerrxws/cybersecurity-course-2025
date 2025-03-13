# 🔐 User Authentication System

## Overview
This project implements a simple user authentication system with two-factor authentication (2FA). Users can log in by providing their username, password, and a one-time authentication key. The program securely stores user credentials in a CSV file and verifies them against user input.

## ✨ Features
- ✅ **Secure User Authentication**: Verifies user credentials using hashed passwords and a one-time authentication key.
- ✅ **Password Hashing**: Implements a custom password hashing function with bitwise NOT and XOR encryption techniques.
- ✅ **Two-Factor Authentication (2FA)**: Users must provide a valid one-time authentication key.
- ✅ **Dynamic Memory Management**: Uses dynamic memory allocation for user input and structured data.
- ✅ **CSV-Based User Storage**: Reads and writes user data from a CSV file (hesla.csv).
- ✅ **Valgrind-Validated**: Ensures memory safety with zero memory leaks.
- ✅ **Makefile Included**: Easily compile and manage the project with a Makefile.

## 🚀 How It Works

### 1️⃣ User Authentication Flow
```
┌─────────────────────────────┐
│   User enters credentials   │
└───────────────┬─────────────┘
                ▼
┌─────────────────────────────┐
│ Check if username exists    │
└───────────────┬─────────────┘
                ▼
┌─────────────────────────────┐
│ Verify hashed password      │
└───────────────┬─────────────┘
                ▼
┌─────────────────────────────┐
│ Validate one-time auth key  │
└───────────────┬─────────────┘
                ▼
   ✅ Authentication Success!   
       OR ❌ Authentication Failed
```

### 2️⃣ Password Hashing Process
1. Repeat password to a fixed size (32 characters).
2. Apply bitwise NOT (~) to each character.
3. XOR each character with a predefined salt value.
4. Convert output to ASCII characters (for storage).

## 🛠️ Compilation & Setup

### 1️⃣ Compiling the Program
Use the Makefile for easy compilation:

```sh
make
```

Alternatively, compile manually using:

```sh
gcc -o zadanie2 zadanie2.c -Wall -Wextra -g
```

### 2️⃣ Running the Program
```sh
./zadanie2
```

The program prompts for:
- Username
- Password
- One-time authentication key

## 🔄 User Management

### Adding Users
To manually add users, edit the info.txt or the hesla.csv file:

```csv
Username,Hashed Password,OTP_1,OTP_2,OTP_3,OTP_4,OTP_5,OTP_6,OTP_7,OTP_8,OTP_9,OTP_10
user1,EUfD0fVlHEKkigIFiga4CYxVFIlwfRFD,usr0key0,usr0key1,usr0key2,usr0key3,usr0key4,usr0key5,usr0key6,usr0key7,usr0key8,usr0key9
user2,FDhI0Ga1JGEo0hKKGeD5BV4GBJj3cFFD,usr1key0,usr1key1,usr1key2,usr1key3,usr1key4,usr1key5,usr1key6,usr1key7,usr1key8,usr1key9
```

### Removing Used One-Time Auth Keys
After successful login, the used OTP is removed from hesla.csv.

## 🧪 Testing & Debugging

### 1️⃣ Running Tests
To test the program with Valgrind:

```sh
valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./zadanie2
```

Expected output:
```
== NO memory leaks detected ==
All heap blocks were freed -- no leaks are possible
```

### 2️⃣ Test Cases

#### ✅ Valid Login
```
meno: user1
heslo: password123
overovaci kluc: usr0key0
ok
```

#### ❌ Invalid Password
```
meno: alice
heslo: wrongpassword
overovaci kluc: otp123
chyba
```

#### ❌ Invalid OTP
```
meno: alice
heslo: securepassword
overovaci kluc: wrongotp
chyba
```

#### ❌ User Not Found
```
meno: unknown_user
heslo: password
overovaci kluc: otp
chyba
```

## 📋 File Structure
```
📂 zadanie2_project/
├── 📝 README.md          # This file
├── 📄 zadanie2.c         # Main C program
├── 📄 Makefile           # Compilation script
├── 📄 hesla.csv          # User credentials storage
└── 📄 info.txt           # Additional user info
```

## 📌 Technical Details

### 1️⃣ Secure User Authentication
- Reads user credentials from hesla.csv.
- Hashes passwords before comparison.
- Checks if the one-time authentication key is valid.

### 2️⃣ Memory Management & Debugging
- Uses dynamic memory allocation (malloc & calloc).
- Memory is freed properly using freeUserInfo().
- Valgrind-tested to ensure no memory leaks.

### 3️⃣ Error Handling
- Graceful error handling for file operations.
- Input validation prevents crashes due to malformed input.

## 💡 Future Improvements
- 🔹 Add a user registration feature.
- 🔹 Encrypt stored passwords using a cryptographic hash (e.g., SHA-256, bcrypt).
- 🔹 Implement a graphical user interface (GUI).

## 👨‍💻 Author
Valeriia Buhaiova  
Cybersecurity Course – User Authentication System  
📅 Date: March 2025
