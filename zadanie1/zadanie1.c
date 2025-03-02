/**
 * Author: Valeriia Buhaiova
 * Course: Cybersecurity
 * Year: 2025
 * Algorithm: Custom AES (S-Box replaced with Bit Rotation Substitution)
 */

#define _GNU_SOURCE
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

// pre-define values for aes algo
#define MAX_FILE_SIZE 100000000
#define KEY_SIZE 16
#define BLOCK_SIZE 16
#define ROUNDS 10
#define EXPANDED_KEY_SIZE (ROUNDS + 1) * BLOCK_SIZE

#pragma region Defitiions
// def-work with args
bool checkIfTxtFile(char *fileName);
bool parseArguments(int argc, char *argv[], bool *isEncrypt, bool *isDecrypt, char **key, char **inputFile, char **outputFile);

// def-work with key
void addRoundKey(uint8_t text[4][4], uint8_t key[4][4]);
void subBytesKey(const int size, uint8_t word[size]);
uint8_t *keyExpansion(const uint8_t key[KEY_SIZE]);
char *keyAdjustment(const char *key);
char *addPadding(const char *input, const int size);
char *cutInput(const char *input, const int size);

// def-array/matrix
void toMatrix(uint8_t matrix[4][4], uint8_t *data);
void toArray(uint8_t *data, uint8_t matrix[4][4]);
void transposeMatrix(uint8_t matrix[4][4]);

// def-shiftBytes
void shiftToLeft(const int size, uint8_t word[size]);
void shiftToRight(const int size, uint8_t word[size]);

// def-PKCS-7
bool padMessage(const uint8_t *plaintext, uint8_t *paddedText, const size_t originalLength, const size_t paddedLength);
bool countOriginalLength(uint8_t *paddedText, size_t *originalLength, size_t paddedLength);

// def-char/bytes
bool convertCharToBytes(const char *src, uint8_t *dest, const size_t bytesCount);
bool convertBytesToChar(const uint8_t *src, char *dest, const size_t bytesCount);
uint8_t rotByteByBit(uint8_t byte);

// def-shiftRows(Inverse)
void shiftRows(uint8_t state[4][4]);
void invShiftRows(uint8_t state[4][4]);

// def-Galois Field Multiplocations
uint8_t galoisFieldMultiplication2(uint8_t x);
uint8_t galoisFieldMultiplication3(uint8_t x);
uint8_t galoisFieldMultiplication9(uint8_t x);
uint8_t galoisFieldMultiplication11(uint8_t x);
uint8_t galoisFieldMultiplication13(uint8_t x);
uint8_t galoisFieldMultiplication14(uint8_t x);

// def-mixColumns(Inverse)
void mixColumns(uint8_t state[4][4]);
void invMixColumns(uint8_t state[4][4]);

// def-substitution(Inverse)
void substitution(uint8_t state[4][4]);
void invSubstitution(uint8_t state[4][4]);

// def-encryption
void aesRound(uint8_t state[4][4], uint8_t roundKey[4][4]);
void aesFinalRound(uint8_t state[4][4], uint8_t roundKey[4][4]);
void aesEncrypt(unsigned char *message, unsigned char *expandedKey);

// def-decryption
void aesInvRound(uint8_t state[4][4], uint8_t roundKey[4][4]);
void aesInvFinalRound(uint8_t state[4][4], uint8_t roundKey[4][4]);
void aesDecrypt(unsigned char *message, unsigned char *expandedKey);

// def-files
uint8_t *readFileDynamic(const char *filename, size_t *fileSize);

// def-mainBlocks
uint8_t *encrypt(const char *text, const char *key, uint8_t **result, size_t *resultLength);
uint8_t *decrypt(const char *ciphertext, const char *key, uint8_t **result, const size_t cipehrLength, size_t *resultLength);

#pragma endregion


// Round Constant (is a predefined set of values used in AES)
const uint8_t Rcon[10] = {
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
};

// program loop
int main(int argc, char *argv[]) {
    // define params
    bool isEncrypt = false, isDecrypt = false;
    char *key = NULL, *inputFile = NULL, *outputFile = NULL;
    size_t fileSize;  // -> size of input
    char *text = NULL;  // -> pointer for input
    uint8_t *result = NULL;  // -> pointer for encr/decr data
    size_t resultLength;  // -> length of the processed data
    FILE *outputFileWrite = NULL;
    size_t written;  // -> number of bytes written to output file

    // check whether parsing was successful
    if (!parseArguments(argc, argv, &isEncrypt, &isDecrypt, &key, &inputFile, &outputFile)) {
        printf("chyba\n");

        free(key);
        free(inputFile);
        free(outputFile);


        return 1;
    }

    // read file without knowing its size (read in bi mode)
    text = (char *)readFileDynamic(inputFile, &fileSize);
    
    // check whether reading file was successful
    if (!text) {
        printf("chyba\n");

        free(key);
        free(inputFile);
        free(outputFile);
        
        return 1;
    }

    // define pointer for result and size of encrypted/decrypted data
    if (isEncrypt) {
        result = encrypt(text, key, &result, &resultLength);
    } else if (isDecrypt) {
        result = decrypt(text, key, &result, fileSize, &resultLength);
    }

    // check if encr/decr was successful
    if (!result) {
        printf("chyba\n");

        free(key);
        free(inputFile);
        free(outputFile);
        
        return 1;
    }

    // writing result into file (bi-mode)
    outputFileWrite = fopen(outputFile, "wb");
    if (!outputFileWrite) {
        printf("chyba\n");

        free(key);
        free(inputFile);
        free(outputFile);
        free(result);

        return 1;
    }

    // if encryption -> add num of padding
    if (isEncrypt) {
        written = fwrite(&resultLength, sizeof(size_t), 1, outputFileWrite);
    }
    written = fwrite(result, sizeof(uint8_t), resultLength, outputFileWrite);
    fclose(outputFileWrite);
    // check if writting was successful
    if (written != resultLength) {
        printf("chyba: Failed to write all data to the output file\n");

        free(key);
        free(inputFile);
        free(outputFile);
        free(result);
        
        return 1;
    }

    free(key);
    free(inputFile);
    free(outputFile);
    free(text);
    free(result);

    return 0;
}

#pragma region Main Blocks 
    /**
    * encrypts @param text using @param key, performing all necessary steps for encryption.
    * dtores the encrypted data in @param result and returns a dynamically allocated byte array. 
    * the encrypted data length is stored in @param resultLength.
    */
    uint8_t *encrypt(const char *text, const char *key, uint8_t **result, size_t *resultLength) {
        // validate input
        if (!text || !key) {
            return NULL;
        }
    
        // --------------------- Initialization ---------------------
        size_t textLength, paddedLength;
        uint8_t *plaintext = NULL, *plainkey = NULL, *paddedMessage = NULL;
        uint8_t *encryptedTextBytes = NULL, *expandedKey = NULL;
        char *adjustedKey = NULL;
    
        // calculate lengths
        textLength = strlen(text);
        paddedLength = textLength + (BLOCK_SIZE - (textLength % BLOCK_SIZE));
    
        // ----------------------------------------------------------
    
        // ------------------------ Encryption -----------------------
        
        // adjust key size
        adjustedKey = keyAdjustment(key);
        if (!adjustedKey) {
            return NULL;
        }
    
        // allocate and convert text to bytes
        plaintext = calloc(textLength, sizeof(uint8_t));
        if (!plaintext) return NULL;
        if (!convertCharToBytes(text, plaintext, textLength)) {
            free(plaintext);
            return NULL;
        }
    
        // allocate and convert key to bytes
        plainkey = calloc(KEY_SIZE, sizeof(uint8_t));
        if (!plainkey) {
            free(plaintext);
            return NULL;
        }
        if (!convertCharToBytes(adjustedKey, plainkey, KEY_SIZE)) {
            free(plaintext);
            free(plainkey);
            free(adjustedKey);
            return NULL;
        }
        free(adjustedKey);
    
        // expand key
        expandedKey = keyExpansion(plainkey);
        if (!expandedKey) {
            free(plainkey);
            return NULL;
        } 
        free(plainkey); 
    
        // apply padding
        paddedMessage = malloc(paddedLength);
        if (!paddedMessage) {
            free(expandedKey);
            return NULL;
        }
        if (!padMessage(plaintext, paddedMessage, textLength, paddedLength)) {
            free(paddedMessage);
            free(expandedKey);
            return NULL;
        }
        free(plaintext);
    
        // allocate memory for encryption
        encryptedTextBytes = malloc(paddedLength);
        if (!encryptedTextBytes) {
            free(paddedMessage);
            free(expandedKey);
            return NULL;
        }
    
        // encrypt block by block
        for (size_t i = 0; i < paddedLength; i += BLOCK_SIZE) {
            uint8_t ciphertext[BLOCK_SIZE];
            memcpy(ciphertext, paddedMessage + i, BLOCK_SIZE);
            aesEncrypt(ciphertext, expandedKey);
            memcpy(encryptedTextBytes + i, ciphertext, BLOCK_SIZE);
        }
        free(paddedMessage);
        free(expandedKey);
    
        // set pointer to encrypted data
        *result = encryptedTextBytes;
        // store new dataSize using pointer
        *resultLength = paddedLength;
    
        return encryptedTextBytes;
    }

    /**
    * Decrypts @param ciphertext using @param key, performing all necessary steps for decryption.
    * Stores the decrypted data in @param result and returns a dynamically allocated byte array.
    * The decrypted data length is stored in @param resultLength.
    */

    uint8_t *decrypt(const char *ciphertext, const char *key, uint8_t **result, const size_t cipehrLength, size_t *resultLength) {
        // validate input
        if (!ciphertext || !key) {
            return NULL;
        }

        // --------------------- Initialization ---------------------
        size_t originalLength;
        uint8_t *plainCiphertext = NULL, *plainkey = NULL, *decryptedTextBytes = NULL;
        uint8_t *expandedKey = NULL, *originalText = NULL;
        char *adjustedKey= NULL;

        // allocate memory for ciphertext and key (byte representation)
        plainCiphertext = malloc(cipehrLength);
        plainkey = malloc(KEY_SIZE);
        if (!plainCiphertext || !plainkey) {
            free(plainCiphertext);
            free(plainkey);
            return NULL;
        }

        // ----------------------------------------------------------

        // ------------------------ Decryption -----------------------

        //adjust key size
        adjustedKey = keyAdjustment(key);
        if (!adjustedKey) {
            return NULL;
        }

        // convert text and key to bytes
        if (!convertCharToBytes(ciphertext, plainCiphertext, cipehrLength) ||
            !convertCharToBytes(adjustedKey, plainkey, KEY_SIZE)) {
            free(plainCiphertext);
            free(plainkey);
            free(adjustedKey);
            return NULL;
        }
        free(adjustedKey);

        // expand key
        expandedKey = keyExpansion(plainkey);
        if (!expandedKey) {
            free(plainCiphertext);
            free(plainkey);
            return NULL;
        }
        free(plainkey);

        // allocate memory for decrypted text
        decryptedTextBytes = calloc(cipehrLength, sizeof(uint8_t));
        if (!decryptedTextBytes) {
            free(plainCiphertext);
            free(expandedKey);
            return NULL;
        }

        // decrypt block by block
        for (size_t i = 0; i < cipehrLength; i += BLOCK_SIZE) {
            uint8_t decrypted[BLOCK_SIZE];
            memcpy(decrypted, plainCiphertext + i, BLOCK_SIZE);
            aesDecrypt(decrypted, expandedKey);
            memcpy(decryptedTextBytes + i, decrypted, BLOCK_SIZE);
        }
        free(plainCiphertext);
        free(expandedKey);

        // determine original length (removing padding)
        if (!countOriginalLength(decryptedTextBytes, &originalLength, cipehrLength)) {
            free(decryptedTextBytes);
            return NULL;
        }

        // extract original text (without padding)
        originalText = calloc(originalLength + 1, sizeof(uint8_t));
        if (!originalText) {
            free(decryptedTextBytes);
            return NULL;
        }
        memcpy(originalText, decryptedTextBytes, originalLength);
        originalText[originalLength] = '\0'; 
        free(decryptedTextBytes);

        *result = originalText;
        *resultLength = originalLength;

        return originalText;
    }

#pragma endregion

#pragma region Work with File
    /**
    * reads the file @param filename, first determining its size and storing it in @param fileSize.
    * returns a dynamically allocated buffer containing the file data, or NULL on failure.
    */
    uint8_t *readFileDynamic(const char *filename, size_t *fileSize) {
        // open file in binary mode
        FILE *file = fopen(filename, "rb");
        if (!file) {
            return NULL;
        }
    
        size_t actualFileSize;
        // compute size of file
        fread(&actualFileSize, sizeof(size_t), 1, file);
        if (actualFileSize <= 0 ||  actualFileSize > MAX_FILE_SIZE || actualFileSize % BLOCK_SIZE != 0) { 
            fseek(file, 0, SEEK_END);
            actualFileSize = ftell(file);
            rewind(file);
        }
        *fileSize = actualFileSize;
    
        // Validate file size
        if (actualFileSize <= 0) {
            fclose(file);
            return NULL;
        }
    
        *fileSize = actualFileSize;
    
        // allocate memory for file data (+1 for null terminator)
        uint8_t *buffer = (uint8_t*)malloc(*fileSize + 1);
        if (!buffer) {
            fclose(file);
            return NULL;
        }
    
        // read file
        size_t bytesRead = fread(buffer, 1, *fileSize, file);
        fclose(file);
    
        // check if all data were read
        if (bytesRead != *fileSize) {
            free(buffer);
            return NULL;
        }
    
        // add null terminator for safe string handling
        buffer[*fileSize] = '\0';
    
        return buffer;
    }    

#pragma endregion

#pragma region Work with args
    /**
     * function to check if a file has a .txt extension
     */
     bool checkIfTxtFile(char *fileName) {
        if (!fileName) return false; 
        char *extension = strrchr(fileName, '.');
        return (extension && strcmp(extension, ".txt") == 0);
    }

    /**
     * function to parse command-line arguments
     */ 
     // todo: add free() -> because i won`t free att the main(will think that allocation is not successful)
     
     bool parseArguments(int argc, char *argv[], bool *isEncrypt, bool *isDecrypt, char **key, char **inputFile, char **outputFile) {
        // can be less than 6 arguments (mode, key, input, output + their flags)
        if (argc < 6) {
            return false;
        }
        
        // '-p' counter
        int keyCount = 0;
    
        // parse arguments
        for (int i = 1; i < argc; i++) {
            // encryption mode
            if (strcmp(argv[i], "-s") == 0) {
                *isEncrypt = true;
            // decryption mode
            } else if (strcmp(argv[i], "-d") == 0) {
                *isDecrypt = true;
            // parse key value
            } else if (strcmp(argv[i], "-p") == 0) {
                // check if the next argument exists and is not a flag
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    // store the next argument as the key
                    *key = strdup(argv[++i]);;
                    keyCount++;
                    // it is not possible to have more than one key
                    if (keyCount > 1) {
                        return false;
                    }
                } else {
                    return false;
                }
            // parse input file
            } else if (strcmp(argv[i], "-i") == 0) {
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    // store next arg as input file
                    *inputFile = strdup(argv[++i]);;
                } else {
                    return false;
                }
            // parse output file
            } else if (strcmp(argv[i], "-o") == 0) {
                if (i + 1 < argc && argv[i + 1][0] != '-') {
                    // store next arg as output file
                    *outputFile = strdup(argv[++i]);;
                } else {
                    return false;
                }
            } else {
                // invalid argument
                return false;
            }
        }
    
        // ensure valid argument combinations
        if ((*isEncrypt && *isDecrypt) || !*key || !*inputFile || !*outputFile) {
            return false;
        }

        //check wheter the files are .txt
        if(!checkIfTxtFile(*inputFile) || !checkIfTxtFile(*outputFile)) {
            return true;
        }
    
        return true;
    }

#pragma endregion

#pragma region Array Helper Functions (_1D_2D)
    #pragma region Array_Matrix
        /**
        * convert 1D array @param data to 2D @param matrix
        */
        void toMatrix(uint8_t matrix[4][4], uint8_t *data) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    matrix[row][col] = data[row + col * 4];
                }
            }
        }

        /**
        * convert 2D @param matrix to 1D array @param data
        */
        void toArray(uint8_t *data, uint8_t matrix[4][4]) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    data[row + col * 4] = matrix[row][col];
                }
            }
        }

        /**
        * function to swap the rows with columns of a @param matrix 
        */
        void transposeMatrix(uint8_t matrix[4][4]) {
            uint8_t temp;
            for (int row = 0; row < 4; row++) {
                for (int col = row + 1; col < 4; col++) {
                    temp = matrix[row][col];
                    matrix[row][col] = matrix[col][row];
                    matrix[col][row] = temp;
                }
            }
        }        

    #pragma endregion

    #pragma region ShiftBytes
        /** 
        * shift the @param word to the left by 1 byte: [1, 2, 3] -> [2, 3, 1]
        */
        void shiftToLeft(const int size, uint8_t word[size]) {
            uint8_t lastBit = word[0];
            for (int i = 0; i < size - 1; i++) {
                word[i] = word[i + 1];
            }
            word[size - 1] = lastBit;
        }

        /**
        * shift the @param word to the right by 1 byte: [1, 2, 3] -> [3, 1, 2]
        */
        void shiftToRight(const int size, uint8_t word[size]) {
            uint8_t lastBit = word[size - 1];
            for (int i = size - 1; i > 0; i--) {
                word[i] = word[i - 1];
            }
            word[0] = lastBit;
        }
    #pragma endregion

    #pragma region PKCS_7 
        /**
        * provides padding for a @param message using PKCS#7 to make it a multiple of 16 bytes.
        */
        bool padMessage(const uint8_t *plaintext, uint8_t *paddedText, const size_t originalLength, const size_t paddedLength) {
            // check input validity
            if(plaintext == NULL || paddedText == NULL || originalLength <= 0 || paddedLength <= 0) {
                return false;
            }

            // number of bytes to pad
            // size_t paddingNum = (originalLength % BLOCK_SIZE == 0) ? BLOCK_SIZE - (originalLength % BLOCK_SIZE) : 0;
            size_t paddingNum = BLOCK_SIZE - (originalLength % BLOCK_SIZE);

            // it is creater that BLOCK_SIZE so there will be no mistake while remove padding
            uint8_t paddingValue = BLOCK_SIZE + paddingNum;
            
            // store result of copying and check if it was successful
            void *flag = memcpy(paddedText, plaintext, originalLength);
            if(flag == NULL) {
                return false;
            }


            // fill remaining space with padding bytes
            for(size_t i = originalLength; i < paddedLength; i++) {
                paddedText[i] = paddingValue;
            }

            return true;
        }

         /**
        * count the original length (without padding) of @param message and store result in @param originalLength.
        */ 
        bool countOriginalLength(uint8_t *paddedText, size_t *originalLength, size_t paddedLength) {
            // check input validity
            if (paddedText == NULL || paddedLength == 0 || originalLength == NULL) {
                return false;
            }
            
            // get the padding value
            size_t paddingValue = paddedText[paddedLength - 1];
        
            // padding value must be at least BLOCK_SIZE and at most BLOCK_SIZE * 2
            // if not so it is byte from original text
            if (paddingValue < BLOCK_SIZE || paddingValue > (BLOCK_SIZE * 2)) {
                *originalLength = paddedLength;
                return true;
            }
        
            size_t paddingNum = paddingValue - BLOCK_SIZE;
        
            // ensure paddingNum is valid
            if (paddingNum > BLOCK_SIZE || paddingNum >= paddedLength) {
                return false;
            }
        
            // compute new length
            *originalLength = paddedLength - paddingNum;
        
            return true;
        }
        
    #pragma endregion
    
    #pragma region Char_and_Bytes
        /**
         * take already adjusted(padded) text ( @param text) and convert it into bytes-array ( @param plaintext)
         */
         bool convertCharToBytes(const char *src, uint8_t *dest, const size_t bytesCount) {
            if(src == NULL || dest == NULL || bytesCount <= 0) {
                return false;
            }

            if (strlen(src) > bytesCount) {
                return false;  // Prevent buffer overflow
            }
            
            if(!memcpy(dest, src, bytesCount)) {
                return false;
            }

            return true;
        }

        /**
        * convert a byte array ( @param bytes ) into a null-terminated string ( @param text )
        */
        bool convertBytesToChar(const uint8_t *src, char *dest, const size_t bytesCount) {
            if (src == NULL || dest == NULL || bytesCount == 0) {
                return false;
            }
        
            if(!memcpy(dest, src, bytesCount)) {
                return false;
            }
            dest[bytesCount] = '\0';  // Ensure null termination
        
            return true;
        }

        /** 
        * rotate @param byte to the left by 1 bit
        */
        uint8_t rotByteByBit(uint8_t byte) {
            return (byte << 1) | (byte >> 7);
        }
        
    #pragma endregion
#pragma endregion

#pragma region Work with Key
    /**
     * XOR between two 4x4 matrices ( @param text and @param key)
     */
    void addRoundKey(uint8_t text[4][4], uint8_t key[4][4]) {
        transposeMatrix(key);

        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                text[row][col] ^= key[row][col];
            }
        }
    }

    /** 
    * apply rotation for every bit in word (instead of S-Box)
    */
    void subBytesKey(const int size, uint8_t word[size]) {
        for (int i = 0; i < size; i++) {
            word[i] = rotByteByBit(word[i]);
        }
    }

    /**
    * expanse @param key into derives multiple subkeys (round keys) 
    */
    uint8_t *keyExpansion(const uint8_t key[KEY_SIZE]) {
        // alocate memory for all round`s subkey
        uint8_t *expandedKey = calloc(EXPANDED_KEY_SIZE + 1, sizeof(uint8_t));
        if (!expandedKey) {
            return NULL;
        }

        int expKeyIndex = 0;
        // copy the secret key to the expanded key
        for (int i = 0; i < KEY_SIZE; i++) {
            expandedKey[i] = key[i];
        }
        expKeyIndex += KEY_SIZE;

        uint8_t tempWord[4];
        // every subkey divide into 4-byte word to generate next subkey 
        while (expKeyIndex < EXPANDED_KEY_SIZE) {
            // copy last 4 bytes into temp array
            for (int i = 0; i < 4; i++) {
                tempWord[i] = expandedKey[expKeyIndex - 4 + i];
            }

            // apply RotWord, SubBytes, and Rcon transformations on the last key-word.
            if (expKeyIndex % KEY_SIZE == 0) {
                shiftToLeft(4, tempWord);
                subBytesKey(4, tempWord);
                int rconIndex = (expKeyIndex / KEY_SIZE) - 1;
                tempWord[0] ^= Rcon[rconIndex];  
            }
            
            // generate the next 4 bytes of the expanded key
            for (int i = 0; i < 4; i++) {
                expandedKey[expKeyIndex + i] = expandedKey[expKeyIndex - KEY_SIZE + i] ^ tempWord[i];
            }

            // move to the next word
            expKeyIndex += 4;
        }

        return expandedKey;
    }
    

    /**
    * adjust @param key before starting encr/decryption
    */
    char *keyAdjustment(const char *key) {
        char *newKey;

        int keySize = strlen(key);
        // secret key is too short
        if (keySize < KEY_SIZE) {
            newKey = addPadding(key, KEY_SIZE);
        // secret key is too long
        } else if (keySize > KEY_SIZE) {
            newKey = cutInput(key, KEY_SIZE);
        } else {
            // allocate and copy the key as-is
            newKey = strdup(key);
        }

        return newKey;
    }

    /**
    * adds padding to a string to fit a @param size
    */
    char *addPadding(const char *input, const int size) {
        // allocate memory with given 'size' and copy given 'input'
        char *newInput = calloc(size + 1, sizeof(char));
        if (!newInput){
            return NULL; 
        }
        int inputLen = strlen(input);
        strncpy(newInput, input, inputLen);

        // add padding with '0' if needed
        for (int i = inputLen; i < size; i++) {
            newInput[i] = '0';
        }
        
        // ensure null termination
        newInput[size] = '\0';

        return newInput;
    }

    /**
    * cuts the input string to fit a @param size
    */
    char *cutInput(const char *input, const int size) {
        if (!input || size <= 0) {
            return NULL;
        }

        // allocate memory for the new cut string (+1 for null terminator)
        char *newInput = calloc(size + 1, sizeof(char));
        if (!newInput) {
            return NULL; 
        }

        // copy up to 'size' characters from input
        strncpy(newInput, input, size);

        // ensure null termination
        newInput[size] = '\0';

        return newInput;
    }

#pragma endregion

#pragma region Encryption/Decryption help-function
    #pragma region shiftRows
        /** 
         * each row of the state matrix is cyclically shifted to the left:
         * - Row 0 remains unchanged
         * ...
         * - Row k is shifted left by k positions
         */
        void shiftRows(uint8_t state[4][4]) {
            for (int i = 1; i < 4; i++) {
                // shift left `i` times
                for (int j = 0; j < i; j++) {
                    shiftToLeft(4, state[i]);
                }
            }  
        }

        /**
         * each row of the state matrix is cyclically shifted to the right:
         * - Row 0 remains unchanged
         * ...
         * - Row k is shifted right by k positions
         */
        void invShiftRows(uint8_t state[4][4]) {
            for (int i = 1; i < 4; i++) {
                // Shift right `i` times
                for (int j = 0; j < i; j++) {
                    shiftToRight(4, state[i]);
                }
            }
        }
    #pragma endregion

    #pragma region MixColumns
        #pragma region Galois Field Multiplication

            /** 
            * multiply by 2 in GF(2^8)
            */
            uint8_t galoisFieldMultiplication2(uint8_t x) {
                return (x & 0x80) ? ((x << 1) ^ 0x1B) : (x << 1);
            }
            
            /** 
             * multiply by 3 in GF(2^8) (x * 3 = (x * 2) ^ x)
            */
            uint8_t galoisFieldMultiplication3(uint8_t x) {
                return galoisFieldMultiplication2(x) ^ x;
            }
            
            /** 
             * multiply by 9 in GF(2^8) (x * 9 = (x * 2 * 2 * 2) ^ x)
             */
            uint8_t galoisFieldMultiplication9(uint8_t x) {
                return galoisFieldMultiplication2(galoisFieldMultiplication2(galoisFieldMultiplication2(x))) ^ x;
            }
            
            /**
             * multiply by 11 in GF(2^8) (x * 11 = (x * 2 * 2 * 2) ^ (x * 2) ^ x)
             */
            uint8_t galoisFieldMultiplication11(uint8_t x) {
                return galoisFieldMultiplication2(galoisFieldMultiplication2(galoisFieldMultiplication2(x)) ^ x) ^ x;
            }
            
            /** 
             * multiply by 13 in GF(2^8) (x * 13 = (x * 2 * 2 * 2) ^ (x * 2 * 2) ^ x)
            */
            uint8_t galoisFieldMultiplication13(uint8_t x) {
                return galoisFieldMultiplication2(galoisFieldMultiplication2(galoisFieldMultiplication2(x) ^ x)) ^ x;
            }
            
            /** 
             * multiply by 14 in GF(2^8) (x * 14 = (x * 2 * 2 * 2) ^ (x * 2 * 2) ^ (x * 2))
             */
            uint8_t galoisFieldMultiplication14(uint8_t x) {
                return galoisFieldMultiplication2(galoisFieldMultiplication2(galoisFieldMultiplication2(x) ^ x) ^ x);
            }
        
            
        #pragma endregion

        // todo: rewrite so function will return pointer for better style and easy debug
        /**
         * using predefined rules for matrix multiplication 
         * in Galois Field GF(2⁸) to provide diffusion to 
         * compute new values for columns of @param state
         */
        void mixColumns(uint8_t state[4][4]) {
        
            for (int col = 0; col < 4; col++) {
                // store column values for easy debug
                uint8_t s0 = state[0][col];
                uint8_t s1 = state[1][col];
                uint8_t s2 = state[2][col];
                uint8_t s3 = state[3][col];
        
                // compute new values with predefine matrix multiplication rules in Galois Field GF(2⁸)
                state[0][col] = galoisFieldMultiplication2(s0) ^ galoisFieldMultiplication3(s1) ^ s2 ^ s3;
                state[1][col] = s0 ^ galoisFieldMultiplication2(s1) ^ galoisFieldMultiplication3(s2) ^ s3;
                state[2][col] = s0 ^ s1 ^ galoisFieldMultiplication2(s2) ^ galoisFieldMultiplication3(s3);
                state[3][col] = galoisFieldMultiplication3(s0) ^ s1 ^ s2 ^ galoisFieldMultiplication2(s3);
            }
        }
        
        /**
         * using predefined rules for matrix multiplication 
         * in Galois Field GF(2⁸) to reverse diffusion to 
         * compute new values for columns of @param state
         */
        void invMixColumns(uint8_t state[4][4]) {
            for (int col = 0; col < 4; col++) {
                // store column values for easy debugging
                uint8_t s0 = state[0][col];
                uint8_t s1 = state[1][col];
                uint8_t s2 = state[2][col];
                uint8_t s3 = state[3][col];
        
                // compute new values using predefined matrix multiplication rules in Galois Field GF(2⁸)
                state[0][col] = galoisFieldMultiplication14(s0) ^ galoisFieldMultiplication9(s3) ^ 
                                galoisFieldMultiplication13(s2) ^ galoisFieldMultiplication11(s1);
        
                state[1][col] = galoisFieldMultiplication14(s1) ^ galoisFieldMultiplication9(s0) ^ 
                                galoisFieldMultiplication13(s3) ^ galoisFieldMultiplication11(s2);
        
                state[2][col] = galoisFieldMultiplication14(s2) ^ galoisFieldMultiplication9(s1) ^ 
                                galoisFieldMultiplication13(s0) ^ galoisFieldMultiplication11(s3);
        
                state[3][col] = galoisFieldMultiplication14(s3) ^ galoisFieldMultiplication9(s2) ^ 
                                galoisFieldMultiplication13(s1) ^ galoisFieldMultiplication11(s0);
            }
        }        
        
    #pragma endregion

    #pragma region Substitution
        /**
        * Applies substitution (left rotation by 3) to every byte in the state matrix.
        */
        void substitution(uint8_t state[4][4]) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    state[row][col] = (state[row][col] << 3) | (state[row][col] >> 5);
                }
            }
        }

        /**
        * Applies inverse substitution (right rotation by 3) to every byte in the state matrix.
        */
        void invSubstitution(uint8_t state[4][4]) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    state[row][col] = (state[row][col] >> 3) | (state[row][col] << 5);
                }
            }
        }

    #pragma endregion
#pragma endregion

#pragma region Encryption
    #pragma region Round
        /**
         * provides 1 round of aes encryption:
         * substitution(instead or s-box) -> shoftRows -> mixColums -> addRound
         */
        void aesRound(uint8_t state[4][4], uint8_t roundKey[4][4]){
            substitution(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKey);
        }
        
        /**
         * provides final round of AES (without mixColumns)
         */
        void aesFinalRound(uint8_t state[4][4], uint8_t roundKey[4][4]){
            substitution(state);
            shiftRows(state);
            addRoundKey(state, roundKey);
        }

    #pragma endregion
    
    /**
    *  provides full AES encryption
    */
    void aesEncrypt(unsigned char *message, unsigned char *expandedKey) {
        // transform message(array) into state-block(matrix)
        unsigned char state[4][4];
        toMatrix(state, message);

        // coppy first subkey(roundKey)
        uint8_t roundKeys[ROUNDS + 1][4][4];
        memcpy(roundKeys, expandedKey, EXPANDED_KEY_SIZE);

        // main aes encryption
        addRoundKey(state, roundKeys[0]);
        for (int i = 1; i < ROUNDS; i++) {
            aesRound(state, roundKeys[i]);
        }
        aesFinalRound(state, roundKeys[ROUNDS]);

        // copy encrypted state into massege (array-look)
        toArray(message, state);
    }

#pragma endregion

#pragma region Decryption
    #pragma region Round
        /**
         * provides 1 round of aes decryption:
         * invShiftRows -> invSubstitution(instead or s-box) -> invMixColums -> addRoundKey
         */
         void aesInvRound(uint8_t state[4][4], uint8_t roundKey[4][4]) {
            invShiftRows(state);
            invSubstitution(state);
            addRoundKey(state, roundKey);
            invMixColumns(state);
        }
        
        /**
         * provides final round of aes decryption (without invMixColumns)
         */
         void aesInvFinalRound(uint8_t state[4][4], uint8_t roundKey[4][4]) {
            invShiftRows(state);
            invSubstitution(state);
            addRoundKey(state, roundKey);
        }

    #pragma endregion

    /**
     * provides full aes decryption
    */
    void aesDecrypt(unsigned char *message, unsigned char *expandedKey) { 
        // transform message(array) into state-block(matrix)
        uint8_t state[4][4];
        toMatrix(state, message);
        
        // coppy first subkey(roundKey)
        uint8_t roundKeys[ROUNDS + 1][4][4];
        memcpy(roundKeys, expandedKey, EXPANDED_KEY_SIZE);
        
        // aes decryption
        addRoundKey(state, roundKeys[10]);
        for(int i = ROUNDS - 1; i > 0; i--){
            aesInvRound(state, roundKeys[i]);
        }
        aesInvFinalRound(state, roundKeys[0]);

        // copy encrypted state into massege (array-look)
        toArray(message, state);
    }

#pragma endregion
