#!/bin/bash
INPUT_FILE="input.txt"
ENC_FILE="encrypted.txt"
DEC_FILE="decrypted.txt"
PASSWORDS=("test" " " "longpassword123" "!@#\$%^&*()" "日本語")

# Cleanup before tests
rm -f "$ENC_FILE" "$DEC_FILE"
TOTAL_TESTS=0
PASSED_TESTS=0

should_fail() {
    local password="$1"
    [[ "$password" == "" ]] && return 0
    return 1
}

run_test() {
    local password="$1"
    local order="$2"
    
    # Cleanup files
    rm -f "$ENC_FILE" "$DEC_FILE"
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    
    echo "=== Testing with password: \"$password\" ==="
    
    # Build encryption command - properly escape the password for shell
    local esc_password=$(printf '%q' "$password")
    
    # Build encryption command based on parameter order
    case "$order" in
        1) ENC_CMD="./zadanie1 -s -p $esc_password -i \"$INPUT_FILE\" -o \"$ENC_FILE\"" ;;
        2) ENC_CMD="./zadanie1 -s -i \"$INPUT_FILE\" -o \"$ENC_FILE\" -p $esc_password" ;;
        3) ENC_CMD="./zadanie1 -s -o \"$ENC_FILE\" -i \"$INPUT_FILE\" -p $esc_password" ;;
        4) ENC_CMD="./zadanie1 -p $esc_password -s -i \"$INPUT_FILE\" -o \"$ENC_FILE\"" ;;
        5) ENC_CMD="./zadanie1 -p $esc_password -i \"$INPUT_FILE\" -s -o \"$ENC_FILE\"" ;;
        6) ENC_CMD="./zadanie1 -i \"$INPUT_FILE\" -o \"$ENC_FILE\" -s -p $esc_password" ;;
    esac
    
    # Build decryption command
    DEC_CMD="./zadanie1 -d -p $esc_password -i \"$ENC_FILE\" -o \"$DEC_FILE\""
    
    echo "Running encryption: $ENC_CMD"
    eval "$ENC_CMD"
    ENC_EXIT_CODE=$?
    
    echo "Running decryption: $DEC_CMD"
    eval "$DEC_CMD"
    DEC_EXIT_CODE=$?
    
    if should_fail "$password"; then
        if [[ $ENC_EXIT_CODE -ne 0 || $DEC_EXIT_CODE -ne 0 ]]; then
            echo "✅ Expected failure, test passed."
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "❌ Unexpected success, test failed!"
        fi
        return
    fi
    
    if [[ $ENC_EXIT_CODE -ne 0 || $DEC_EXIT_CODE -ne 0 ]]; then
        echo "❌ Unexpected failure, test failed!"
        return
    fi
    
    INPUT_HASH=$(sha256sum "$INPUT_FILE" | awk '{print $1}')
    ENC_HASH=$(sha256sum "$ENC_FILE" | awk '{print $1}')
    DEC_HASH=$(sha256sum "$DEC_FILE" | awk '{print $1}')
    
    echo "SHA-256 Hashes:"
    echo "  Input:      $INPUT_HASH"
    echo "  Encrypted:  $ENC_HASH"
    echo "  Decrypted:  $DEC_HASH"
    
    if [[ "$INPUT_HASH" == "$ENC_HASH" ]]; then
        echo "❌ Encryption failed: Input and Encrypted hashes match!"
    elif [[ "$INPUT_HASH" != "$DEC_HASH" ]]; then
        echo "❌ Decryption failed: Input and Decrypted hashes don't match!"
    else
        echo "✅ Encryption and decryption successful!"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    fi
    echo "------------------------------"
}

# Run through all passwords and parameter orders
for password in "${PASSWORDS[@]}"; do
    for order in {1..6}; do
        run_test "$password" "$order"
    done
done

# Testing invalid cases
test_invalid_case() {
    local cmd="$1"
    local expected_to_fail="$2"
    echo "=== Testing case: '$cmd' ==="
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    eval "$cmd"
    EXIT_CODE=$?
    
    if [[ "$expected_to_fail" == "true" ]]; then
        if [[ $EXIT_CODE -ne 0 ]]; then
            echo "✅ Expected failure, test passed."
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "❌ Unexpected success, test failed!"
        fi
    else
        if [[ $EXIT_CODE -eq 0 ]]; then
            echo "✅ Expected success, test passed."
            PASSED_TESTS=$((PASSED_TESTS + 1))
        else
            echo "❌ Unexpected failure, test failed!"
        fi
    fi
    echo "------------------------------"
}

# True means "should fail" for these cases
test_invalid_case "./zadanie1 -s -p -i \"$INPUT_FILE\" -o \"$ENC_FILE\"" "true"  # Missing password
test_invalid_case "./zadanie1 -s -p password -o \"$ENC_FILE\"" "true"  # Missing input file
test_invalid_case "./zadanie1 -s -p password -i \"$INPUT_FILE\"" "true"  # Missing output file

# False means "should pass" for this case - direct decryption is allowed
test_invalid_case "./zadanie1 -d -p password -i \"$INPUT_FILE\" -o \"$ENC_FILE\"" "false"  # Decrypt without prior encrypt

echo "✅ Passed $PASSED_TESTS out of $TOTAL_TESTS tests."
