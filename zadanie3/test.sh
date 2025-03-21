#!/bin/bash

# File: test.sh
# Usage: ./test.sh [e|m|h|a]

BIN="./zadanie3"
VALGRIND="valgrind --leak-check=full --error-exitcode=123"

# Create temporary files
TMP_INPUT=$(mktemp)
TMP_CLEAN=$(mktemp)
TMP_OUT=$(mktemp)
TMP_ERR=$(mktemp)

test_easy() {
cat <<EOF > "$TMP_INPUT"
touch tuke
chown bps tuke
chmod 7 tuke
ls tuke             # Test3: Expected -> tuke bps rwx
mkdir tuke          # Test4: Expected -> chyba
mkdir folder
chmod 4 tuke
zapis tuke          # Test5: Expected -> chyba
chmod 0 folder
cd folder           # Test6: Expected -> chyba
chmod 7 folder
vypis tuke          # Test7: Expected -> ok
zapis folder        # Test8: Expected -> ok
quit
EOF
}

test_medium() {
cat <<EOF > "$TMP_INPUT"
mkdir a
cd a
mkdir b
cd b
mkdir c
cd c
touch deepfile
chown hacker deepfile
chmod 7 deepfile
vypis deepfile           # Test1: Expected -> ok
chmod 0 deepfile
vypis deepfile           # Test2: Expected -> chyba
chmod 4 deepfile
zapis deepfile           # Test3: Expected -> chyba
chmod 6 deepfile
zapis deepfile           # Test4: Expected -> ok
spusti deepfile          # Test5: Expected -> chyba
chmod 7 deepfile
spusti deepfile          # Test6: Expected -> ok
cd ..
cd ..
mkdir z
cd z
mkdir y
cd y
mkdir x
cd x
touch secret
chmod 0 secret
cd ../../../b/c
zapis ../../z/y/x/secret     # Test7: Expected -> chyba
chmod 2 ../../z/y/x/secret
zapis ../../z/y/x/secret     # Test8: Expected -> ok
cd ../../../
rm a                         # Test9: Expected -> chyba
rm a/b/c/deepfile
rm a/b/c                     # Test10: Expected -> ok
quit
EOF
}

test_hard() {
cat <<EOF > "$TMP_INPUT"
mkdir a
cd a
mkdir b
cd b
mkdir c
cd c
touch x
mkdir x               # Test1: Expected -> chyba
chmod 7 x
chown neo x
cd ..
cd ..
mkdir d
cd d
mkdir e
cd e
mkdir f
cd f
touch g
chmod 0 g
chmod 7 ../f
cd ../../../../a/b/c
vypis x               # Test2: Expected -> ok
chmod 0 x
vypis x               # Test3: Expected -> chyba
chmod 4 x
zapis x               # Test4: Expected -> chyba
chmod 6 x
zapis x               # Test5: Expected -> ok
cd ../../../d/e/f
touch hacked
chmod 7 hacked
chown agent hacked
cd ../../..
cd a/b/../b/./c
spusti ../../../d/e/f/hacked   # Test6: Expected -> ok
cd ../../../
rm a/b/c/x           # Test7: Expected -> ok
rm a/b/c             # Test8: Expected -> ok
rm a/b               # Test9: Expected -> ok
rm a                 # Test10: Expected -> ok
rm d                 # Test11: Expected -> chyba
rm d/e/f/hacked
rm d/e/f             # Test12: Expected -> ok
mkdir foo
touch foo            # Test13: Expected -> chyba
mkdir foo/bar        # Test14: Expected -> ok
touch foo/bar/baz
chmod 0 foo/bar/baz
vypis foo/bar/baz    # Test15: Expected -> chyba
chown root foo/bar/baz
chmod 4 foo/bar/baz
vypis foo/bar/baz    # Test16: Expected -> ok
chmod 99 foo         # Test17: Expected -> chyba
chmod -1 foo         # Test18: Expected -> chyba
chmod 7 foo
zapis foo            # Test19: Expected -> ok
ls /
quit
EOF
}

run_tests_and_check() {
    local test_input="$1"
    local test_name="$2"
    local test_emoji="$3"

    echo -e "\n$test_emoji Running $test_name tests..."

    # Prepare clean input file (without comment lines)
    grep -vE '^#|^$' "$test_input" > "$TMP_CLEAN"

    # Run your program
    $BIN < "$TMP_CLEAN" > "$TMP_OUT" 2> "$TMP_ERR"
    
    # Initialize arrays to track test cases and their expected results
    declare -a test_ids=()
    declare -a expected_results=()
    
    # First pass: collect all test cases and their expected results
    while IFS= read -r line; do
        if [[ "$line" =~ \#\ Test([0-9]+):\ Expected\ -\>\ ([a-zA-Z0-9]+) ]]; then
            test_ids+=(${BASH_REMATCH[1]})
            expected_results+=(${BASH_REMATCH[2]})
        fi
    done < "$test_input"
    
    # Read actual outputs
    mapfile -t actual_lines < "$TMP_OUT"
    
    # Track if we have any failures
    failures=0
    
    # Now validate each test
    for i in "${!test_ids[@]}"; do
        test_id="${test_ids[$i]}"
        expected="${expected_results[$i]}"
        
        # Look through all output lines for the expected result
        found=0
        for actual in "${actual_lines[@]}"; do
            if [[ "$actual" == *"$expected"* ]]; then
                echo "✅ Test$test_id passed"
                found=1
                break
            fi
        done
        
        if [[ $found -eq 0 ]]; then
            echo "❌ Test$test_id failed (expected: $expected, not found in output)"
            failures=$((failures + 1))
        fi
    done
    
    # Only print output if there were failures
    if [[ $failures -gt 0 ]]; then
        echo "Program output:"
        cat "$TMP_OUT"
        echo "---"
    fi
}

# Handle args
case "$1" in
    e)
        echo "🔧 Running easy tests..."
        test_easy
        run_tests_and_check "$TMP_INPUT" "easy"
        ;;
    m)
        echo "🧪 Running medium tests..."
        test_medium
        run_tests_and_check "$TMP_INPUT" "med"
        ;;
    h)
        echo "🧨 Running hard tests..."
        test_hard
        run_tests_and_check "$TMP_INPUT" "hard"
        ;;
    a)
        echo "🏁 Running all tests..."
        test_easy
        run_tests_and_check "$TMP_INPUT" "easy" "🐣"

        test_medium
        run_tests_and_check "$TMP_INPUT" "med" "🤓"

        test_hard
        run_tests_and_check "$TMP_INPUT" "hard" "😈"
        ;;
    *)
        echo "Usage: $0 [e|m|h|a]"
        exit 1
        ;;
esac

# Run under valgrind
echo -e "\n🧼 Valgrind memory check..."
$VALGRIND $BIN < "$TMP_CLEAN" > /dev/null 2>&1

if [[ $? -eq 123 ]]; then
    echo "❌ Valgrind found memory issues!"
else
    echo "✅ No memory leaks detected."
fi

# Clean up
rm -f "$TMP_INPUT" "$TMP_CLEAN" "$TMP_OUT" "$TMP_ERR"