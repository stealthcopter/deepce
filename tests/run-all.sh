#!/bin/bash

echo "Running all tests"

# Printing functions
C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
Y="${C}[1;33m"
NC="${C}[0m"

printTest() { 
    line='.......................................................'
    NAME="Test #000:$2 "
    printf "Test #%03d:%s %s " "$1" "$2" "${line:${#NAME}}"
}

printPass() { printf "%sPass%s\n" "${GREEN}" "$NC"; }
printIgnore() { printf "%sIgnore%s\n" "${Y}" "$NC"; }
printFail() { printf "%sFail%s\n" "${RED}" "$NC"; }

# Empty results folder
rm -f results/*

# Ensure tests are executable
chmod +x *.sh

testNo=0
exitCode=0
index="results/index.md"

echo -e "# Test Results\n" > $index

# Run all tests found in this folder
for filename in *.sh; do

    if [ "$filename" = "run-all.sh" ]; then
        continue
    fi

    testNo=$((testNo+1))

    name=$(basename "$filename" .sh)
    
    printTest "$testNo" "$name"
    
    "./$filename" 2>/dev/null 1>&2
    RESULT=$?

    if [ $RESULT -eq 0 ]; then
        printPass
        echo "- [$name]($name.html) - PASS" >> $index
    elif [ $RESULT -eq 1 ]; then 
        printIgnore
        echo "- [$name]($name.html) - IGNORED" >> $index
    else
        printFail
        exitCode=1
        echo "- [$name]($name.html) - FAILED" >> $index
    fi
    
    # If possible generate html output for the logs
    if [ -x "$(command -v aha)" ] & [ -f "results/$name.log" ]; then
        aha -b -f "results/$name.log" > "results/$name.html"
    fi
    
done

exit $exitCode
