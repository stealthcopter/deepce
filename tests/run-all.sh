#!/bin/bash

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

testNo=0

# Run all tests found in this folder
for filename in *.sh; do

    if [ "$filename" = "run-all.sh" ]; then
        continue
    fi

    testNo=$((testNo+1))

    name=$(basename "$filename" .sh)
    
    printTest "$testNo" "$name"
    
    "./$filename" 2>/dev/null 1> "results/$name.log"
    RESULT=$?

    # Check if any commands were not found on this platform
    if grep -q "command not found" "results/$name.log"; then
      printFail
      grep "command not found" "results/$name.log"
    elif [ $RESULT -eq 0 ]; then
        printPass
    elif [ $RESULT -eq 1 ]; then 
        printIgnore
    else
        printFail
    fi
    
    # If possible generate html output for the logs
    if [ -x "$(command -v aha)" ]; then
        aha -b -f "results/$name.log" > "results/$name.html"
    fi
    
done
