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
mkdir -p results
rm -f results/*

# Ensure tests are executable
chmod +x ./*.sh

testNo=0
exitCode=0
index="results/index.md"
passCount=0
ignoreCount=0
failCount=0

echo -e "{% include tests.md %}\n\n| Test | Status |\n|-------|-------|" >$index

# Run all tests found in this folder
for filename in *.sh; do

  if [ "$filename" = "run-all.sh" ]; then
    continue
  fi

  testNo=$((testNo + 1))

  name=$(basename "$filename" .sh)

  printTest "$testNo" "$name"

  "./$filename" 2>/dev/null 1>&2
  RESULT=$?

  if [ $RESULT -eq 0 ]; then
    printPass
    echo "| [$name]($name.html) [🖹]($name.log) | ✅ PASSED |" >>$index
    passCount=$((passCount + 1))
  elif [ $RESULT -eq 1 ]; then
    printIgnore
    echo "| $name | 🤷‍♂️ IGNORED |" >>$index
    ignoreCount=$((ignoreCount + 1))
  else
    printFail
    exitCode=1
    echo "| [$name]($name.html) [🖹]($name.log) | ❌ FAILED |" >>$index
    failCount=$((failCount + 1))
  fi

  # If possible generate html output for the logs
  if
    [ -x "$(command -v aha)" ] &
    [ -f "results/$name.log" ]
  then
    aha -b -f "results/$name.log" >"results/$name.html"
  fi

done

echo -e "\n\n| Status | Frequency |\n|-------|-------|\n|Passed|$passCount|\n|Ignored|$ignoreCount|\n|Failed|$failCount|" >>$index

exit $exitCode
