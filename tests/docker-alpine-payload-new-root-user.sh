#!/bin/bash

if [ -z "$DEEPCE_DANGEROUS_TESTS" ] ; then
  # To run this test define DEEPCE_DANGEROUS_TESTS using the following:
  # export DEEPCE_DANGEROUS_TESTS=1
  echo "DEEPCE_DANGEROUS_TESTS not defined, skipping dangerous test"
  exit 1
fi

# check docker is available
docker ps >/dev/null 2>&1 || exit 1

# Create name for docker instance from the script name
name=deepce-$(basename "$0" .sh)
log=results/$(basename "$0" .sh).log

# Get the path to deepce script in parent directory
scriptPath=$(dirname "$PWD")/deepce.sh

# Remove and delete previous container if it exists
docker stop "$name" 2>/dev/null
docker rm "$name" 2>/dev/null

# Run the test using -nn (no network) so we're not waiting around
result=$(docker run --rm --name "$name" -v "$scriptPath":/root/deepce.sh --privileged alpine /root/deepce.sh -ne \
          -e PRIVILEGED \
          --user deepce \
          --password deepce \
          )

# Save the output
echo "$result" | tee "$log"

# Check if any commands were not found on this platform
if echo "$result" | grep -q "command not found"; then
  echo "Command not found"
  exit 2
fi

# Check if a new root user was added
if grep -q "deepce" /etc/passwd; then
  echo "We added a new root user!!!"
else
  echo "Failed to add a new root user"
  exit 101
fi