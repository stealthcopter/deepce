#!/bin/bash

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
          --shadow \
          )

# Save the output
echo "$result" | tee "$log"

# Check if any commands were not found on this platform
if echo "$result" | grep -q "command not found"; then
  echo "Command not found"
  exit 2
fi

# Check if a new root user was added
if echo "$result" | grep -q "^root:"; then
  echo "We printed /etc/shadow"
else
  echo "Failed to print /etc/shadow"
  # FIXME: Ignoring result
  exit 1
fi
