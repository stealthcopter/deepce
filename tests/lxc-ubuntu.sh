#!/bin/bash

# check lxc is available
lxc list >/dev/null 2>&1 || exit 1

# Create name for docker instance from the script name
name=deepce-$(basename "$0" .sh)
log=results/$(basename "$0" .sh).log

# Get the path to deepce script in parent directory
scriptPath=$(dirname "$PWD")/deepce.sh

# Run the test using -nn (no network) so we're not waiting around
lxc launch ubuntu: "$name"
lxc exec "$name" -- mkdir -p /deepce
lxc file push "$scriptPath" "$name/deepce/"
result=$(lxc exec "$name" "/deepce/deepce.sh")
lxc exec "$name" -- rm -rf /deepce
lxc stop "$name"
lxc delete "$name"

# Save the output
echo "$result" | tee "$log"

# Check if any commands were not found on this platform
if echo "$result" | grep -q "command not found"; then
  echo "Command not found"
  exit 2
fi
