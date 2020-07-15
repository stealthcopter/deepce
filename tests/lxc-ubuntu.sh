#!/bin/bash

# check lxc is avaliable
lxc list >/dev/null 2>&1 || exit 1

# Create name for docker instance from the script name
name=deepce-$(basename $0 .sh)

# Get the path to deepce script in parent directory
scriptPath=$(dirname "$PWD")/deepce.sh

# Run the test using -nn (no network) so we're not waiting around
lxc launch ubuntu: $name
lxc exec "$name" -- mkdir -p /deepce
lxc file push "$scriptPath" "$name/deepce/"
lxc exec "$name" "/deepce/deepce.sh"
lxc exec "$name" -- rm -rf /deepce
lxc stop "$name"
lxc delete "$name"