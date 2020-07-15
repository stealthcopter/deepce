#!/bin/bash

# check docker is avaliable
docker ps >/dev/null 2>&1 || exit 1

# Create name for docker instance from the script name
name=deepce-$(basename $0 .sh)

# Get the path to deepce script in parent directory
scriptPath=$(dirname "$PWD")/deepce.sh

# Remove and delete previous container if it exists
docker stop $name
docker rm $name

# Run the test using -nn (no network) so we're not waiting around
docker run --rm -it --name $name -v "$scriptPath":/root/deepce.sh alpine /root/deepce.sh -nn