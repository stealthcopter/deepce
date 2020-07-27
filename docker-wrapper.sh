#!/bin/sh
# This script will run deepce on every active docker container it finds

# Get the path to this script so we can find the deepce.sh script
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# Check if docker is accessible
if [ "$(command -v docker)" ]; then
    echo "Docker is accessible"
else
    echo "Error: Docker is not accessible"
    exit
fi

# Check if current user is root or in the docker group 
if groups | grep -q '\bdocker\b'; then
    echo "User is in docker group"
else
    if [ "$(id -u)" = 0 ]; then
        echo "User is root"
    else
        echo "Error: current user is not in docker group and is not root"
        exit
    fi
fi

containers=$(docker ps --format "{{.Names}}")
for container in $containers
do
    echo "Running deepce on docker container: $container"
    docker exec "$container" mkdir -p /deepce
    docker cp "$SCRIPTPATH/deepce.sh" "$container:/deepce/"
    docker exec "$container" /deepce/deepce.sh | tee "docker-$container.log"
    docker exec "$container" rm -rf /deepce
done
