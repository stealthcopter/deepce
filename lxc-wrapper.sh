#!/bin/sh
# This script will run deepce on every active lxc container it finds

# Get the path to this script so we can find the deepce.sh script
SCRIPT=$(realpath "$0")
SCRIPTPATH=$(dirname "$SCRIPT")

# Check if lxc is accessible
if [ "$(command -v lxc)" ]; then
    echo "LXC is accessible"
else
    echo "Error: LXC is not accessible"
    exit
fi

# Check if current user is root or in the lxc group
if groups | grep -q '\blxd\b'; then
    echo "User is in lxd group"
else
    if [ "$(id -u)" = 0 ]; then
        echo "User is root"
    else
        echo "Error: current user is not in lxd group and is not root"
        exit
    fi
fi

containers=$(lxc list -c n --format csv)
for container in $containers
do
    echo "Running deepce on lxc container: $container"
    lxc exec "$container" -- mkdir -p /deepce
    lxc file push "$SCRIPTPATH/deepce.sh" "$container/deepce/"
    lxc exec "$container" "/deepce/deepce.sh" | tee "lxc-$container.log"
    lxc exec "$container" -- rm -rf /deepce
done
