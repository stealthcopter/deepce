#!/bin/bash

echo "Starting a vulnerable docker instances"

# Privilged container
echo "Starting: privileged-ubuntu-5555"
echo "  - Privileged container to escape"
echo "  - Meteperter is running on port 5555"

docker run -d --rm -it --name privileged-ubuntu-5555 -p 5555:5555 --privileged ubuntu
docker cp /home/metasploit/bind5555.bin privileged-ubuntu-5555:/
docker exec -d privileged-ubuntu-5555 /bind5555.bin

echo -e "\nUse metasploit to connect to this container and perform a container escape"

docker run -d --rm -it --name ubuntu-with-secrets -e ROOT_PASSWORD=g00dp4ssw0rd ubuntu

echo "\nDone deepce{runn1ng_scr1pts_1s_h4rd}"
