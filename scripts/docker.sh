#!/bin/bash

sudo apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg-agent \
    software-properties-common

sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
   
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io

sudo usermod -aG docker ubuntu

docker run -d --restart=unless-stopped --name alpine-with-secrets -e MYSQL_PASSWORD=S00perS3rect alpine tail -f /dev/null
docker run -d --restart=unless-stopped --name ubuntu-with-files ubuntu tail -f /dev/null

docker cp /tmp/scripts/flag.txt ubuntu-with-files:/

docker pull alpine:3.5
docker pull archlinux 
docker pull busybox 
docker pull fedora 
docker pull php
