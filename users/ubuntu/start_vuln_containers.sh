#!/bin/bash

echo "Creating a vulnerable container with docker sock exposed"
docker run -d -it --name deepce-container-escape1 -v /var/run/docker.sock:/var/run/docker.sock ubuntu
