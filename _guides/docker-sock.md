# Docker Sock

## Issue
The docker sock file usually found at `/var/run/docker.sock` exposes a HTTP API for interacting with the docker daemon. Any user capable of writing to this sock file can completely control docker including creating new containers which can be used to get command execution as root on the host operating system.

## Example
For an example of this please see the `exploitDockerSock()` method in `deepce.sh`. An explanation of this attack is listed below:

Use docker sock HTTP API to do the following:

1. Add a new container that mounts the root partition to /mnt
2. Start the container
3. Wait
4. Check the logs
5. Stop container
6. Remove container

## Fix
Avoiding adding the docker sock to any containers.

## Resources
