# Docker Group

## Issue
Any user in the docker group can elevate to root by creating a docker container and mounting the root file system inside the container.

The docker documentation states that every user in the docker group needs to be trusted. However this is a flawed security model, as even if the user is trustworth every single piece of code they run may not be and any application ran by that user has the ability to elevate itself to root without permission. 

## Example
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt /bin/bash
```

## Fix

TODO: Add solutions

## Resources
