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

# Getting / Running it

```bash
wget https://github.com/stealthcopter/deepce/deepce.sh 
```

# Overview

Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)

In order for it to be compatible with the maximum number of containers DEEPCE is written in pure `sh` with no dependancies. It will make use of additional tools such as curl, nmap, nslookup and dig if avaliable but for the most part is not reliant upon them for enumeration.

None of the enumeration should touch the disk, however most of the exploits create new containers which will cause disk writes and some of the exploits overwrite runC which can be destructive, so be careful! Most of the scans 

## Enumerations

The following is the list of enumerations performed by DEEPCE. 

- Container ID & name (via reverse dns)
- Container IP / DNS Server
- Discover docker version
- Interesting mounts
- Passwords in common files and environment variables
- Password hashes
- Common sensitive files stored in containers
- Idenfity other containers on same network
- Port scan other container and the host machine
- Find exposed docker sock

## Exploits

- Docker Group Privledge Escaltion
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
./deepce.sh 
```

# Contributing

I welcome pull requests, issues and feedback.

- Fork it
- Create your feature branch (git checkout -b my-new-feature)
- Commit your changes (git commit -am 'Added some feature')
- Push to the branch (git push origin my-new-feature)
- Create new Pull Request


