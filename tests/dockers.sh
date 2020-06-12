# The following commands show how to create vulnerable docker images that can be exploited using DEEPCE

# RUN IN BACKGROUND 
# These containers will be run interactively by default to make them run in the background 
# replace: `-it` with `-d` and `sh` with `tail -f /dev/null`

# ADD SCRIPT
# to deepce.sh script automatically
# add: -v "/home/mat/Cloud/coursework/Final Year Project/deepce/deepce.sh":/root/deepce.sh
# Note to run it automatically change `sh` to `/root/deepce.sh`

scriptPath=$(dirname "$PWD")/deepce.sh

# Test running on a few different containers
docker run --rm -it --name deepce-busybox -v "$scriptPath":/root/deepce.sh busybox /root/deepce.sh | tee  results/busybox.log
docker run --rm -it --name deepce-alpine -v "$scriptPath":/root/deepce.sh alpine /root/deepce.sh  | tee  results/alpine.log
docker run --rm -it --name deepce-ubuntu -v "$scriptPath":/root/deepce.sh ubuntu /root/deepce.sh  | tee  results/ubuntu.log

# Create a alpine linux container that is vulnerable to CVE-2019-5021
docker run --rm -it --name deepce-alpine-cve alpine:3.5 -v "$scriptPath":/tmp/deepce.sh sh -c "apk add --no-cache linux-pam shadow sudo && sudo -u nobody /tmp/deepce.sh"

# Create a privileged container
docker run --rm -it --name deepce-privileged  -v "$scriptPath":/root/deepce.sh  --privileged alpine /root/deepce.sh  | tee  results/alpine-privileged.log

# Create a container with the docker sock mounted
docker run --rm -it --name deepce-sock -v /var/run/docker.sock:/var/run/docker.sock alpine /root/deepce.sh  | tee  results/alpine-sock.log

# Create a container with passwords/secrets in environmnet variables
docker run --rm -it --name deepce-secrets -e MYSQL_PASSWORD=S00perS3rect -v "$scriptPath":/root/deepce.sh alpine /root/deepce.sh  | tee  results/alpine-env-var.log 


