#!/bin/bash

# Add metasploit user
sudo useradd -m metasploit
echo metasploit:metasploit| sudo chpasswd
sudo usermod -aG docker metasploit
sudo usermod -aG lxd metasploit

# Download alpine image
cd /tmp
wget https://raw.githubusercontent.com/saghul/lxd-alpine-builder/master/build-alpine
bash ./build-alpine
rm ./build-alpine
lxc image import ./*.tar.gz --alias alpine && lxd init --auto
rm ./*.tar.gz

# Install metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  sudo ./msfinstall

# Download stealthcopter's metasploit modules (as they're not merged in yet)
mkdir -p /home/metasploit/.msf4/modules/post/linux/gather
mkdir -p /home/metasploit/.msf4/modules/exploits/linux/local

cd /home/metasploit/.msf4/modules/post/linux/gather

# Enum containers
wget https://raw.githubusercontent.com/stealthcopter/metasploit-framework/feat/mod/enum_containers/modules/post/linux/gather/enum_containers.rb

cd /home/metasploit/.msf4/modules/exploits/linux/local
# Docker privildged container escape
wget https://raw.githubusercontent.com/stealthcopter/metasploit-framework/feat/mod/docker_privileged_container_escape/modules/exploits/linux/local/docker_privileged_container_escape.rb

# LXC priv escape
wget https://raw.githubusercontent.com/stealthcopter/metasploit-framework/feat/mod/lxc_priv_esc/modules/exploits/linux/local/lxc_privilege_escalation.rb

# Add a flag for loading metasploit
echo -e "deepce{m3t4p0d_u53d_h4rd3n}\npost/linux/gather/enum_containers\nexploits/linux/local/docker_privileged_container_escape\nexploits/linux/local/lxc_privilege_escalation" > /home/metasploit/.msf4/deepce.txt

# Launch bash so a .bashrc profile is generated
sudo -u metaspliot /bin/bash -c whoami

echo 'export MSFLOGO=~/.msf4/deepce.txt' >> /home/metasploit/.bashrc
echo 'export PATH=\"/opt/deepce:$PATH\"' >> /home/metasploit/.bashrc

# Copy in useful scripts
cp /tmp/scripts/start_local_meterpreter_shell.sh /home/metasploit/
cp /tmp/scripts/start_vulnerable_docker.sh /home/metasploit/

chown -R metasploit:metasploit /home/metasploit/.msf4/
sudo -u metasploit 'echo -e "yes\n\n\n"|msfdb init'

# Generate some meterpreter shells
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=4444 -f elf -o /home/metasploit/bind4444.bin
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=5555 -f elf -o /home/metasploit/bind5555.bin
msfvenom -p linux/x64/meterpreter/bind_tcp LPORT=6666 -f elf -o /home/metasploit/bind6666.bin
chmod a+rx /home/metasploit/bind*

chown -R metasploit:metasploit /home/metasploit/

# Disallow other user using metasploit
chown -R root:metasploit /opt/metasploit-framework/bin/*
chmod -R 750 /opt/metasploit-framework/bin/*

chmod +x /home/metasploit/*.sh
