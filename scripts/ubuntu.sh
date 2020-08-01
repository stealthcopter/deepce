#!/bin/bash

usermod -aG lxd ubuntu
deluser ubuntu sudo
rm -rf /etc/sudoers.d/90-cloud-init-users

ln -s /opt/deepce /home/ubuntu/deepce

# Launch bash so a .bashrc profile is generated
sudo -u ubuntu /bin/bash -c whoami

echo 'export PATH=\"/opt/deepce:$PATH\"' >> /home/metasploit/.bashrc
