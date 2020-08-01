# Version 0.3

RUN_TESTS = false

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/bionic64"
  
    config.vm.provider :virtualbox do |vbox|
      vbox.gui = false
      vbox.name = "deepce"
    end
  
  config.vm.hostname = "deepce"
  
  config.vm.provision "file", source: "scripts", destination: "/tmp/"
  config.vm.provision :shell, :inline => "cp /tmp/scripts/rc.local /etc/rc.local"
  
  config.vm.provision :shell, :inline => "apt update"
  config.vm.provision :shell, :inline => "apt install -y zip nmap aha"
  
  config.vm.provision :shell, :inline => "echo ubuntu:ubuntu | chpasswd"
  config.vm.provision :shell, :inline => "echo root:rootbeer| chpasswd" # Give them something to crack if they want
  
  config.vm.provision "shell", keep_color: true, name: "docker.sh", path: "scripts/docker.sh"
  config.vm.provision "shell", keep_color: true, name: "metasploit.sh", path: "scripts/metasploit.sh"
  config.vm.provision "shell", keep_color: true, name: "ubuntu.sh", path: "scripts/ubuntu.sh"
  
  # enable ssh
  config.vm.provision :shell, :inline => "sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config && service sshd restart"
  
  # Add deepce
  config.vm.provision :shell, :inline => "git clone https://github.com/stealthcopter/deepce /opt/deepce && chown -R ubuntu:ubuntu /opt/deepce"
  config.vm.provision :shell, :inline => "zip -r /opt/deepce.zip /opt/deepce"
  
  # Add linpeas
  config.vm.provision :shell, :inline => "cd /opt && wget https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/master/linPEAS/linpeas.sh && chmod a+rx /opt/linpeas.sh"
  
  if RUN_TESTS
    # Run all tests so that all docker images are pulled down
    config.vm.provision :shell, :inline => "cd /opt/deepce/tests && ./run-all.sh || echo some tests failed, but lets carry on..."
  end
    
  # Copy files to tmp dir
  config.vm.provision "file", source: "users", destination: "/tmp/users"
  
  # Ubuntu's Files
  config.vm.provision "shell",inline: "chown -R ubuntu:ubuntu /tmp/users/ubuntu && mv /tmp/users/ubuntu/* /home/ubuntu/"
  
  # Metasploits's Files
  config.vm.provision "shell",inline: "chown -R metasploit:metasploit /tmp/users/metasploit && mv /tmp/users/metasploit/* /home/metasploit/"  
  
  # Root's Files
  config.vm.provision "shell",inline: "mv /tmp/users/root/* /root/"
  
  # Clean up
  config.vm.provision :shell, :inline => "rm -rf /tmp/*"
end
