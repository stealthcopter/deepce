# Add metasploit user
sudo useradd -m metasploit
echo metasploit:metasploit| sudo chpasswd

# Install metasploit
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
  chmod 755 msfinstall && \
  sudo ./msfinstall

# TODO Download stealthcopter's metasploit modules (as they're not merged in yet)
