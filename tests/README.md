# Testing deepce.sh
All the scripts in this folder should work as standalone tests that can be run to demonstrate `deepce.sh` in a range of situations. The `run-all.sh` script can be used to run all tests found in this folder. 

# Setting Up Container Platforms
If you're not familiar with using a container platform this guide will help you setup your first container and test it with `deepce.sh`

## Docker 

Install docker following the relevant platform instructions
- [Linux](https://docs.docker.com/engine/install/) - Click into Linux flavour for full guide
- [Mac](https://docs.docker.com/docker-for-mac/install/) 
- [Windows](https://docs.docker.com/docker-for-windows/install/) 

Test docker is available to the current user
```bash
docker --version
```

Create a run your first container
```bash
docker run hello-world
```

### Running Provided Tests
Now you have docker working you can run one of the provided scripts to test `deepce.sh` such as running the following to test a privileged alpine container (It's possible to escape a privileged container and execute commands on the host machine) 

```bash
cd tests
./docker-alpine-privileged.sh
```

### Manually Testing
This will show you how to create a container and then copy deepce.sh into it and execute. Note there are many different ways to do this. 

```bash
# Create and run an alpine container
docker run --rm -it --name deepce_test_container --privileged alpine /bin/bash
# Install the nano text editor
apk add nano
# Use nano to create a text file and paste the contents of deepce.sh into it 
nano deepce.sh
# Make the script executable
chmod +x ./deepce.sh
# Run deepce.sh
./deepce.sh
```


## LXC
LXC is only available on Linux and it can be installed via a package manager as follows: 

```bash
sudo apt-get install lxc
```

TODO: Describe setup & first container instructions


# Wrapper Scripts

If Docker or LXC is already installed on the system, you can use the wrapper scripts `docker-wrapper.sh` or `lxc-wrapper.sh` to automatically run `deepce.sh` on every container it can find on the system.