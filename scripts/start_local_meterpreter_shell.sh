#!/bin/bash

echo "Stopping any previous shells"
killall bind4444.bin

echo "Starting a bind shell on the local machine on port 4444"
/home/metasploit/bind4444.bin & 
pid=$!

echo -e "\nChecking process is running:"
ps -aux | grep bind4444 | grep -v "grep"

echo -e "\nTo stop this shell please execute:"
echo "kill $pid"
