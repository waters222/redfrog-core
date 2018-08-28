#!/bin/bash
sudo apt-get update
sudo apt-get install traceroute -y
sudo apt-get install golang -y
sudo apt-get install go-dep -y
/usr/bin/go get -u github.com/derekparker/delve/cmd/dlv
