#!/bin/bash
sudo apt-get update
sudo apt-get install traceroute -y
sudo apt-get install golang -y
sudo apt-get install go-dep -y
export GOPATH=$HOME/go
git clone https://github.com/derekparker/delve.git $GOPATH/src/github.com/derekparker/delve
cd $GOPATH/src/github.com/derekparker/delve
make install
