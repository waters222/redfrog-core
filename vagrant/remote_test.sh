#!/bin/bash
cd /home/vagrant/map/src/github.com/weishi258/redfrog-core
export GOPATH=/home/vagrant/map
/usr/bin/go build -gcflags "all=-N -l" -o ./bin/debug-remote-test github.com/weishi258/redfrog-core/test
echo "Build Test Finished"
sudo setcap 'cap_net_admin+ep' ./bin/debug-remote-test
sudo /home/vagrant/go/bin/dlv --listen=:40000 --headless  --api-version=2 exec ./bin/debug-remote-test -- -l debug -m server -addr 127.0.0.1:9090
echo "Debugger Test Started"
