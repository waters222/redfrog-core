#!/bin/bash
cd /home/vagrant/map/src/github.com/weishi258/redfrog-core
export GOPATH=/home/vagrant/map
/usr/bin/go build -gcflags "all=-N -l" -o ./bin/debug-proxy-client github.com/weishi258/redfrog-core/main
echo "Build Proxy Finished"
#sudo setcap 'cap_net_admin=+ep' ./bin/debug-remote-test
sudo /home/vagrant/go/bin/dlv --listen=:40000 --headless  --api-version=2 exec ./bin/debug-proxy-client -- -l debug -c prod-config.yaml
echo "Debugger Proxy Started"
