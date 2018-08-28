#!/bin/bash
cd /home/vagrant/map/src/github.com/weishi258/redfrog-core
export GOPATH=/home/vagrant/map
/usr/bin/go build -gcflags "all=-N -l" -o ./bin/debug-redfrog-core github.com/weishi258/redfrog-core/main
echo "Build Finished"
/home/vagrant/go/bin/dlv --listen=:40000 --headless  --api-version=2 exec ./bin/debug-redfrog-core -- -l debug -c ~/map/src/github.com/weishi258/redfrog-core/sample-config.yaml
echo "Debugger Started"

