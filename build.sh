#!/bin/zsh
export GOPATH=$PWD/../../../../
export INJECT_PARAMS="-X main.Version=$(git describe --tags) -X main.RevInfo=$(git rev-parse --short HEAD) -X main.BuildTime=$(date +'%Y-%m-%d_%H:%M:%S_%z')"

echo "Building proxy-client"
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $INJECT_PARAMS -a -o ./bin/redfrog-client  main/main.go

echo "Building proxy-server"
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $INJECT_PARAMS -a -o ./bin/redfrog-server ./proxy_server/server.go

echo "Building test"
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a -o ./bin/test ./test/test.go

echo "Building proxy-client-arm64"
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags $INJECT_PARAMS -a -o ./bin/redfrog-client-arm64 ./main/main.go

