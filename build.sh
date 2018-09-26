#!/usr/bin/env bash
export GOPATH=$PWD/../../../../
echo "Building proxy-client"
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a  -o ./bin/redfrog-server ./proxy_server/server.go
echo "Building proxy-server"
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a  -o ./bin/redfrog-client ./main/main.go
echo "Building proxy-client-arm64"
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a  -o ./bin/redfrog-client-arm64 ./main/main.go

echo "Building test"
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -a  -o ./bin/test ./test/test.go


