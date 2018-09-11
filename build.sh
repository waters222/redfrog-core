#!/usr/bin/env bash
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a  -o ./bin/redfrog-server ./proxy_server/server.go
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a  -o ./bin/redfrog-client ./main/main.go