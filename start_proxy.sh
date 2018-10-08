#!/bin/bash
nohup ./redfrog-client -c prod-config.yaml > output.log &
PID=$!
echo $PID > redfrog.pid