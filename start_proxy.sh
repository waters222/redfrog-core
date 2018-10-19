#!/bin/bash
nohup /home/rock64/redfrog/redfrog-client -c /home/rock64/redfrog/prod-config.yaml > /home/rock64/redfrog/output.log &
PID=$!
echo $PID > /home/rock64/redfrog/redfrog.pid