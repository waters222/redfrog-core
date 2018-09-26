#!/bin/sh
cd /app
IP_ADDR=$(dig +short test-server)
./test -m client -timeout 10 -addr $IP_ADDR:9191