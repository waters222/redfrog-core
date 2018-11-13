#!/bin/sh
cd /app
./batchTest -d /app/dns.txt -m dns -time 60 -r 2 -port 9191 -portRange 100 -dnsCount 50