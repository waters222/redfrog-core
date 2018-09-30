#!/bin/sh
cd /app
COUNTER=0
PORT=9191
while [ $COUNTER -lt 1 ];do
    ./test -m server -addr :$PORT >> output.log &
    let PORT=PORT+1
    let COUNTER=COUNTER+1
done
tail -f output.log
