#!/bin/sh
cd /app
#COUNTER=0
PORT=9191
#while [ $COUNTER -lt 1 ];do
#
#    let PORT=PORT+1
#    let COUNTER=COUNTER+1
#done
./test -m server -addr :$PORT
#tail -f output.log
