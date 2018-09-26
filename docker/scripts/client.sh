#!/bin/sh
ip route del default
ip route add default via 192.168.0.2

tail -f /dev/null