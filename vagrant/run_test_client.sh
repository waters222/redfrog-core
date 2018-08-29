#!/bin/bash
vagrant ssh -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/bin/debug-remote-test -m client -addr 192.168.1.1:1234 --timeout 5 -msg "hi there"'