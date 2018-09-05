#!/bin/bash
vagrant ssh client -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/bin/debug-remote-test -m client -addr 10.0.0.51:9090 --timeout 60 -msg "hi there"'