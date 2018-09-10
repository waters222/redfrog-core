#!/bin/bash
vagrant ssh client -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/bin/debug-remote-test -m client -addr 10.0.0.51:9191 --timeout 20 -msg "hi there"'