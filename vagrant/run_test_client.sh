#!/bin/bash
vagrant ssh client -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/bin/debug-remote-test -m client -addr 10.10.1.103:9191 --timeout 20 -msg "hi there"'