#!/bin/bash
vagrant ssh client -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/bin/debug-remote-test -m client -addr 1.2.3.4:1234 --timeout 5 -msg "hi there"'