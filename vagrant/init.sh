#!/bin/bash
vagrant ssh gateway -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/vagrant/remote_setup.sh'
vagrant ssh client -c '/home/vagrant/map/src/github.com/weishi258/redfrog-core/vagrant/remote_setup.sh'