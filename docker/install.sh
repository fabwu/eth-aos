#!/bin/bash

# install dependencies for puppet
apt-get update && apt-get upgrade -y 
DEBIAN_FRONTEND=noninteractive apt-get install -y wget apt-utils 

# install puppet
wget -q https://apt.puppetlabs.com/puppet6-release-bionic.deb \
           -O puppetlabs-release-repo.deb 

# install and delete deb file
dpkg -i puppetlabs-release-repo.deb 
rm -rf puppetlabs-release-repo.deb 

# install puppet agent
apt-get update 
DEBIAN_FRONTEND=noninteractive apt-get install -y puppet-agent


# run module install on the puppet script
/opt/puppetlabs/bin/puppet module install \
        --target-dir=/opt/puppetlabs/puppet/modules \
        --modulepath /etc/puppetlabs/code/modules puppetlabs-vcsrepo

# apply the puppet script etc. 
/opt/puppetlabs/bin/puppet apply --onetime --verbose \
    --no-daemonize --no-usecacheonfailure --no-splay \
    --show_diff /config.pp


# create the tools directory
mkdir -p /home/netos/tools
mkdir /source

# copy eclipse
ln -s /eclipseclp /home/netos/tools/eclipseclp

# clean the apt
apt-get clean
