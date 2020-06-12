#
# Puppet configuration file for Barrelfish, Ubuntu 18.04 Version
#

# Config files that have to be available during boot
define config_file_copy($filename = $title, $mode="0600", 
                   $owner="root", $group="root", $repo="/mnt/local/conf") {
  file { "${filename}":
    require => Vcsrepo[$repo],
    ensure => file,
    mode   => $mode,
    owner  => $owner,
    group  => $group,
    source => "${repo}${filename}",
  }
}

# The default for config files: Symlink them into the repo
define config_file($filename = $title, $mode="0600", 
                   $owner="root", $group="root", $repo="/mnt/local/conf",
                   $notify="")
{
  file { "${filename}":
    require => Vcsrepo[$repo],
    ensure => link,
    notify => $notify,
    mode   => $mode,
    owner  => $owner,
    group  => $group,
    target => "${repo}${filename}",
  }
}

define pip_install($package = $title)
{
  exec {"pip-install_${package}":
    require => Package['python-pip'],
    command => "/usr/bin/pip install ${package}",
    unless => "/usr/bin/pip list | grep ${package}",
  }
}

exec { 'dpkg-addarchs' :
  command => '/usr/bin/dpkg --add-architecture arm64',
  require => File['/etc/apt/sources.list'],
}

exec { 'dpkg-addarchs-update' :
  command => '/usr/bin/apt-get update',
  require => Exec['dpkg-addarchs'],
}

exec { 'apt-update':
  command => '/usr/bin/apt-get update',
}

exec { 'mkdir-udev':
  command => '/bin/mkdir -p /etc/udev/rules.d/',
}

class barrelfish_build {
  # Packages for building Barrelfish code
  $barrelfish_build_env = [
    'qemu-system-x86', 'qemu-system-arm', 'qemu-utils',
    'build-essential', 'bison', 'flex', 'cmake', 
    'ghc', 'libghc-src-exts-dev', 'libghc-ghc-paths-dev',
    'libghc-parsec3-dev', 'libghc-random-dev', 'libghc-ghc-mtl-dev',
    'libghc-async-dev', 'gcc-arm-linux-gnueabi', 'g++-arm-linux-gnueabi',
    'libgmp3-dev', 'cabal-install', 'curl', 'freebsd-glue',
    'libelf-freebsd-dev', 'libusb-1.0-0-dev', 'gnu-efi:arm64',
    'libefiboot-dev', 'gcc-aarch64-linux-gnu', 'g++-aarch64-linux-gnu',
    'gdb-multiarch', 'cpio', 'libghc-aeson-pretty-dev', 'libghc-aeson-dev',
    'libghc-missingh-dev', 
    # this package is not yet available ton ubuntu 18.04
    # 'libghc-pretty-simple-dev',
    # For gem5: libpython2.7, google's tcmalloc, protobuf
    'libpython2.7', 'libprotobuf10', 'libtcmalloc-minimal4',
  ]

  # Packages for building Barrelfish tech notes
  $barrelfish_build_docs = [
    'texlive-latex-base', 'texlive-latex-extra', 'texlive-latex-recommended',
    'texlive-bibtex-extra', 'texlive-extra-utils',
    'texlive-fonts-recommended', 'texlive-font-utils',
    'texlive-generic-recommended', 'texlive-generic-extra',
    'texlive-pictures', 'texlive-science', 'graphviz', 'doxygen', 'lhs2tex',
  ]

  # Packages for running Barrelfish harness
  $barrelfish_harness_env = [
    'python-pexpect', 'python-pip' , 'python-junit.xml', 'mtools', 'parted',
    'telnet'
  ]

  package { $barrelfish_build_env:
    require => Exec['dpkg-addarchs-update'],
    ensure => 'installed',
  }

  exec { 'cabal-update':
    require => Package['cabal-install'],
    command => 'cabal update',
    user => 'root',
    path => '/usr/bin',
    environment => [ 'HOME=/root' ],
  }

  exec { 'cabal-install_bytestring-trie':
    require => Exec['cabal-update'],
    command => 'cabal install --global bytestring-trie',
    user => 'root',
    path => '/usr/bin:/bin',
    environment => [ 'HOME=/root' ],
    unless => 'cabal list --installed --simple-output | grep bytestring-trie',
  }

  exec { 'cabal-install_pretty-simple':
    require => Exec['cabal-update'],
    command => 'cabal install --global pretty-simple',
    user => 'root',
    path => '/usr/bin:/bin',
    environment => [ 'HOME=/root' ],
    unless => 'cabal list --installed --simple-output | grep pretty-simple',
  }

  package { $barrelfish_build_docs:
    require => Exec['apt-update'],
    ensure => 'installed',
  }

  package { $barrelfish_harness_env:
    require => Exec['apt-update'],
    ensure => 'installed',
  }
  pip_install { 'GitPython': }

  # Xeon Phi compiler symlinks (needs /home/netos available)
  exec { 'xeon_phi_symlink':
    command => '/home/netos/tools/mpss-3.7.1/setup_mpss.sh',
    onlyif  => '/usr/bin/test -e /home/netos',
    unless  => '/usr/bin/test -e /opt/mpss/3.7.1/sysroots'
  }
}

class util_packages {
  $utils = [
    'vim', 'vim-gnome', 'emacs24-nox', 'screen', 'tmux', 'tree', 'ack-grep',
    'silversearcher-ag', 'tig', 'git', 'imagemagick', 'valgrind',
    'conserver-client', 'htop', 'iotop', 'dc', 'bc', 'cscope', 'aptitude',
    'dnsutils', 'syslinux-utils', 'inetutils-traceroute', 'wget', 'zsh',
    'python-requests',
  ]

  package { 'syslinux':
    ensure => 'purged',
  }

  package { $utils:
    require => Exec['apt-update'],
    ensure => 'installed' 
  }

}

class docker_util_packages {
  $utils = [
    'git', 'conserver-client', 'syslinux-utils',  'wget',
    'python-requests', 'udev'
  ]

  package { 'syslinux':
    ensure => 'purged',
  }

  package { $utils:
    require => Exec['apt-update'],
    ensure => 'installed' 
  }
}



define tool_symlink($filename = $title, $targetdir='/usr/local/bin', $ext='')
{
  file { "${targetdir}/${filename}":
    require => Vcsrepo['/mnt/local/conf'],
    ensure => link,
    owner => "root",
    group => "root",
    target => "/mnt/local/conf/tools/${filename}${ext}",
  }
}

class emmentaler {
  include barrelfish_build
  include util_packages

  exec {'get_harness_key':
    command => '/bin/su harness -c "cat ~/.ssh/id_rsa" > /root/.ssh/harness_id_rsa && chmod 400 /root/.ssh/harness_id_rsa',
  }
  vcsrepo { '/mnt/local/conf':
    require => Exec['get_harness_key'],
    ensure => latest,
    provider => git,
    source => 'ssh://vcs-user@code.systems.ethz.ch:8006/diffusion/EMMENTALERCONFIG/conf.git',
    identity => '/root/.ssh/harness_id_rsa',
  }

  config_file { '/etc/sudoers.d/bfadmin': }
  config_file { '/etc/conserver/console.cf': }
  config_file { '/etc/dhcp/dhclient.conf': }
  config_file { '/etc/apparmor.d/local/sbin.dhclient': }
  config_file { '/etc/apt/sources.list': }

  # For monitoring
  package { 'munin-node':
    require => Exec['apt-update'],
    ensure => 'installed',
  }
  # Setup munin-node symlinks as generated by munin-node-configure
  exec { 'munin-node-configure':
    require => Package['munin-node'],
    command => '/usr/sbin/munin-node-configure --shell | /bin/sh -x'
  }
  # Add munin-node config file
  config_file { '/etc/munin/munin-node.conf': }
}

node 'emmentaler1' {
  include emmentaler

  # Packages for managing Barrelfish racks
  $bf_rack_env = [
    'conserver-server', 'isc-dhcp-server', 'nfs-kernel-server', 'tftpd-hpa',
    'bind9', 'ipmitool'
  ]

  pip_install { 'pysnmp==4.3.9': }

  package { $bf_rack_env:
    require => Exec['apt-update'],
    ensure => 'installed',
  }

  # For building barrelfish website
  package { [ 'jekyll', 'ruby-redcarpet' ]:
    require => Exec['apt-update'],
    ensure => 'installed',
  }

  # to make sure cron picks up changes to crontab, we restart it using a
  # notify relationship:
  # https://www.puppetcookbook.com/posts/restart-a-service-when-a-file-changes.html
  service { 'cron':
    ensure => 'running',
    enable => true,
    require => Package['cron']
  }
  config_file{'/etc/crontab':
    notify => Service['cron']
  }
  config_file{'/etc/exports': }
  config_file{'/etc/default/bind9': }
  config_file{'/etc/default/isc-dhcp-server': }
  config_file{'/etc/dhcp/dhcpd.conf': }
  config_file{'/etc/default/tftpd-hpa': }
  config_file{'/etc/bind/named.conf': }
  config_file{'/etc/conserver/server.conf': }
  config_file{'/etc/conserver/conserver.passwd': }
  config_file{'/etc/network/interfaces': }
  config_file{'/etc/network/interfaces.d/barrelfish-subnet': }

  tool_symlink{'rackpower': ext=>'.py' }

  file { '/mnt/emmentaler1_nfs':
    ensure => link,
    target => '/mnt/local/nfs'
  }
}

node 'emmentaler2' {
  include emmentaler

  # For jenkins-build-per-branch
  package { 'gradle':
    require => Exec['apt-update'],
    ensure => 'installed',
  }
  config_file{'/etc/network/interfaces': }
  config_file{'/etc/network/interfaces.d/eno2-dhcp': }
  file { '/mnt/emmentaler1_nfs': ensure => directory }
  config_file_copy{'/etc/fstab': }
  config_file{'/etc/resolv.conf': }
}

node 'emmentaler3' {
  include emmentaler
  config_file{'/etc/network/interfaces': }
  config_file{'/etc/network/interfaces.d/eno2-dhcp': }
  file { '/mnt/emmentaler1_nfs': ensure => directory }
  config_file_copy{'/etc/fstab': }
  config_file{'/etc/resolv.conf': }
}


node 'default' {
  file { "/etc/apt/sources.list":
    ensure => file,
    mode   => "0644",
    owner  => "root",
    group  => "root",
    source => "/sources.list",
  }  
  include barrelfish_build
  include docker_util_packages
}
