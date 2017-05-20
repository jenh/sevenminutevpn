#!/bin/bash

# Paste this into the launch script box on Lightsail to automatically install
# and deploy VPN and config files. See README.md for step-by-step connection
# and configuration file download instructions.

source /etc/os-release

if [ "${ID_LIKE}" = "rhel fedora" ]; then
 echo Detected RHELish OS, using yum to install
 sudo yum -y install git;
elif [ "${ID_LIKE}" = "debian" ]; then
 echo Detected Debianesque OS, using apt to install
 sudo apt-get -y install git;
else
 echo "Don't detect RHEL or Debian. Skipping."
fi

git clone https://github.com/jenh/sevenminutevpn.git /tmp/sevenminutevpn

if [ "${ID_LIKE}" = "debian" ]; then
  cd /tmp/sevenminutevpn && sudo ./ubuntu-vpn.sh
else
  cd /tmp/sevenminutevpn && sudo ./build-vpn.sh
fi
