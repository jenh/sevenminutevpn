#!/bin/bash

# 7 minute VPN and Web server: Installs OpenVPN & Apache on Ubuntu-based
# systems. Tested on Lightsail; be sure to open ports: UDP 1194 & TCP 443.
# Client configuration files (ovpn, ONC, p12) placed at https://IP/downloads
# (self-signed cert); username is vpn, password is dropped in ubuntu user's home
# directory (.web). Usage: cd sevenminutevpn && sudo ./ubuntu-vpn.sh or
# paste launchscript.sh into your EC2 user-data/Lightsail launch script
# window.



# Set paths and other global variables
export STARTDIR=`pwd`
echo $STARTDIR
# Get the logged-in unprivileged user. On Ec2, this will be "ubuntu", but we
# want this to work for anyone

export logname=`logname`

export openvpn_rel="2.3"
# Get distro codename
source /etc/lsb-release

# Set log file
LOG=/tmp/.build-vpn.log`date +%s`

exec > >(tee -a $LOG) 2>&1

if [ "$EUID" -ne 0 ]
  then echo "Script must be run as root. Usage: sudo ./build-vpn.sh"
  exit
fi

export MYIP=`curl checkip.amazonaws.com`
echo "Using $MYIP as hostname."

export HOSTNAME=`hostname`
# Put Hostname in /etc/hosts; if you don't do this, weirdness like sudo timeouts
# can occur
sudo printf "127.0.0.1 $HOSTNAME\n$(cat /etc/hosts)\n" > /etc/hosts


printf "************************************************************\n"
printf "* Starting install. Output and errors logged to            *\n"
printf "* /tmp/$LOG.                                               *\n"
printf "************************************************************\n"
printf "\n\n"
printf "*******************\n"
printf "* Updating system *\n"
printf "*******************\n"
printf "\n\n"

sudo apt-get update -y
sudo apt-get upgrade -y

printf "**********************\n"
printf "* Installing OpenVPN *\n"
printf "**********************\n"
printf "\n\n"

wget -O - https://swupdate.openvpn.net/repos/repo-public.gpg|sudo apt-key add -

sudo bash -c "echo "deb http://build.openvpn.net/debian/openvpn/release/$openvpn_rel $DISTRIB_CODENAME main" > /etc/apt/sources.list.d/openvpn-aptrepo.list"

# Could install easy-rsa here as well, but easy-rsa3 from github is fuller/easier

sudo apt-get -y install openvpn

printf "*************************************\n"
printf "* Installing git & cloning easy-rsa *\n"
printf "*************************************\n"
printf "\n\n"

sudo apt-get -y install git
git clone https://github.com/OpenVPN/easy-rsa.git
# Copy easy-rsa over & delete it from local
sudo cp -r easy-rsa/easyrsa3 /etc/openvpn/easy-rsa
rm -r $STARTDIR/easy-rsa

# Move vars, find public IP and put it in there, set easy-rsa home directory
sudo cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars

printf "********************************\n"
printf "* Setting server name to $myip *\n"
printf "********************************\n"
printf "\n\n"

sudo sed -i 's/$PWD/\/etc\/openvpn\/easy-rsa/g' /etc/openvpn/easy-rsa/vars
sudo sed -i "s/^#set_var EASYRSA\t/set_var\t EASYRSA\t/g" /etc/openvpn/easy-rsa/vars
sudo sed -i "s/ChangeMe/$MYIP/g" /etc/openvpn/easy-rsa/vars
sudo sed -i "s/^#set_var\ EASYRSA_REQ_CN/set_var\ EASYRSA_REQ_CN/g" /etc/openvpn/easy-rsa/vars

printf "***************************************\n"
printf "* Building CA and generating certs... *\n"
printf "***************************************\n"
printf "\n\n"

sudo /etc/openvpn/easy-rsa/easyrsa init-pki
sudo /etc/openvpn/easy-rsa/easyrsa --batch build-ca nopass
sudo /etc/openvpn/easy-rsa/easyrsa build-server-full server nopass
sudo /etc/openvpn/easy-rsa/easyrsa gen-dh
sudo /etc/openvpn/easy-rsa/easyrsa build-client-full client nopass
sudo /usr/sbin/openvpn --genkey --secret /etc/openvpn/easy-rsa/ta.key

# Oh so ugly; PAM auth is disabled, disable and adduser nologin if you want to use it
# From a known good server.conf, you can get generate your own using:
# awk  '!/^;|^#|^\s*$/' server.conf |awk '{printf "%s\\n",$0}' |sed 's/"/\\"/g'

printf "**********************************\n"
printf "* Building base server.conf file *\n"
printf "**********************************\n"
printf "\n\n"

sudo printf "port 1194\nproto udp\ndev tun\nca /etc/openvpn/easy-rsa/pki/ca.crt\nkey /etc/openvpn/easy-rsa/pki/private/server.key\ncert /etc/openvpn/easy-rsa/pki/issued/server.crt\ndh /etc/openvpn/easy-rsa/pki/dh.pem\nserver 10.8.0.0 255.255.255.0\nifconfig-pool-persist ipp.txt\npush \"redirect-gateway def1 bypass-dhcp\"\npush \"dhcp-option DNS 10.8.0.1\"\npush \"dhcp-option DNS 208.67.222.222\"\npush \"dhcp-option DNS 208.67.220.220\"\nduplicate-cn\nkeepalive 10 60\ntls-version-min 1.2 #Note: Disable if you support Chromebooks\ntls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA\ncipher AES-256-CBC\ntls-auth /etc/openvpn/easy-rsa/ta.key 0\ncomp-lzo\nuser nobody\ngroup nogroup\npersist-key\npersist-tun\nstatus openvpn-status.log\nlog /var/log/openvpn.log\nverb 3\nauth SHA256\nserver-ipv6 2001:db8:0:123::/64\ntun-ipv6\npush tun-ipv6\nifconfig-ipv6 2001:db8:0:123::1 2001:db8:0:123::2\npush \"route-ipv6 2001:db8:0:abc::/64\"\npush \"route-ipv6 2000::/3\"\nproto udp6\n#plugin /usr/lib64/openvpn/plugin/lib/openvpn-auth-pam.so login" >> /etc/openvpn/server.conf

# Set up NAT
printf "**********************\n"
printf "* Setting up routing *\n"
printf "**********************\n"
printf "\n\n"

# The linebreak after the cat is essential or you get iptables unknown command errors.
printf "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE\nCOMMIT\n$(cat /etc/ufw/before.rules)\n" > /etc/ufw/before.rules


sed -i 's/DEFAULT_FORWARD_POLICY=\"DROP\"/DEFAULT_FORWARD_POLICY=\"ACCEPT\"/g' /etc/default/ufw
sudo ufw allow 1194/udp
sudo ufw allow 22/tcp
sudo ufw allow 443/tcp
sudo ufw allow from any port 68 to any port 67 proto udp
sudo ufw disable
sudo ufw --force enable

# Enable IP forwarding
sudo sed -i "s/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g" /etc/sysctl.conf
sudo sysctl -p

printf "******************************\n"
printf "* Installing Apache HTTP 2.4 *\n"
printf "******************************\n"
printf "\n\n"
sudo apt-get -y install apache2

# ssl for https, headers to allow ovpn-specific download behavior, auth_digest
# for password-protected config directory
sudo a2enmod ssl headers auth_digest

printf "*******************************\n"
printf "* Installing Self-Signed Cert *\n"
printf "*******************************\n"
printf "\n\n"

sudo mkdir -p /etc/pki/tls/certs
sudo mkdir -p /etc/pki/tls/private
sudo openssl req -new -newkey rsa:4096 -sha256 -days 365 -nodes -x509 -keyout /etc/pki/tls/private/localhost.key -out /etc/pki/tls/certs/localhost.crt -subj "/CN=$MYIP/"

printf "****************************************************************\n"
printf "* Updating Apache config. Adding server name and virtual host. *\n"
printf "* Disabling server sig, module advertisement, setting noindex  *\n"
printf "* for robots. Redirect all http connections to https. Add ovpn *\n"
printf "* mimetype logic for mobile device downloads.                  *\n"
printf "****************************************************************\n"
printf "\n\n"

sudo sed -i "s/#ServerName www.example.com/ServerName $MYIP/g" /etc/apache2/sites-enabled/000-default.conf

sudo printf "\n<VirtualHost *:80>\nServerName $MYIP\nRedirect / https://$MYIP/\n</VirtualHost>\n<VirtualHost *:443>\nServerName $MYIP\nSSLEngine on\nSSLCertificateFile /etc/pki/tls/certs/localhost.crt\n
SSLCertificateKeyFile /etc/pki/tls/private/localhost.key\n</VirtualHost>\n\nServerSignature Off\nServerTokens Prod\n\n<IfModule headers_module>\n<FilesMatch \".ovpn$\">\nHeader Set Content-type application/x-openvpn-profile\n</FilesMatch>\n</IfModule>" >> /etc/apache2/sites-enabled/000-default.conf

printf "******************************************************************\n"
printf "* Generating client config download directory at host/downloads. *\n"
printf "* Creating password & copying to .web in ec2-user home.          *\n"
printf "******************************************************************\n"
printf "\n\n"
sudo mkdir /var/www/html/downloads && sudo chown www-data:www-data /var/www/html/downloads

# Generate a password for the client config directory, place it in ~/ so that user can find it on login.
# Username is vpn.

rand_pw=`< /dev/urandom tr -dc '_A-Z-a-z-0-9@><^&*()[]+?' | head -c9`; echo $rand_pw >> /home/$logname/.web; htdigest_hash=`printf vpn:vpnweb:$rand_pw | md5sum -`; echo "vpn:vpnweb:${htdigest_hash:0:32}" >> /home/$logname/.tmp

sudo mv /home/$logname/.tmp /etc/apache2/.digestauth
sudo chown www-data:www-data /etc/apache2/.digestauth

sudo chown $logname /home/$logname/.web

sudo printf "\n<Directory \"/var/www/html/downloads\">\nAuthType Digest\nAuthName \"vpnweb\"\nAuthUserFile /etc/apache2/.digestauth\nRequire valid-user\n</Directory>" >> /etc/apache2/sites-enabled/000-default.conf

printf "*******************\n"
printf "* Starting Apache *\n"
printf "*******************\n"
printf "\n\n"

sudo apachectl restart

printf "********************************************\n"
printf "* Building client configs and placing them *\n"
printf "* at https://$MYIP/downloads.       *\n"
printf "********************************************\n"
printf "\n\n"

# Pull git repository...might be overkill if running from EC2/Lightsail, but
# allows everything to work if not using EC2. If it's already there, it's a no-op

cd /tmp && git clone https://github.com/jenh/sevenminutevpn.git

# Ubuntu does not have python already?

sudo apt-get install python -y
cd /tmp/sevenminutevpn/mkcliconf && sudo python mkcliconf.py

# Move configs to download directory
sudo mv $STARTDIR/sevenminutevpn/mkcliconf/$MYIP.* /var/www/html/downloads/
sudo chown www-data:www-data /var/www/html/downloads/


printf "***************************************\n"
printf "* Installing DNSMasq and configuring  *\n"
printf "* ad-blocking.                        *\n"
printf "***************************************\n"
printf "\n\n"

cd /tmp && wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
sudo mv -f /tmp/hosts /etc/hosts
# Ham-handed, but...
sudo sed -i "s/127.0.0.1 localhost.localdomain/127.0.0.1 localhost.localdomain\n127.0.0.1 $HOSTNAME/g" /etc/hosts
sudo printf "127.0.0.1 $HOSTNAME\n$(cat /etc/hosts)" > /etc/hosts
sudo apt-get install dnsmasq -y
sudo service dnsmasq start

printf "********************\n"
printf "* Starting OpenVPN *\n"
printf "********************\n"
printf "\n\n"

sudo systemctl enable openvpn
sudo service openvpn start

printf "*****************************************************************\n"
printf "* ALL DONE! Open up ports 443/TCP and 1194/UDP. Navigate to     *\n"
printf "* https://$myip/downloads, log in using vpn and the      *\n"
printf "* password in /home/[user]/.web and download your client        *\n"
printf "*  configuration file (files if using Chromebook).              *\n"
printf "*****************************************************************\n"
printf "\n\n\n\n"
