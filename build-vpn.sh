#!/bin/bash

# 7 minute VPN and Web server: Installs OpenVPN & Apache on CentOS-based
# systems. Tested on Lightsail; be sure to open ports: UDP 1194 & TCP 443.
# Client configuration files (ovpn, ONC, p12) placed at https://IP/downloads
# (self-signed cert); username is vpn, password is dropped in ec2-user's home
# directory (.web). Usage: cd sevenminutevpn && sudo ./build-vpn.sh or
# paste launchscript.sh into your EC2 user-data/Lightsail launch script
# window.


# Set path
export STARTDIR=`pwd`
echo $STARTDIR

# Set log file
LOG=/tmp/.build-vpn.log`date +%s`

exec > >(tee -a $LOG) 2>&1

if [ "$EUID" -ne 0 ]
  then echo "Script must be run as root. Usage: sudo ./build-vpn.sh"
  exit
fi

export logname=`logname`

# If we're running from the command line, figure out logged-in user for .web
# file. If we're running from user-data on ec2, logname doesn't work, so we'll
# use ec2-user, ec2's default Amazon AMI user.

if [ -z $logname ];
then
  export logname="ec2-user"
  echo Will place download password at /home/$logname/.web
fi

printf "************************************************************\n"
printf "* Starting install. Output and errors logged to            *\n"
printf "* /tmp/$LOG.                                               *\n"
printf "************************************************************\n"
printf "\n\n"
printf "*******************\n"
printf "* Updating system *\n"
printf "*******************\n"
printf "\n\n"

sudo yum -y update

printf "**********************\n"
printf "* Installing OpenVPN *\n"
printf "**********************\n"
printf "\n\n"
# Fix CVE-2017-7479, no longer taking Amazon's base install
# Build rpm from 2.3.17 source

sudo yum -y install gcc rpm-build openssl-devel lzo-devel pam-devel git

cd $STARTDIR && wget https://swupdate.openvpn.org/community/releases/openvpn-2.3.17.tar.gz

cd $STARTDIR && rpmbuild -tb openvpn-2.3.17.tar.gz
sudo rpm -ivh ~/rpmbuild/RPMS/x86_64/openvpn-2.3.17-1.x86_64.rpm

printf "*****************************\n"
printf "* Adding OpenVPN to startup *\n"
printf "*****************************\n"
printf "\n\n"

sudo chkconfig openvpn on

printf "*************************************\n"
printf "* Installing git & cloning easy-rsa *\n"
printf "*************************************\n"
printf "\n\n"

sudo yum -y install git
git clone https://github.com/OpenVPN/easy-rsa.git

# Copy easy-rsa over & delete it from local
sudo cp -r easy-rsa/easyrsa3 /etc/openvpn/easy-rsa
rm -r $STARTDIR/easy-rsa

# Move vars, find public IP and put it in there, set easy-rsa home directory
sudo cp /etc/openvpn/easy-rsa/vars.example /etc/openvpn/easy-rsa/vars
myip=$(curl checkip.amazonaws.com)

printf "********************************\n"
printf "* Setting server name to $myip *\n"
printf "********************************\n"
printf "\n\n"

sudo sed -i 's/$PWD/\/etc\/openvpn\/easy-rsa/g' /etc/openvpn/easy-rsa/vars
sudo sed -i "s/^#set_var EASYRSA\t/set_var\t EASYRSA\t/g" /etc/openvpn/easy-rsa/vars
sudo sed -i "s/ChangeMe/$myip/g" /etc/openvpn/easy-rsa/vars
sudo sed -i "s/^#set_var\ EASYRSA_REQ_CN/set_var\ EASYRSA_REQ_CN/g" /etc/openvpn/easy-rsa/vars
sudo sed -i "s/^#set_var\ EASYRSA_PKI/set_var\ EASYRSA_PKI/g" /etc/openvpn/easy-rsa/vars

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
# From a good server.conf, you can get this from:
# awk  '!/^;|^#|^\s*$/' server.conf |awk '{printf "%s\\n",$0}' |sed 's/"/\\"/g'

printf "**********************************\n"
printf "* Building base server.conf file *\n"
printf "**********************************\n"
printf "\n\n"


sudo printf "port 1194\nproto udp\ndev tun\nca /etc/openvpn/easy-rsa/pki/ca.crt\nkey /etc/openvpn/easy-rsa/pki/private/server.key\ncert /etc/openvpn/easy-rsa/pki/issued/server.crt\ndh /etc/openvpn/easy-rsa/pki/dh.pem\nserver 10.8.0.0 255.255.255.0\nifconfig-pool-persist ipp.txt\npush \"redirect-gateway def1 bypass-dhcp\"\npush \"dhcp-option DNS 10.8.0.1\"\npush \"dhcp-option DNS 208.67.222.222\"\npush \"dhcp-option DNS 208.67.220.220\"\nduplicate-cn\nkeepalive 10 60\ntls-version-min 1.2 #Note: Disable if you support Chromebooks\ntls-cipher TLS-DHE-RSA-WITH-AES-256-GCM-SHA384:TLS-DHE-RSA-WITH-AES-256-CBC-SHA\ncipher AES-256-CBC\ntls-auth /etc/openvpn/easy-rsa/ta.key 0\ncomp-lzo\nuser nobody\ngroup nobody\npersist-key\npersist-tun\nstatus openvpn-status.log\nlog /var/log/openvpn.log\nverb 3\nauth SHA256\nserver-ipv6 2001:db8:0:123::/64\ntun-ipv6\npush tun-ipv6\nifconfig-ipv6 2001:db8:0:123::1 2001:db8:0:123::2\npush \"route-ipv6 2001:db8:0:abc::/64\"\npush \"route-ipv6 2000::/3\"\nproto udp6\n#plugin /usr/lib64/openvpn/plugin/lib/openvpn-auth-pam.so login" >> /etc/openvpn/server.conf

# Set up NAT
printf "**********************\n"
printf "* Setting up routing *\n"
printf "**********************\n"
printf "\n\n"

sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo service iptables save
sudo service iptables restart

# Enable IP forwarding
sed -i "s/net.ipv4.ip_forward = 0/net.ipv4.ip_forward = 1/g" /etc/sysctl.conf
sudo sysctl -p

printf "********************\n"
printf "* Starting OpenVPN *\n"
printf "********************\n"
printf "\n\n"

sudo service openvpn start
printf "******************************\n"
printf "* Installing Apache HTTP 2.4 *\n"
printf "******************************\n"
printf "\n\n"

sudo yum -y install httpd
sudo chkconfig httpd on
sudo yum -y install mod_ssl

printf "*******************************\n"
printf "* Installing Self-Signed Cert *\n"
printf "*******************************\n"
printf "\n\n"

sudo openssl req -new -newkey rsa:4096 -sha256 -days 365 -nodes -x509 -keyout /etc/pki/tls/private/localhost.key -out /etc/pki/tls/certs/localhost.crt -subj "/CN=$myip/"

printf "****************************************************************\n"
printf "* Updating Apache config. Adding server name and virtual host. *\n"
printf "* Disabling server sig, module advertisement, setting noindex  *\n"
printf "* for robots. Redirect all http connections to https. Add ovpn *\n"
printf "* mimetype logic for mobile device downloads.                  *\n"
printf "****************************************************************\n"
printf "\n\n"

sudo sed -i "s/#ServerName www.example.com:80/ServerName $myip/g" /etc/httpd/conf/httpd.conf

sudo printf "\n<VirtualHost *:80>\nServerName $myip\nRedirect / https://$myip/\n</VirtualHost>\n<VirtualHost *:443>\nServerName $myip\nSSLCertificateFile /etc/pki/tls/certs/localhost.crt\nSSLCertificateKeyFile /etc/pki/tls/private/localhost.key\n</VirtualHost>\n\nServerSignature Off\nServerTokens Prod\nHeader set X-Robots-Tag \"noindex\"\n\n<IfModule headers_module>\n<FilesMatch \".ovpn$\">\nHeader Set Content-type application/x-openvpn-profile\n</FilesMatch>\n</IfModule>" >> /etc/httpd/conf/httpd.conf

printf "******************************************************************\n"
printf "* Generating client config download directory at host/downloads. *\n"
printf "* Creating password & copying to .web in ec2-user home.          *\n"
printf "******************************************************************\n"
printf "\n\n"

sudo mkdir /var/www/html/downloads && sudo chown apache:apache /var/www/html/downloads

# Generate a password for the client config directory, place it in ~/ so that user can find it on login.
# Username is vpn.

rand_pw=`< /dev/urandom tr -dc '_A-Z-a-z-0-9@><^&*()[]+?' | head -c9`; echo $rand_pw >> /home/$logname/.web; htdigest_hash=`printf vpn:vpnweb:$rand_pw | md5sum -`; echo "vpn:vpnweb:${htdigest_hash:0:32}" >> /tmp/.tmp

sudo mv /tmp/.tmp /etc/httpd/.digestauth
sudo chown apache:apache /etc/httpd/.digestauth

sudo chown $logname:$logname /home/$logname/.web

sudo printf "\n<Directory \"/var/www/html/downloads\">\nAuthType Digest\nAuthName \"vpnweb\"\nAuthUserFile /etc/httpd/.digestauth\nRequire valid-user\n</Directory>" >> /etc/httpd/conf/httpd.conf


printf "*******************\n"
printf "* Starting Apache *\n"
printf "*******************\n"
printf "\n\n"

sudo service httpd start

printf "********************************************\n"
printf "* Building client configs and placing them *\n"
printf "* at https://$myip/downloads.       *\n"
printf "********************************************\n"
printf "\n\n"

cd /tmp && git clone https://github.com/jenh/sevenminutevpn.git
cd /tmp/sevenminutevpn/mkcliconf && sudo python mkcliconf.py

# Move configs to download directory
sudo mv /tmp/sevenminutevpn/mkcliconf/$myip.* /var/www/html/downloads/
sudo chown apache:apache /var/www/html/downloads/


printf "***************************************\n"
printf "* Installing DNSMasq and configuring  *\n"
printf "* ad-blocking.                        *\n"
printf "***************************************\n"
printf "\n\n"

cd /tmp && wget https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
sudo mv -f /tmp/hosts /etc/hosts
sudo yum -y install dnsmasq
sudo service dnsmasq start
sudo chkconfig dnsmasq on

printf "*****************************************************************\n"
printf "* ALL DONE! Open up ports 443/TCP and 1194/UDP. Navigate to     *\n"
printf "* https://$myip/downloads, log in using vpn and the      *\n"
printf "* password in /home/[user]/.web and download your client        *\n"
printf "*  configuration file (files if using Chromebook).              *\n"
printf "*****************************************************************\n"
printf "\n\n\n\n"
