# Paste this into the launch script box on Lightsail
#install git
sudo yum -y install git
#clone
git clone https://github.com/jenh/sevenminutevpn.git /tmp/sevenminutevpn
# Use /tmp
cd /tmp/sevenminutevpn && sudo ./build-vpn.sh
