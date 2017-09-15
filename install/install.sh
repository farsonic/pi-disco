#!/bin/bash


echo "__________.__          ________  .__                     ";
echo "\______   \__|         \______ \ |__| ______ ____  ____  ";
echo " |     ___/  |  ______  |    |  \|  |/  ___// ___\/  _ \ ";
echo " |    |   |  | /_____/  |    \   \  |\___ \\  \__(  <_> )";
echo " |____|   |__|         /_______  /__/____  >\___  >____/ ";
echo "                               \/        \/     \/       ";



#Confirm if user is either root or sudo root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

start=$(date +%s.%N)

echo "\nIn order to use Pi-Disco you need to have an API Key from Fingerbank.inverse.ca" 
echo "Create an account and paste the provided Key below" 
echo "Please enter your FingerBank API key:"
read apikey
#echo $apikey

echo "\nPlease provide IP Address of an SRX Firewall as well as credentials for SSH/Netconf and WebAPI Access" 
echo "Note: SSH Credentials will typically be different from the dedicated WebAPI username/password" 
echo "\nPlease enter your SRX IP Address:"
read SRX_IP
echo "Please enter your SRX Username:"
read SRX_USERNAME
echo "\nPlease enter your SRX Password:"
read SRX_PASSWORD
echo "\nPlease enter the SRX WebAPI Username:"
read WEBAPI_USERNAME
echo "\nPlease enter the SRX WebAPI Password:"
read WEBAPI_PASSWORD
echo "\nPlease provide IP Address of an EX-Series switch as well as credentials for SSH/Netconf" 
echo "Please enter your EX IP Address:"
read EX_IP
echo "\nPlease enter your EX Username:"
read EX_USERNAME
echo "\nPlease enter your EX Password:"
read EX_PASSWORD

# Make project directories 
mkdir /var/tmp/netdisco-installer
mkdir /opt/

#install dependencies 
cd /var/tmp/netdisco-installer/
apt-get update 
apt-get install -y python git wget
wget -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py
rm get-pip.py
pip install junos-eznc netaddr nmap pyrad redis requests scapy ua_parser walrus pyyaml flask nmap



#download code from Github and activate agents 
cd /opt/
rm -r pi-disco
git clone https://github.com/farsonic/pi-disco.git
sed -i "s/FINGERBANKAPI/$apikey/g" /opt/pi-disco/netdisco.conf
sed -i "s/WEBAPI_USERNAME/$WEBAPI_USERNAME/g" /opt/pi-disco/netdisco.conf
sed -i "s/WEBAPI_PASSWORD/$WEBAPI_PASSWORD/g" /opt/pi-disco/netdisco.conf
sed -i "s/SRX_IP/$SRX_IP/g" /opt/pi-disco/netdisco.conf
sed -i "s/SRX_USERNAME/$SRX_USERNAME/g" /opt/pi-disco/netdisco.conf
sed -i "s/SRX_PASSWORD/$SRX_PASSWORD/g" /opt/pi-disco/netdisco.conf
sed -i "s/EX_IP/$EX_IP/g" /opt/pi-disco/netdisco.conf
sed -i "s/EX_USERNAME/$EX_USERNAME/g" /opt/pi-disco/netdisco.conf
sed -i "s/EX_PASSWORD/$EX_PASSWORD/g" /opt/pi-disco/netdisco.conf


cp /opt/pi-disco/init/* /etc/init.d/
chmod 755 /etc/init.d/netdisco*
chown root:root /etc/init.d/netdisco*
update-rc.d netdisco-dhcp defaults
update-rc.d netdisco-dhcp enable
update-rc.d netdisco-ex defaults
update-rc.d netdisco-ex enable
update-rc.d netdisco-ping defaults
update-rc.d netdisco-ping enable
update-rc.d netdisco-radius defaults
update-rc.d netdisco-radius enable
update-rc.d netdisco-srx-syslog defaults
update-rc.d netdisco-srx-syslog enable
update-rc.d netdisco-srx-update defaults
update-rc.d netdisco-srx-update enable
update-rc.d netdisco-useragent defaults
update-rc.d netdisco-useragent enable
update-rc.d netdisco-webserver defaults
update-rc.d netdisco-webserver enable

#Start agents and redis-server
/etc/init.d/netdisco-dhcp start
/etc/init.d/netdisco-ex start
/etc/init.d/netdisco-ping start
/etc/init.d/netdisco-radius start
/etc/init.d/netdisco-srx-syslog start
/etc/init.d/netdisco-srx-update start
/etc/init.d/netdisco-useragent start
/etc/init.d/netdisco-webserver start
/etc/init.d/redis-server start
/usr/bin/redis-server --daemonize yes

#Delete install directory 
#rm -r /var/tmp/netdisco-installer

cp /opt/pi-disco/install/greeting.sh /etc/profile.d/
chmod +x /etc/profile.d/greeting.sh

#How long did this take? Expect a long run time on a Raspberry PI. Original model PI's will possibly not have enough memory. 
end=$(date +%s.%N)    
runtime=$(python -c "print(${end} - ${start})")

echo "Installation runtime was $runtime"
