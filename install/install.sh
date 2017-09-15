#!/bin/bash


printf "Install script v1.0 15/09/2017"



#Confirm if user is either root or sudo root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

start=$(date +%s.%N)

echo -e "\nIn order to use Pi-Disco you need to have an API Key from Fingerbank.inverse.ca" 
echo -e  "Create an account and paste the provided Key below" 
echo -e "Please enter your FingerBank API key:"
read apikey
#echo $apikey

echo -e "\nPlease provide IP Address of an SRX Firewall as well as credentials for SSH/Netconf and WebAPI Access" 
echo -e "Note: SSH Credentials will typically be different from the dedicated WebAPI username/password" 
echo -e "\nPlease enter your SRX IP Address:"
read SRX_IP
echo -e "Please enter your SRX Username:"
read SRX_USERNAME
echo -e "Please enter your SRX Password:"
read -s SRX_PASSWORD
echo -e "Please enter the SRX WebAPI Username:"
read WEBAPI_USERNAME
echo -e "Please enter the SRX WebAPI Password:"
read -s WEBAPI_PASSWORD
echo -e "\nPlease provide IP Address of an EX-Series switch as well as credentials for SSH/Netconf" 
echo -e "\nPlease enter your EX IP Address:"
read EX_IP
echo -e "Please enter your EX Username:"
read EX_USERNAME
echo -e "Please enter your EX Password:"
read -s EX_PASSWORD
echo -e "Please enter your EX RADIUS Shared Secret:"
read EX_SECRET

# Make project directories 
mkdir /var/tmp/netdisco-installer
mkdir /opt/

#install dependencies 
cd /var/tmp/netdisco-installer/
apt-get update 
apt-get install -y python git wget
wget -N https://bootstrap.pypa.io/get-pip.py
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
sed -i "s/EX_IP/$EX_IP/g" /opt/pi-disco/agents/netdisco-radius.py
sed -i "s/EX_SECRET/$EX_SECRET/g" /opt/pi-disco/agents/netdisco-radius.py


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

/etc/init.d/netdisco-dhcp restart
/etc/init.d/netdisco-ex restart
/etc/init.d/netdisco-ping restart
/etc/init.d/netdisco-radius restart
/etc/init.d/netdisco-srx-syslog restart
/etc/init.d/netdisco-srx-update restart
/etc/init.d/netdisco-useragent restart
/etc/init.d/netdisco-webserver restart
/etc/init.d/redis-server restart

/usr/bin/redis-server --daemonize yes

#Delete install directory 
#rm -r /var/tmp/netdisco-installer

cp /opt/pi-disco/install/greeting.sh /etc/profile.d/
chmod +x /etc/profile.d/greeting.sh

#Is everything up and running, lets check output of ps -aux to be sure 
/opt/pi-disco/check-status.py


printf "
#EX Specific configuration required
set system services ssh protocol-version v2
set system services netconf ssh
set forwarding-options dhcp-relay overrides bootp-support
set forwarding-options dhcp-relay overrides delete-binding-on-renegotiation
set forwarding-options dhcp-relay server-group DHCP-Servers <Pi-Disco IP Address>
set forwarding-options dhcp-relay active-server-group DHCP-Servers
set protocols dot1x authenticator authentication-profile-name pidisco
set protocols dot1x authenticator interface all supplicant multiple
set protocols dot1x authenticator interface all mac-radius restrict
set protocols dot1x authenticator interface all server-fail vlan-name default
set access radius-server <Pi-Disco IP Address> port 1812
set access radius-server <Pi-Disco IP Address> accounting-port 1813
set access radius-server <Pi-Disco IP Address> secret $EX_SECRET
set access radius-server <Pi-Disco IP Address> retry 1
set access profile pidisco authentication-order radius
set access profile pidisco radius authentication-server <Pi-Disco IP Address>
set access profile pidisco radius accounting-server <Pi-Disco IP Address>
set access profile pidisco accounting order radius
set access profile pidisco accounting update-interval 10
set access profile pidisco accounting statistics volume-time
"


printf "
#SRX Specific configuration required
set system services ssh protocol-version v2
set system services netconf ssh
set system services webapi user $WEBAPI_USERNAME password $WEBAPI_PASSWORD
set system services webapi client <Pi-Disco IP Address>
set system services webapi http
"




#How long did this take? Expect a long run time on a Raspberry PI. Original model PI's will possibly not have enough memory. 
end=$(date +%s.%N)    
runtime=$(python -c "print(${end} - ${start})")

echo "Installation runtime was $runtime"
