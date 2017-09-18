# pi-disco

__________.__          ________  .__
\______   \__|         \______ \ |__| ______ ____  ____
 |     ___/  |  ______  |    |  \|  |/  ___// ___\/  _ \
 |    |   |  | /_____/  |    \   \  |\___ \  \__(  <_> )
 |____|   |__|         /_______  /__/____  >\___  >____/
                               \/        \/     \/

Pi-disco peovides a single platform for discovery and fingerprinting of all devices across a network. Once devices are discovered and profiled the resulting device is programmed into an SRX firewall using a dynamic REST API without the need for configuration changes or commits to the system. 

## Theory of operation

Pi-Disco provides the following basic system agents for the detection of devices, both static and dynamic on the network across the network. 

..* DHCP Sniffer 
..* RADIUS Server
..* HTTP UserAgent detection
..* ICMP/PING Agent
..* Juniper EX-Series Polling agent

## Install process
bash <(curl -s https://raw.githubusercontent.com/farsonic/pi-disco/master/install/install.sh)




