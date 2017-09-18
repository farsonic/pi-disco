# Pi-disco

Pi-disco peovides a single platform for discovery and fingerprinting of all devices across a network. Once devices are discovered and profiled the resulting device is programmed into an SRX firewall using a dynamic REST API without the need for configuration changes or commits to the system. 

## Theory of operation

Pi-Disco provides the following basic system agents for the detection of network devices, both static and dynamic on the network across the network. With these operational, all devices, configured through DHCP or Statically assigned should be detected and permantly stored into a centralised Redis database. Not all agents are required to be operational, but each is used to fill in additional information as devices are discovered. 
```
* DHCP Sniffer (Dynamic device detection and fingerprinting) 
* RADIUS Server
* HTTP UserAgent detection
* ICMP/PING Agent
* Juniper EX-Series Polling agent (Static device detection and fingerprinting)
```

### DHCP-Sniffer 
The DHCP agent (known as netdisco-dhcp-listener) is purely listener of DHCP requests on the network and doesn't provide IP Addressing. It is expected that one or more servers are providing IP address allocation already in the network. Network devices/switches should be configured to additionally forward DHCP requests to the Pi-Disco server for analysis. Once a DHCP request is received the agent checks the local Redis database to determine if an entry exists for this device, based on the MAC Address, if not one is created. The Agent then passes the MAC Address, Requested DHCP options and DHCP server name to the global Fingerbank database for analysis. The returned values are used to update the MAC address entry in the Redis database. MAC Address entries are never deleted from Redis, providing a historical context for every device that has connected to the network. Fingerprintint results include the MAC Vendor, Operating System Type, Version and device categorisation. Additionally the IP Address of the device is also associated with the MAC Address, once the client responds with a DHCP ACK including the IP Value. 

## RADIUS agent
The RADIUS agent (known as netdisco-radius) is a very simple RADIUS server designed to integrate with a MAC Radius based network. Currently the implementation is intended to always successfully authenticate a device connecting to the network. The intention here is not to provide network authentication, but to determine where a specific MAC Address is located. RADIUS provides information including the Switch name and the physical port a device is connected to. The RADIUS Agent will also accept interium accounting packets from devices in the network. With both RADIUS Authentication and Accounting being collected by the agent the Redis database is able to be updated to include the actual location of the device down to the switch/port level as well as the current status (Start/Stop) of traffic from the MAC Address. All this information is updated into the Redis server apon collection.   



## Install process
bash <(curl -s https://raw.githubusercontent.com/farsonic/pi-disco/master/install/install.sh)




