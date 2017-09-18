# Pi-disco

Pi-disco peovides a single platform for discovery and fingerprinting of all devices across a network. Once devices are discovered and profiled the resulting device is programmed into an SRX firewall using a dynamic REST API without the need for configuration changes or commits to the system. 

## Theory of operation

Pi-Disco provides the following basic system agents for the detection of network devices, both static and dynamic on the network across the network. With these operational, all devices, configured through DHCP or Statically assigned should be detected and permantly stored into a centralised Redis database. Not all agents are required to be operational, but each is used to fill in additional information as devices are discovered. 
```
* DHCP Sniffer (Dynamic device detection and fingerprinting) 
* RADIUS Server
* Juniper EX-Series Polling agent (Static device detection and fingerprinting)
* HTTP UserAgent detection
* ICMP/PING Agent
```

### DHCP-Sniffer 
The DHCP agent (known as netdisco-dhcp-listener) is purely listener of DHCP requests on the network and doesn't provide IP Addressing. It is expected that one or more servers are providing IP address allocation already in the network. Network devices/switches should be configured to additionally forward DHCP requests to the Pi-Disco server for analysis. Once a DHCP request is received the agent checks the local Redis database to determine if an entry exists for this device, based on the MAC Address, if not one is created. The Agent then passes the MAC Address, Requested DHCP options and DHCP server name to the global Fingerbank database for analysis. The returned values are used to update the MAC address entry in the Redis database. MAC Address entries are never deleted from Redis, providing a historical context for every device that has connected to the network. Fingerprintint results include the MAC Vendor, Operating System Type, Version and device categorisation. Additionally the IP Address of the device is also associated with the MAC Address, once the client responds with a DHCP ACK including the IP Value. 

## RADIUS agent
The RADIUS agent (known as netdisco-radius) is a very simple RADIUS server designed to integrate with a MAC Radius based network. Currently the implementation is intended to always successfully authenticate a device connecting to the network. The intention here is not to provide network authentication, but to determine where a specific MAC Address is located. RADIUS provides information including the Switch name and the physical port a device is connected to. The RADIUS Agent will also accept interium accounting packets from devices in the network. With both RADIUS Authentication and Accounting being collected by the agent the Redis database is able to be updated to include the actual location of the device down to the switch/port level as well as the current status (Start/Stop) of traffic from the MAC Address. All this information is updated into the Redis server apon collection, keeping track of the device as it changes location/status. 

## EX-Series device agent
The EX Polling agent (known as netdisco-ex-poller) peridically connects to every defined Juniper switch in the network and collects the Ethernet Switching table, ARP table etc. Once this is collected the MAC addresses are validated against the existing Redis Database to detect devices that have not been detected through DHCP and/or 802.1X based RADIUS authentication. New devices are analysed against the Fingerbank database in a similar manner to the DHCP agent. This information is stored in the database for future use. 

## HTTP UserAgent detection
The UserAgent agent (known as netdisco-useragent) operates only where the SRX firewall has a GRE tunnel directly to the Pi-Disco server. Over this tunnel the SRX should be forwarding all TCP port 80 HTTP traffic. The agent will analyse the HTTP UserAgent header to determine what Browser is being used by each IP address. The agent then matches the IP Address to the device in the network and updates the Redis database. 

```
set interfaces gr-0/0/0 unit 0 tunnel source <SRX IP Address>
set interfaces gr-0/0/0 unit 0 tunnel destination <Pi Disco IP Address>
set interfaces gr-0/0/0 unit 0 family inet address <Tunnel IP Address for this end>

set security zones security-zone trust interfaces gr-0/0/0.0

set firewall filter port-mirror term interesting-traffic from protocol tcp
set firewall filter port-mirror term interesting-traffic from destination-port 80
set firewall filter port-mirror term interesting-traffic then port-mirror
set firewall filter port-mirror term interesting-traffic then accept
set firewall filter port-mirror term pass then accept

set interfaces ge-0/0/0 unit 0 family inet filter input port-mirror
```

## ICMP/PING Agent
The ICMP Agent (known as netdisco-pinger) periodically pings every device listed in the database to detmine if it is alive and functional. Caution is needed here as devices can still be functional on the network but blocking ICMP traffic inbound. This is used to simply provide another level of operational status of a device. 



## Install process
bash <(curl -s https://raw.githubusercontent.com/farsonic/pi-disco/master/install/install.sh)




