
![](/images/PiDisco.png)

Pi-disco peovides a single platform for discovery and fingerprinting of all devices across a network. Once devices are discovered and profiled the resulting device is programmed into an SRX firewall using a dynamic REST API without the need for configuration changes or commits to the system. 

## Theory of operation

Pi-Disco provides the following basic system agents for the detection of network devices, both static and dynamic across the network. With the agents operational, all devices, configured through DHCP or Statically assigned should be passively detected and permantly stored into a centralised Redis database. Not all agents are required to be operational, but each is used to fill in additional information as devices are discovered, ensuring the platform and SRX firewalls have a complete catalogue of every device. 
```
* DHCP Sniffer (Dynamic device detection and fingerprinting) 
* RADIUS Server
* Juniper EX-Series Polling agent (Static device detection and fingerprinting)
* HTTP UserAgent detection
* ICMP/PING Agent
* Juniper SRX-Series dynamic programming
```

![](/images/Overview.png)


### DHCP-Sniffer 
The DHCP agent (known as netdisco-dhcp-listener) is purely listener of DHCP requests on the network and doesn't provide IP Addressing. It is expected that one or more servers are providing IP address allocation already in the network. Network devices/switches should be configured to additionally forward DHCP requests to the Pi-Disco server for analysis. Once a DHCP request is received the agent checks the local Redis database to determine if an entry exists for this device, based on the MAC Address, if not one is created. The Agent then passes the MAC Address, Requested DHCP options and DHCP server name to the global Fingerbank database for analysis. The returned values are used to update the MAC address entry in the Redis database. MAC Address entries are never deleted from Redis, providing a historical context for every device that has connected to the network. Fingerprintint results include the MAC Vendor, Operating System Type, Version and device categorisation. Additionally the IP Address of the device is also associated with the MAC Address, once the client responds with a DHCP ACK including the IP Value. 

Usage: /etc/init.d/netdisco-dhcp-listener {start|stop|restart|status}

![](/images/dhcp.png)

## RADIUS agent
The RADIUS agent (known as netdisco-radius) is a very simple RADIUS server designed to integrate with a MAC Radius based network. Currently the implementation is intended to always successfully authenticate a device connecting to the network. The intention here is not to provide network authentication, but to determine where a specific MAC Address is located. RADIUS provides information including the Switch name and the physical port a device is connected to. The RADIUS Agent will also accept interium accounting packets from devices in the network. With both RADIUS Authentication and Accounting being collected by the agent the Redis database is able to be updated to include the actual location of the device down to the switch/port level as well as the current status (Start/Stop) of traffic from the MAC Address. All this information is updated into the Redis server apon collection, keeping track of the device as it changes location/status. 

Usage: /etc/init.d/netdisco-radius {start|stop|restart|status}

![](/images/RADIUS.png)

## EX-Series device agent
The EX Polling agent (known as netdisco-ex-poller) peridically connects to every defined Juniper switch in the network and collects the Ethernet Switching table, ARP table etc. Once this is collected the MAC addresses are validated against the existing Redis Database to detect devices that have not been detected through DHCP and/or 802.1X based RADIUS authentication. New devices are analysed against the Fingerbank database in a similar manner to the DHCP agent. This information is stored in the database for future use. The polling agent uses NETCONF to connect to switches and requires credentials to be stored in the configuration file for this task. No changes are made and the user credentials could be read-only if required. 

Usage: /etc/init.d/netdisco-ex-poller {start|stop|restart|status}

![](/images/EX-Poller.png)

## HTTP UserAgent detection
The UserAgent agent (known as netdisco-useragent) operates only where the SRX firewall has a GRE tunnel directly to the Pi-Disco server. Over this tunnel the SRX should be forwarding all TCP port 80 HTTP traffic. The agent will analyse the HTTP UserAgent header to determine what Browser is being used by each IP address. The agent then matches the IP Address to the device in the network and updates the Redis database. 


The following configuration on the SRX allows for a GRE tunnel to/from the Pi-Disco Server. A Firewall filter is created and attached to the interface that carries Internet facing traffic on the trust side of the network. 

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

Usage: /etc/init.d/netdisco-useragent {start|stop|restart|status}

![](/images/UserAgent.png)

## ICMP/PING Agent
The ICMP Agent (known as netdisco-ping) periodically pings every device listed in the database to detmine if it is alive and functional. Caution is needed here as devices can still be functional on the network but blocking ICMP traffic inbound. This is used to simply provide another level of operational status of a device. 

Usage: /etc/init.d/netdisco-pinger {start|stop|restart|status}

## SRX Update agent 
The SRX Update Agent (known as netdisco-srx-update) utalises the dynamic REST based API integrated with JUNOS on the SRX-Series NGFW platform. The agent subscribes to the Redis database and immediatly detects every change made to a device either manually from the Redis-cli, the pi-disco agents or through the Web GUI. This capability ensures the SRX platform has an identical view of the active devices in the Redis database within seconds of them being connected or updated. 

When running through the install process the required configuration commands are provided for the SRX. For refernce the following needs to be configured. The WebAPI uses it's own dedicated username/password and is unique from the local user credentials used for SSH, NETCONF etc. 

```
set system services webapi user admin password <PASSWORD>
set system services webapi client <Pi Disco IP Address> 
set system services webapi http
```

Usage: /etc/init.d/netdisco-srx-update {start|stop|restart|status}

![](/images/SRX-Mapping.png)

## Web Interface
The GUI is a Pyhon Flask Web application that relies on the underlying Redis database. By default the web interface is installed/operating at http://<PI-IP-Address>:8080/ 

Usage: /etc/init.d/netdisco-webserver {start|stop|restart|status}



# Install process
bash <(curl -s https://raw.githubusercontent.com/farsonic/pi-disco/master/install/install.sh)


# Debugging

Each agent is located in /opt/pidisco/agents and can be run directly from the command line if requried. This can aid in debugging functionality or to determine if the installation processed failed or there are missing dependencies. Before running one of these agents, first stop the agent from running using /etc/init.d/agent* stop. 

