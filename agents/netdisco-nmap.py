#!/usr/bin/python

from nmap import *
import datetime
from netaddr import *
from walrus import *

wdb = Database(host='localhost', db=0)
db = Database(host='localhost', db=0)
var = 1

nm = nmap.PortScanner()
nm.scan(hosts='192.168.0.0/24', arguments='-A')
hosts_list = [(x, nm[x]['vendor']) for x in nm.all_hosts()]

def mac_address_oui(mac,host):
    device_id = "device_" + mac.translate(None, ':')
    k = wdb.Hash(device_id)
    try:
            mac_address = EUI(mac)
            oui = mac_address.oui
            vendor = oui.registration().org
            print host,vendor
            k.update(mac_vendor=vendor)

    except NotRegisteredError:
            print host, " Unknown"
            k.update(mac_vendor="unknown vendor")

def scan_subnet():
    for host, vendor in hosts_list:
       if not vendor:
          pass
       if vendor:
        for mac in vendor:
            localtime = time.asctime( time.localtime(time.time()) )  
            mac_lower = mac.lower()
            mac_address_oui(mac_lower,host)
            mac_lower = mac_lower.translate(None,':')
            device_id = "device_" + mac_lower
            #print host,device_id
            k = wdb.Hash(device_id)
            k.update(nmap_discovered="True") 
            k.update(ip_address=host)
            k.update(mac=mac)
            k.update(last_nmap_test=localtime)
            #print k        
            
            
while var == 1:
     print "Scanning local subnet....."
     scan_subnet()
     time.sleep(60)  