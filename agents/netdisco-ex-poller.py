#!/usr/bin/python

import redis,yaml,ConfigParser
from walrus import *
from netaddr import *
import json
from jnpr.junos.op.arp import ArpTable
from jnpr.junos.factory.factory_loader import FactoryLoader
from jnpr.junos.exception import ConnectError
from jnpr.junos import Device


yml = '''
---
EtherSwTable:
  rpc: get-interface-ethernet-switching-table
  item: ethernet-switching-table/mac-table-entry[mac-type='Learn']
  key: mac-address
  view: EtherSwView

EtherSwView:
  fields:
    vlan_name: mac-vlan
    mac_address: mac-address
    mac_type: mac-type
    mac_age: mac-age
    interface_name: mac-interfaces-list/mac-interfaces
    
DHCPSnoopTable:
  rpc: get-dhcp-snoop-binding
  item: dhcp-snooping-information
  key: dhcp-mac
  view: DHCPSnoopView

DHCPSnoopView:
  fields:
    vlan_name: dhcp-vlan
    ip_address: dhcp-ip
    mac_address: dhcp-mac
    dhcp_lease: dhcp-lease
    dhcp_type: dhcp-type
    interface_name: dhcp-interface    
    
LLDPTable:
  rpc: get-lldp-neighbors-information
  item: lldp-neighbor-information
  key: lldp-remote-chassis-id
  view: LLDPView

LLDPView:
  fields:
    interface_name: lldp-local-interface
    mac_address: lldp-remote-chassis-id
    hostname: lldp-remote-system-name
    ip_address: lldp-remote-port-description
    
'''






def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print("exception on %s!" % option)
            dict1[option] = None
    return dict1


wdb = Database(host='localhost', db=0)
var = 1

Config = ConfigParser.ConfigParser()
Config.read("/opt/pi-disco/netdisco.conf")
dir = ConfigSectionMap("Global")['directory']
username = ConfigSectionMap("EX")['username']
password = ConfigSectionMap("EX")['password']
ex_ip = ConfigSectionMap("EX")['ip']
ex_ip = ex_ip.split(',')

globals().update(FactoryLoader().load(yaml.load(yml)))



file = dir + "ex_series.conf"
data = open(file)
entries = data.read()
list = entries.splitlines()

def mac_address_oui(device_id,mac):
    k = wdb.Hash(device_id) 
    try:
       mac_address = EUI(mac)
       oui = mac_address.oui
       vendor = oui.registration().org
       #print "Vendor Lookup:     " +vendor
       k.update(mac_vendor=vendor)
       category_update(mac,vendor)
       return

    except:
       #print "Vendor: Unknown"
       k.update(mac_vendor="unknown vendor")
       return

def category_update(mac,vendor):
    mac = item.mac_address.translate(None, ':')
    mac = mac.lower()
    device_id = "device_" + mac
    k = wdb.Hash(device_id) 
    if "Aruba" in vendor:
        k.update(category="Network Equipment")
        
    if "Juniper Networks" in vendor:
        k.update(category="Network Equipment") 
        
    if "Cisco" in vendor:
        k.update(category="Network Equipment") 
        
    if "Ubiquiti" in vendor:
        k.update(category="Network Equipment") 
        
    if "Espressif" in vendor:
        k.update(category="Internet of Things (IoT)") 
        
    if "Slim Devices, Inc." in vendor:
        k.update(category="Internet of Things (IoT)") 
        
    if "D&M Holdings Inc." in vendor:
        k.update(category="Internet of Things (IoT)")     
     
    if "Kingjon Digital Technology Co.,Ltd" in vendor:
        k.update(category="Internet of Things (IoT)")
        
    if "Belkin" in vendor:
        k.update(category="Internet of Things (IoT)")        

    if "Universal Global Scientific Industrial Co., Ltd." in vendor:
        k.update(category="Internet of Things (IoT)") 
        
    if "Raspberry Pi Foundation" in vendor:
        k.update(os="Linux",category="Internet of Things (IoT)")     
            
   
        
             
                             

while var == 1:
    for switch in list: 
       device = switch
       print "Analysing switch = "+switch
       dev = Device(device,user=username,password=password)
             
       try: 
           dev.open()
           #Retrieve ARP Table
           arp_table = ArpTable(dev)
           arp_table.get()
           #Retrieve Ethernet Switching table 
           eth_table = EtherSwTable(dev)
           eth_table.get()
           #Retrieve DHCP Snooping Table
           DHCP_table = DHCPSnoopTable(dev)
           DHCP_table.get()
           print DHCP_table
           LLDP_table = LLDPTable(dev)
           LLDP_table.get()
           print LLDP_table
           	   
           serial_number = dev.facts['serialnumber']
           switch_hostname = dev.facts['hostname']
  
           for item in arp_table:
               mac = item.mac_address.translate(None, ':')
               mac = mac.lower()
               device_id = "device_" + mac
               k = wdb.Hash(device_id)
               k.update(ip_address=item.ip_address,requested_addr=item.ip_address,source_switch=switch_hostname,source_switch_serial=serial_number,mac=item.mac_address.lower())
               #k.expire(ttl=200)
               mac_address_oui(device_id,item.mac_address)
               
           for item in eth_table: 
               mac = item.mac_address.translate(None, ':')
               mac = mac.lower()
               device_id = "device_" + mac
               k = wdb.Hash(device_id)
               k.update(source_switch=switch_hostname,source_switch_serial=serial_number,mac=item.mac_address.lower(),source_vlan=item.vlan_name,source_interface=item.interface_name)
               #k.expire(ttl=200)
               mac_address_oui(device_id,item.mac_address)

           for item in DHCP_table: 
               mac = item.mac_address.translate(None, ':')
               mac = mac.lower()
               device_id = "device_" + mac
               k = wdb.Hash(device_id)
               k.update(ip_address=item.ip_address,requested_addr=item.ip_address,source_switch=switch_hostname,source_switch_serial=serial_number,mac=item.mac_address.lower(),source_vlan=item.vlan_name,source_interface=item.interface_name)
               mac_address_oui(device_id,mac)
               #k.expire(ttl=200)
      
           for item in LLDP_table: 
               mac = item.mac_address.translate(None, ':')
               mac = mac.lower()
               device_id = "device_" + mac
               mac_address_oui(device_id,mac)
               k = wdb.Hash(device_id)
               if valid_ipv4(item.ip_address):
                   if not IPAddress(item.ip_address).is_link_local():
                       print item.ip_address
                       k.update(ip_address=item.ip_address,source_interface=item.interface_name,mac=item.mac_address.lower(),domain_name=item.hostname)
                       
               else:
                   k.update(source_interface=item.interface_name,mac=item.mac_address.lower(),domain_name=item.hostname)
               #k.expire(ttl=200)             
       
                          
           dev.close()    
           time.sleep(20) 
           
          
       except ConnectError:
               print "Cannot connect to device: {0}".format(err)
               time.sleep(20)
