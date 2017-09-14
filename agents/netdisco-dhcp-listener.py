#!/usr/bin/python

from scapy.all import *
import StringIO
import re, requests, json, subprocess, binascii, datetime, os, thread, ConfigParser
from netaddr import *
import netaddr
from flask import Flask
import time
from walrus import *
import logging

#load configuration file

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

Config = ConfigParser.ConfigParser()
Config.read("/opt/pi-disco/netdisco.conf")

key = ConfigSectionMap("Fingerbank")['key']
print key


#Open up Redis database
db = Database(host='localhost', db=0)
fam, hw = get_if_raw_hwaddr(conf.iface)

#Set up local logging 
logger = logging.getLogger('netdisco-dhcp')
hdlr = logging.FileHandler('/var/log/netdisco-dhcp.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)

url = 'https://fingerbank.inverse.ca/api/v1/combinations/interogate?key='
url += key

headers = {'Content-type': 'application/json'}


#try:
#    with open('parameters.json') as parameter_file:
#        parameter_list = json.load(parameter_file)
#        print "Local parameters file loaded" 
#except:   
#    print "Creating blank parameters file"  
parameter_list = {}
    
    
#List of all DHCP option values. Not currently used but could be referenced if needed"
dict = {'132': 'IEEE 802.1Q', '212': 'OPTION_6RD ', '213': 'OPTION_V4_ACCESS_DOMAIN ', '210': 'Path Prefix', '211': 'Reboot Time', '176': 'IP Telephone', '60': 'Class Id', '61': 'Client Id', '62': 'NetWare/IP Domain', '63': 'NetWare/IP Option', '64': 'NIS-Domain-Name ', '65': 'NIS-Server-Addr ', '66': 'Server-Name ', '67': 'Bootfile-Name ', '68': 'Home-Agent-Addrs ', '69': 'SMTP-Server ', '139': 'OPTION-IPv4_Address-MoS ', '138': 'OPTION_CAPWAP_AC_V4 ', '177': 'PacketCable and', '154': 'query-start-time ', '24': 'MTU Timeout', '25': 'MTU Plateau', '26': 'MTU Interface', '27': 'MTU Subnet', '20': 'SrcRte On/Off', '21': 'Policy Filter', '22': 'Max DG', '23': 'Default IP', '160': 'DHCP Captive-Portal', '175': 'Etherboot (Tentatively', '28': 'Broadcast Address', '29': 'Mask Discovery', '130': 'Discrimination string', '0': 'Pad ', '2': 'Time Offset', '4': 'Time Server', '6': 'Domain Server', '128': 'TFTP Server', '8': 'Quotes Server', '96': 'REMOVED/Unassigned ', '119': 'Domain Search', '221': 'Virtual Subnet', '120': 'SIP Servers', '102-107': 'REMOVED/Unassigned ', '99': 'GEOCONF_CIVIC ', '98': 'User-Auth ', '122': 'CCC ', '123': 'GeoConf Option', '124': 'V-I Vendor', '125': 'V-I Vendor-Specific', '126': 'Removed/Unassigned ', '127': 'Removed/Unassigned ', '91': 'client-last-transaction-time option', '59': 'Rebinding Time', '93': 'Client System', '92': 'associated-ip option', '95': 'LDAP ', '94': 'Client NDI', '97': 'UUID/GUID ', '58': 'Renewal Time', '11': 'RLP Server', '10': 'Impress Server', '13': 'Boot File', '12': 'Hostname ', '15': 'Domain Name', '14': 'Merit Dump', '17': 'Root Path', '16': 'Swap Server', '19': 'Forward On/Off', '18': 'Extension File', '57': 'DHCP Max', '56': 'DHCP Message', '51': 'Address Time', '50': 'Address Request', '53': 'DHCP Msg', '52': 'Overload ', '55': 'Parameter List', '116': 'Auto-Config ', '54': 'DHCP Server', '137': 'OPTION_V4_LOST ', '90': 'Authentication ', '136': 'OPTION_PANA_AGENT ', '151': 'status-code ', '150': 'GRUB configuration', '153': 'start-time-of-state ', '152': 'base-time ', '155': 'query-end-time ', '135': 'HTTP Proxy', '157': 'data-source ', '156': 'dhcp-state ', '159': 'OPTION_V4_PORTPARAMS ', '158': 'OPTION_V4_PCP_SERVER ', '134': 'Diffserv Code', '115': 'REMOVED/Unassigned ', '114': 'URL ', '88': 'BCMCS Controller', '89': 'BCMCS Controller', '111': 'Unassigned ', '110': 'REMOVED/Unassigned ', '113': 'Netinfo Tag', '112': 'Netinfo Address', '82': 'Relay Agent', '83': 'iSNS ', '80': 'Rapid Commit', '81': 'Client FQDN', '86': 'NDS Tree', '87': 'NDS Context', '84': 'REMOVED/Unassigned ', '85': 'NDS Servers', '117': 'Name Service', '129': 'Call Server', '48': 'X Window', '49': 'X Window', '46': 'NETBIOS Node', '47': 'NETBIOS Scope', '44': 'NETBIOS Name', '45': 'NETBIOS Dist', '42': 'NTP Servers', '43': 'Vendor Specific', '40': 'NIS Domain', '41': 'NIS Servers', '1': 'Subnet Mask', '3': 'Router ', '5': 'Name Server', '7': 'Log Server', '9': 'LPR Server', '255': 'End ', '146': 'RDNSS Selection', '144': 'GeoLoc ', '145': 'FORCERENEW_NONCE_CAPABLE ', '142': 'OPTION-IPv4_Address-ANDSF ', '143': 'Unassigned ', '140': 'OPTION-IPv4_FQDN-MoS ', '141': 'SIP UA', '209': 'Configuration File', '208': 'PXELINUX Magic', '77': 'User-Class ', '76': 'STDA-Server ', '75': 'StreetTalk-Server ', '74': 'IRC-Server ', '73': 'Finger-Server ', '72': 'WWW-Server ', '71': 'NNTP-Server ', '70': 'POP3-Server ', '100': 'PCode ', '101': 'TCode ', '118': 'Subnet Selection', '79': 'Service Scope', '78': 'Directory Agent', '133': 'IEEE 802.1D/p', '108': 'REMOVED/Unassigned ', '39': 'Keepalive Data', '38': 'Keepalive Time', '161': 'OPTION_MUD_URL_V4 (TEMPORARY', '121': 'Classless Static', '33': 'Static Route', '32': 'Router Request', '31': 'Router Discovery', '30': 'Mask Supplier', '37': 'Default TCP', '36': 'Ethernet ', '35': 'ARP Timeout', '34': 'Trailers ', '131': 'Remote statistics', '109': 'Unassigned ', '220': 'Subnet Allocation'}

def unpackMAC(binmac):
    mac=binascii.hexlify(binmac)[0:12]
    blocks = [mac[x:x+2] for x in xrange(0, len(mac), 2)]
    #print "Converted mac address: " + ':'.join(blocks)
    return ':'.join(blocks)


#Adds a new key to Redis DB when MAC Address is discovered
def update_mac_redis(mac):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(mac=mac)    

          
#Checks the devices dictionary to see if this MAC address is new
#If it is new then lets create a new entry for this. 
#Update Redis DB with discovered hostname
def update_device_mac_hostname_redis(mac,hostname):  
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(hostname=hostname) 

#Not implemented yet, investigate option-82 inclusion here    
def update_device_helper_redis(mac,helper):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(helper=helper)
    
#Assign detected Operating System to the MAC Address
def update_device_mac_os_redis(mac,os):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(os=os) 
    
def update_device_ttl_redis(mac,ttl):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(ttl=ttl)          

#Some general assumptions noted around the TTL present in the DHCP packets and corresponding Operating Systems
#Quite often this is wrong, especially with embedded OS's 
def ttl_os_guess(mac,ttl):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(ttl=ttl) 
    
    if 54 <= ttl <= 74: 
        ttl_os_guess = "Linux"
    elif 118 <= ttl <= 138: 
        ttl_os_guess = "Windows" 
    elif ttl == 255:
        ttl_os_guess = "OSX or iOS"
    else:
        ttl_os_guess = "unknown"    
    device_id.update(ttl_os_guess=ttl_os_guess)     
              
	 
#If a client passed a requested IP Address to us then lets record that against 
#their MAC Address        
def update_device_mac_requested_address_redis(mac,requested_addr):  
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(requested_addr=requested_addr)        
    
def update_device_mac_vendor_class_id_redis(mac,vendor_class_id):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(vendor_class_id=vendor_class_id) 
    
def update_device_dhcp_req_timestamp_redis(mac):  
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    localtime = time.asctime( time.localtime(time.time()) )
    device_id.update(last_dhcp_req=localtime)   
    
def update_device_dhcp_ack_timestamp_redis(mac):  
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    localtime = time.asctime( time.localtime(time.time()) )
    device_id.update(last_dhcp_ack=localtime)                         

#DHCP clients will provide a list of DHCP options, these can be used to fingerprint the operating system 
#This should be stored against the MAC Address  
def update_device_parameter_list_redis(mac,options_list): 
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(options_list=options_list)  
    
def update_device_mobile_redis(mac,mobile): 
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(is_mobile=mobile)      
    
def update_device_category_redis(mac,category): 
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(category=category)           
                
def update_device_dhcp_expiry_redis(mac,lease_expire): 
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    device_id.update(lease_expire=lease_expire) 
                    
def fingerbank(mac,options_list,vendor_class_id):
    #Pass the options list to Fingerbank to determine the operating system    
    data = {}
    #print "We ar using this for the vendor->" + vendor_class_id
    device_id = "device_" + mac.translate(None, ':')
    data['dhcp_fingerprint'] = options_list
    data['dhcp_vendor'] = vendor_class_id
    data['mac'] = mac
    json_data = json.dumps(data)
    response = requests.get(url, data=json_data, headers=headers)
    response = response.json()
    print "Fingerbank response: " + str(response)
    logger.info("Fingerbank response: " + str(response))

                    
    try:
    
        os = (response['device']['name'])
        mobile = (response['device']['mobile'])
        
        try:
        	list = response['device']['parents']
        	category = (list[0]['name'])
        except IndexError:
        	category = "Unknown device category"  
        
        print "__________Fingerprint Info____________"
        print "Redis ID:          " + device_id	
        print "Operating System:  " + os
    	print "Mobile:            " + str(mobile)
    	print "Device Category    " + category   	
    	update_device_mac_os_redis(mac,os)
        update_device_category_redis(mac,category)
        update_device_mobile_redis(mac,str(mobile))
        print "______________________________________\n\n"
        logger.info(device_id + " " + os+ " " + str(mobile)+ " " +  category)
              
    except KeyError:
        print "Can't decode this record....???"
        os = 'unknown'
        update_device_mac_os_redis(mac,os)
       
    #update_parameter_list_os(options_list,os,mobile,category) 

 
#Check to see if we already have a match for this DHCP options list and use the corresponding Operating System 
def lookup_parameter(mac,options_list,vendor_class_id):   
    os = parameter_list[options_list]
    #print "Operating System:  " + str(os)
    #update_device_mac_os_redis(mac,os)
    if os == {}: 
        #print "Looking up Fingerprint"
        thread.start_new_thread(fingerbank, (mac,options_list,vendor_class_id))
            
             
#Maintain a list of discovered DHCP Parameters which will then have an Operating System pinned to them 
def update_parameter_list(options_list):
    try: 
        if parameter_list[options_list]:
           pass

    except KeyError:
        #print "Adding newly discovered DHCP options list"
        parameter_list[options_list] = {}
        write_parameter_file()
           
#Assign Operating System to the DHCP Parameters list when pushed back from FingerBank.org    
def update_parameter_list_os(options_list,os,mobile,category):
    #Add options list to parameters.json file
    update_parameter_list(options_list)
    try:
        parameter_list[options_list] = (os) 
        parameter_list[options_list] = (mobile)
        parameter_list[options_list] = (category)  
        write_parameter_file()                 

    except KeyError:
        print "Unknown Operating System"
        parameter_list[options_list] = "unknown" 
        write_parameter_file()   
             
#Lookup the OUI of the MAC address and extract the vendor name 
#Some MAC Addresses are not registered so insert these as 'unknown' 
def mac_address_oui(mac):
    device_id = "device_" + mac.translate(None, ':')
    device_id = db.Hash(device_id)
    try:
            mac_address = EUI(mac)
            oui = mac_address.oui
            vendor = oui.registration().org
            print "Vendor Lookup:     " +vendor
            device_id.update(mac_vendor=vendor)

    except NotRegisteredError:
            print "Vendor:     Unknown"
            device_id.update(mac_vendor="unknown vendor")
    
        
def write_parameter_file():
    json.dump(parameter_list, open("parameters.json",'w'))
        
#Process DHCP request message        
def dhcp_request(resp):
    msg = ""
    print "_______DHCP Request Received__________"
    mac = unpackMAC(resp[BOOTP].chaddr)
    device_id = "device_" + mac.translate(None, ':')
    print "Redis ID:          " + device_id
    print "MAC Address:       " + mac
    msg += "DHCP Request Redis ID: " + device_id + " MAC Address: " + mac + " " 
    length = len(resp[1][DHCP].options)
    update_mac_redis(mac)
    ttl =  resp.ttl
    update_device_ttl_redis(mac,ttl)
    update_device_dhcp_req_timestamp_redis(mac)
    ttl_os_guess(mac,ttl)
    vendor_class_id = ""
    
    
    for op in range(0, length-1):
        
        if resp[1][DHCP].options[op][0] == 'hostname': 
            hostname = resp[1][DHCP].options[op][1] 
            function = str(resp[1][DHCP].options[op][0])
            print "Hostname:          " + hostname
            msg += "Hostname: " + hostname + " "
            update_device_mac_hostname_redis(mac,hostname)

        elif resp[1][DHCP].options[op][0] == 'requested_addr':
            requested_addr = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "IP Address:        " + requested_addr
            msg += "IP Address: " + requested_addr + " "
            update_device_mac_requested_address_redis(mac,requested_addr)
            
        elif resp[1][DHCP].options[op][0] == 'lease_time':
            lease_time = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            lease_expire = time.asctime( time.localtime(time.time()+lease_time)) 
            print "Lease Expires on:  " + lease_expire
            print "Lease time:        " + str(lease_time) + " seconds"
            msg += "Lease Expire: " + lease_expire + " "
            msg += "Lease Time: " + str(lease_time) + " "
            update_device_dhcp_expiry_redis(mac,lease_expire)

            
        elif resp[1][DHCP].options[op][0] == 'rebinding_time':
            rebinding_time = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "Rebinding time:     " + str(rebinding_time) + " seconds"  
            msg += "Rebinding time: " + str(rebinding_time) + " "
            
        elif resp[1][DHCP].options[op][0] == 'vendor_specific':
            vendor_specific = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "Rebinding time:    " + str(vendor_specific) + " seconds"   
            msg += "Rebinding time: " + str(vendor_specific) + " "  
            
        elif resp[1][DHCP].options[op][0] == 'time_zone':
            time_zone = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "Time Zone:         " + str(time_zone) + " seconds"   
            msg += "TimeZone: " + str(time_zone) + " "     
        
        elif resp[1][DHCP].options[op][0] == 'vendor_class_id':
            vendor_class_id = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "Vendor Class:      " + vendor_class_id
            update_device_mac_vendor_class_id_redis(mac,vendor_class_id)
            msg += "VendorClass: " + vendor_class_id + " "
               
        elif resp[1][DHCP].options[op][0] == 'client_id':
            client_id = resp[1][DHCP].options[op][1]
            function = str(resp[1][DHCP].options[op][0])
            print "Client ID:         "  + client_id
            #Not currently doing anything with this 

        elif resp[1][DHCP].options[op][0] == 'param_req_list':
            hexstr = resp[1][DHCP].options[op][1]
            parameters = [ord(val) for val in hexstr] 
            options_list = str(parameters) 
            options_list = options_list.replace("[","")
            options_list = options_list.replace("]","")
            options_list = options_list.replace(" ","")
            print "DHCP Options:      " + options_list
            msg += "DHCPOptions: " + options_list + " "
            update_parameter_list(options_list)
            update_device_parameter_list_redis(mac,options_list)
            os = lookup_parameter(mac,options_list,vendor_class_id)    
            mac_address_oui(mac)
               
    print "___________End_DHCP Request___________\n\n"
    logger.info(msg)


def dhcp_print(resp):
  request =  resp[DHCP].options
  type = request[0][1]
 
  if type == 1:
    #DHCP Discovery
    ip = str(resp[1][BOOTP].yiaddr)
    mac = unpackMAC(resp[BOOTP].chaddr)
    length = len(resp[1][DHCP].options)
    #print "______DHCP Discovery________"
    #print "DHCP discovery from: " + mac
    #for op in range(0, length-1):
    #    option = resp[1][DHCP].options[op][0] 
    #    value = resp[1][DHCP].options[op][1] 
    #    print str(option) + "=" + str(value)
    #print "______End_DHCP_Discovery____\n"
    

  elif type == 2:
    pass

  elif type == 3:
    #DHCP Request packet is sent in response to an offer made by the server, this contains the IP Address that the client agrees to use 
    #DHCP Requests are also used to rebind the allocated address. This is sent at 1/2 of the lease time 
    dhcp_request(resp)

  elif type == 4:
    pass

  elif type == 5:
    print "______DHCP Ack________"
    ip = str(resp[1][BOOTP].yiaddr)
    mac = unpackMAC(resp[BOOTP].chaddr)
    update_device_mac_requested_address_redis(mac,ip)
    update_mac_redis(mac)
    update_device_dhcp_ack_timestamp_redis(mac)
    length = len(resp[1][DHCP].options)
    #print "DHCP ack to: " + mac
    #for op in range(0, length-1):
    #    option = resp[1][DHCP].options[op][0] 
    #    value = resp[1][DHCP].options[op][1] 
    #    print str(option) + "=" + str(value)
    print "______End_DHCP_Ack____\n"   
    

  elif type == 6:
    pass

  elif type == 7:
    print "______DHCP Release________"
    mac = unpackMAC(resp[BOOTP].chaddr)
    helper = resp[Ether].src
    print "DHCP release from: " + mac
    print "DHCP helper: " + helper
    length = len(resp[1][DHCP].options)
    mac = unpackMAC(resp[BOOTP].chaddr)
    print mac
    print "_____End_DHCP_Release_____\n"
       
  elif type == 8:
    pass

  elif type == 9:
    #Force renew packet	
    pass

  elif type == 10:
    pass

  elif type == 11:
    pass

  elif type == 12:
    pass

  elif type == 13:
    pass

print "running"
sniff(prn=dhcp_print, filter='udp and (port 67 or 68) and (not ip6)', store=1)
