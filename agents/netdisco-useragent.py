#!/usr/bin/python

from scapy import *
from scapy.all import IP, sniff
from scapy.layers import http
import redis
import time
import logging
from walrus import *
from ua_parser import user_agent_parser
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Open up Redis database
db = redis.Redis('localhost')
wdb = Database(host='localhost', db=0)

def process_tcp_packet(packet):
    if not packet.haslayer(http.HTTPRequest):
        # This packet doesn't contain an HTTP request so we skip it
        return
    http_layer = packet.getlayer(http.HTTPRequest)
    ip_layer = packet.getlayer(IP)
    
    try: 
        ip =  '{0[src]}'.format(ip_layer.fields, http_layer.fields)
        ua_string = '{1[User-Agent]}'.format(ip_layer.fields, http_layer.fields)
        agent = user_agent_parser.ParseUserAgent(ua_string)
        print ua_string
        device = user_agent_parser.ParseDevice(ua_string)
        os = user_agent_parser.ParseOS(ua_string)      
        browser_family = agent['family']
        browser_major = agent['major']
        browser_minor = agent['minor']
        browser_patch = agent['patch']
        device_brand = device['brand']
        device_family = device['family']
        device_model = device['model']
        os_family = os['family']
        os_major = os['major']
        os_minor = os['minor']
        os_patch = os['patch']
        os_patch_minor = os['patch_minor'] 
        key = find_key(ip)
        device_hash = wdb.Hash(key)   
        hostname = device_hash['hostname']
        #print key,hostname,ip,browser_family,browser_major,browser_minor,browser_patch,device_brand,device_family,device_model,os_family,os_major,os_minor,os_patch,os_patch_minor
        os_version = str(os_major) +'.'+ str(os_minor) +'.'+ str(os_patch)
        browser_combined = browser_family  +'('+ str(browser_major) +'.'+ str(browser_minor) +'.'+ str(browser_patch) +')'
        k = wdb.Hash(key)
        
        if "Other" not in os_family:
            k.update(os=os_family)
            print ip,key,os_family
            
            if os_family == "Mac OS X":
                k.update(category="Desktop/Laptop")
                
            if os_family == "iOS":
                k.update(category="Smartphones/PDAs/Tablets")    
            
        if ("None" or "Other") not in os_version:
            k.update(os_version=os_version)
            print ip,key,os_version

        if ("None" or "Other") not in browser_combined:
            k.update(browser_family=browser_combined)   
            print ip,key,browser_combined
            
                      
    except KeyError: 
        pass
        
        
def find_key(ip):
    for key in db.scan_iter():
        key_ip = db.hget(key,'requested_addr') 
        if key_ip == ip: 
            return key


sniff(iface="GRETUN0", prn=process_tcp_packet)



