#!/usr/bin/python
#Configure SRX to send SD_SYSLOG to the collector. 
#These will be parsed out and put into a REDIS DEB
#Redis DB entries will have a life of 24 hours only 

#import sys
from scapy.all import *
import time
import redis
from walrus import *

#Open connection to the Redis device database....start some correlation
#Using redis library to retrieve the key quickly then walrus to write to the DB
db = redis.Redis('localhost')
wdb = Database(host='localhost', db=0)


#Open connection to Redis, note using DB=1 for these Application tracking logs 
app_wdb = Database(host='localhost', db=1)

def find_key(ip):
    for device_key in db.scan_iter():
        device_ip = db.hget(device_key,'requested_addr')
        if ip == device_ip:
            return device_key

def update_device(device_key,localtime):
    if device_key != None:   
        device_key = wdb.Hash(device_key)
        device_key.update(SRX_last_seen=localtime)      

def syslog_print(packet):
    line = str(packet[UDP].payload) 
    print line
    
    if "APPTRACK_SESSION_VOL_UPDATE" in line: 
        localtime = time.asctime( time.localtime(time.time()) )
        log = re.findall('"([^"]*)"', line)
        date = line.split()[1]   
        session = "session_id_"
        session += log[17]
        key = app_wdb.Hash(session)
        key.update(date=localtime,last_srx_timestamp=date, closed='Session Open',source_ip=log[0], source_port=log[1], dest_ip=log[2], dest_port=log[3], l4_app=log[4], application=log[5], nested_application=log[6],source_nat_ip=log[7], source_nat_port=log[8], dest__nat_port=log[9], dest_nat_ip=log[10], source_nat_rule=log[11], dest_nat_rule=log[12], protocol_id=log[13], policy_name=log[14],source_zone=log[15], dest_zone=log[16], packets_from_client=log[18], bytes_from_client=log[19], packets_from_server=log[20], bytes_from_server=log[21], duration=log[22], username=log[23],roles=log[24], encrypted=log[25], dest_interface=log[26]) 
        key.expire(ttl=604800)    
        #device_key = find_key(log[0]) 
        #update_device(device_key,localtime)

           
    if "APPTRACK_SESSION_CLOSE" in line: 
        localtime = time.asctime( time.localtime(time.time()) )
        log = re.findall('"([^"]*)"', line)       
        date = line.split()[1]                                          
        session = "session_id_"
        session += log[18]
        key = app_wdb.Hash(session)
        key.update(date=localtime,last_srx_timestamp=date,closed='Session Closed',close_reason=log[0],source_ip=log[1], source_port=log[2], dest_ip=log[3], dest_port=log[4], l4_app=log[5], application=log[6], nested_application=log[7],source_nat_ip=log[8], source_nat_port=log[9], dest__nat_port=log[10], dest_nat_ip=log[11], source_nat_rule=log[12], dest_nat_rule=log[13], protocol_id=log[14], policy_name=log[15],source_zone=log[16], dest_zone=log[17], packets_from_client=log[19], bytes_from_client=log[19], packets_from_server=log[21], bytes_from_server=log[22], duration=log[23], username=log[24],roles=log[25], encrypted=log[26], dest_interface=log[27]) 
        key.expire(ttl=3600)
        #device_key = find_key(log[0])  
        #update_device(device_key,localtime)

        
sniff(prn=syslog_print, filter='udp and (port 514) and (not ip6)', store=0)
