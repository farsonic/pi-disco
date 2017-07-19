#!/usr/bin/python

import os
import datetime
import redis
import netaddr
from walrus import *
from netaddr import valid_ipv4
import logging

db = redis.Redis('localhost')
wdb = Database(host='localhost', db=0)
var = 1

#Set up local logging 
logger = logging.getLogger('netdisco-ping')
hdlr = logging.FileHandler('/var/log/netdisco-ping.log')
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
logger.addHandler(hdlr) 
logger.setLevel(logging.INFO)


def check_ping(ip):
    response = os.system("ping -c 1 " + ip)
    if response == 0:
        pingstatus = True
    else:
        pingstatus = False
    return pingstatus
    
def iter_keys():
    for key in db.scan_iter():
        k = key
        ip = db.hget(key,'requested_addr') 
        if valid_ipv4(ip): 
            localtime = time.asctime( time.localtime(time.time()) )   
            print k 
            check = check_ping(ip)
            print check
            if check == True:
                logger.info("Successful ping test result to " + str(k) + " using " + ip)
            elif check == False: 
                logger.info("Failed ping test result to " + str(k) + " using " + ip)     
            k = wdb.Hash(k)
            k.update(ping=check) 
            k.update(last_ping_test=localtime)
            
        
while var == 1:
     iter_keys()
     time.sleep(60)    
        
     
    