#!/usr/bin/python

import datetime,redis
import xml.etree.ElementTree as ET
import requests
from walrus import *
from requests.auth import HTTPBasicAuth
import argparse

db = redis.Redis('localhost')


srx_ip = '192.168.0.2'
username = 'netdisco'
password = 'jun1per'

def logon(dev_username,ip,redis_mac_vendor,redis_device_model,redis_os,redis_os_version,redis_category,customtags):
    timestamp =  str(datetime.datetime.now().isoformat())
    source = ET.Element("source")
    source.text = "NetDisco Agent"
    user.insert(0,source)
    time = ET.Element("timestamp")
    time.text = timestamp + "z"
    user.insert(1,time)
    operation = ET.Element("operation")
    operation.text = "logon"
    user.insert(2,operation)
    address = ET.Element("IP")
    address.text = str(ip)
    user.insert(3,address)
    domain = ET.Element("domain")
    domain.text = "NetDisco"
    user.insert(4,domain)
    name = ET.Element("user")
    name.text = str(dev_username)
    user.insert(5,name)
    posture = ET.Element("posture")
    posture.text = "Healthy"
    user.insert(6,posture)
    #Add Device attributes into XML
    hostname = ET.Element("value")
    hostname.text = str(dev_username)
    device.insert(0,hostname)
    #Add role assignments into XML
    #if role is not None:
    #    for role in args.role:
    #        ET.SubElement(roles, "role").text = role
    #if groups is not None:
    #    for group in args.groups:
    #        ET.SubElement(device, "group").text = group
    type = ET.Element("device-category")
    type.text = str(redis_category)
    attributes.insert(0,type)
    vendor = ET.Element("device-vendor")
    vendor.text = str(redis_mac_vendor)
    attributes.insert(1,vendor)
    model = ET.Element("device-model")
    model.text = str(redis_device_model)
    attributes.insert(2,model)
    os = ET.Element("device-os")
    os.text = str(redis_os)
    attributes.insert(3,os)
    version = ET.Element("device-os-version")
    version.text = str(redis_os_version)
    attributes.insert(4,version)
    if customtags is not None:
      for entry in customtags:
           ET.SubElement(attributes, entry).text = customtags[entry]

    return;

def logoff(dev_username,ip):
    #Generate XML file for upload
    timestamp =  str(datetime.datetime.now().isoformat())
    source = ET.Element("source")
    source.text = "Aruba ClearPass"
    user.insert(0,source)
    time = ET.Element("timestamp")
    time.text = timestamp + "z"
    user.insert(1,time)
    operation = ET.Element("operation")
    operation.text = 'logoff'
    user.insert(2,operation)
    address = ET.Element("IP")
    address.text = str(ip)
    user.insert(3,address)
    name = ET.Element("user")
    name.text = dev_username
    user.insert(4,name)
    return;

def generatexml():
    tree = ET.ElementTree(root)
    xml = "<?xml version=\"1.0\"?>" + ET.tostring(root)
    headers = {'Content-Type': 'application/xml'}
    url = 'http://'+srx_ip+':8080/api/userfw/v1/post-entry'
    #print xml
    print requests.post(url, auth=HTTPBasicAuth(username,password), data=xml, headers=headers).text
    
    
    
#Redis subscribe
r = redis.StrictRedis()
pubsub = r.pubsub()
pubsub.psubscribe('__keyspace@0__:device_*')

#Initialize a local Dictionary to track device and IP assignment if known
state_db = {}

for msg in pubsub.listen():
    type = msg['data']
    device_id = str(msg['channel'].split(':')[1])
    
    if type == 'hset':
        customtags = {}
        root = ET.Element("userfw-entries")
        user = ET.SubElement(root, "userfw-entry")
        roles = ET.SubElement(user, "role-list")
        attributes = ET.SubElement(user, "end-user-attribute")
        device = ET.SubElement(attributes, "device-identity")
        
        dev_username = device_id.split('_')[1]
        type = msg['data']
        ip = db.hget(device_id,'requested_addr')
        
        redis_mac_vendor = db.hget(device_id,'mac_vendor')
        redis_device_model = db.hget(device_id,'device_model')
        redis_os = db.hget(device_id,'os')
        redis_os_version = db.hget(device_id,'os_version')
        redis_category = db.hget(device_id,'category')
        
        customtags['Deny'] = db.hget(device_id,'deny')
        customtags['MAC-Address'] = db.hget(device_id,'mac')
        customtags['Switch-Serial'] = db.hget(device_id,'source_switch_serial')
        customtags['Switch-Name'] = db.hget(device_id,'source_switch')
        customtags['Switch-Interface'] = db.hget(device_id,'source_interface')
        customtags['Switch-VLAN'] = db.hget(device_id,'source_vlan')
        customtags['Is-Mobile'] = db.hget(device_id,'is_mobile')
        customtags['Hostname'] = db.hget(device_id,'hostname')
        customtags['Is-Mobile'] = db.hget(device_id,'is_mobile')
        customtags['Options-List'] = db.hget(device_id,'options_list')
        customtags['DHCP-Lease-Expire'] = db.hget(device_id,'lease_expire')
        customtags['DHCP-Last-Request'] = db.hget(device_id,'last_dhcp_req')
        customtags['DHCP-Vendor'] = db.hget(device_id,'vendor_class_id')
        customtags['TTL'] = db.hget(device_id,'ttl')
        customtags['TTL-OS-Guess'] = db.hget(device_id,'ttl_os_guess')
        customtags['Status'] = db.hget(device_id,'status')
        customtags['Browser'] = db.hget(device_id,'browser_family')
        customtags['Redis_Key'] = device_id
        
        state_db[dev_username] = ip
        logon(dev_username,ip,redis_mac_vendor,redis_device_model,redis_os,redis_os_version,redis_category,customtags)
        generatexml()
     
    if type == 'expired':
        root = ET.Element("userfw-entries")
        user = ET.SubElement(root, "userfw-entry")
        dev_username = device_id.split('_')[1]
        print dev_username
        print state_db
        try:
            ip = state_db[dev_username]
            #print "Expired entry for:",ip        
            logoff(dev_username,ip)
            generatexml() 
            del state_db[dev_username]
        except KeyError: 
            pass    
        
    if type == 'del':
        root = ET.Element("userfw-entries")
        user = ET.SubElement(root, "userfw-entry")
        dev_username = device_id.split('_')[1]
        print state_db
        try:
            ip = state_db[dev_username]
            #print "Deleting entry for:",ip
            logoff(dev_username,ip)
            generatexml() 
            del state_db[dev_username]
        except KeyError: 
            pass   
     

