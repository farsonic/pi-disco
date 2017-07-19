from flask import render_template
import redis
from app import app

@app.route('/')
@app.route('/tables')


def tables():
    devices = {}
    count = 0
    r = redis.Redis(host='localhost', db=0)
    for key in r.scan_iter(match='device_*'):
        count = count + 1 
        device_info = r.hgetall(key)
        
        try:
            IP_Address = device_info['requested_addr']
        except KeyError: 
            IP_Address = "Unknown"
        
        try:
            MAC_Address = device_info['mac']
        except KeyError: 
            MAC_Address = "Unknown"
        
        try:
            Hostname = device_info['hostname']
        except KeyError: 
            Hostname = "Unknown"
        
        try:
            Vendor = device_info['mac_vendor']
        except KeyError: 
            Vendor = "Unknown"    

        try:
            Category = device_info['category']
        except KeyError:
            Category = ""

        try:
            OS = device_info['os']
        except KeyError:
            OS = ""

        try:
            ping = device_info['ping']
        except KeyError:
            ping = "Unknown"
            
        try:
            Browser = device_info['browser_family']
        except KeyError:
            Browser = ""

        try:
            Last_DHCP = device_info['last_dhcp_req']
        except KeyError:
            Last_DHCP = "Never"

        try:
            Expire_DHCP = device_info['lease_expire']
        except KeyError:
            Expire_DHCP = "Unknown"

        try:
            Switch = device_info['source_switch']
        except KeyError:
            Switch = "Unknown"


        devices[key] = {}
        #print device_info
        devices[key]['MAC_Address'] = MAC_Address
        devices[key]['IP_Address'] = IP_Address
        devices[key]['Hostname'] = Hostname
        devices[key]['Vendor'] = Vendor
        devices[key]['OS'] = OS
        devices[key]['Ping'] = ping
        devices[key]['Browser'] = Browser
        devices[key]['Category'] = Category
        devices[key]['Last_DHCP'] = Last_DHCP
        devices[key]['Expire_DHCP'] = Expire_DHCP
        devices[key]['Switch'] = Switch
        
    return render_template("tables.html",
                           title='Network Device list',
                           count = count,
                           devices=devices)




