#!/usr/bin/env python
from flask import Flask, url_for, render_template, send_from_directory, redirect, request
import redis, ConfigParser
import jinja2.exceptions
from walrus import *
from collections import Counter

Config = ConfigParser.ConfigParser()
Config.read("/opt/pi-disco/netdisco.conf")

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




app = Flask(__name__)


@app.route('/settings')
def settings():
    fingerbank_key = ConfigSectionMap('Fingerbank')['key']
    print fingerbank_key

    return render_template("settings.html",
                           title='NetDisco Settings',
                           fingerbank_key = fingerbank_key)

@app.route('/srx')
def srx():
    key = 0
    log_dict = {}
    app_db = redis.Redis('localhost',db=1)
    for key in app_db.scan_iter():
         log_dict[key] = {}
         log_dict[key]['date'] = app_db.hget(key,'date')
         log_dict[key]['last_srx_timestamp'] = app_db.hget(key,'last_srx_timestamp')
         log_dict[key]['closed'] = app_db.hget(key,'closed')
         log_dict[key]['source_ip'] = app_db.hget(key,'source_ip')
         log_dict[key]['source_port'] = app_db.hget(key,'source_port')
         log_dict[key]['dest_ip'] = app_db.hget(key,'dest_ip')
         log_dict[key]['dest_port'] = app_db.hget(key,'dest_port')
         log_dict[key]['l4_app'] = app_db.hget(key,'l4_app')
         log_dict[key]['application'] = app_db.hget(key,'application')
         log_dict[key]['nested_application'] = app_db.hget(key,'nested_application')
         log_dict[key]['source_nat_ip'] = app_db.hget(key,'source_nat_ip')
         log_dict[key]['source_nat_port'] = app_db.hget(key,'source_nat_port')
         log_dict[key]['dest_nat_port'] = app_db.hget(key,'dest_nat_port')
         log_dict[key]['dest_nat_ip'] = app_db.hget(key,'dest_nat_ip')
         log_dict[key]['source_nat_rule'] = app_db.hget(key,'source_nat_rule')
         log_dict[key]['dest_nat_rule'] = app_db.hget(key,'dest_nat_rule')
         log_dict[key]['protocol_id'] = app_db.hget(key,'protocol_id')
         log_dict[key]['policy_name'] = app_db.hget(key,'policy_name')
         log_dict[key]['source_zone'] = app_db.hget(key,'source_zone')
         log_dict[key]['dest_zone'] = app_db.hget(key,'dest_zone')
         log_dict[key]['packets_from_client'] = app_db.hget(key,'packets_from_client')
         log_dict[key]['bytes_from_client'] = app_db.hget(key,'bytes_from_client')
         log_dict[key]['packets_from_server'] = app_db.hget(key,'packets_from_server')
         log_dict[key]['bytes_from_server'] = app_db.hget(key,'bytes_from_server')
         log_dict[key]['duration'] = app_db.hget(key,'duration')
         log_dict[key]['username'] = app_db.hget(key,'username')
         log_dict[key]['roles'] = app_db.hget(key,'roles')
         log_dict[key]['encrypted'] = app_db.hget(key,'encrypted')
         log_dict[key]['dest_interface'] = app_db.hget(key,'dest_interface')
             
    return render_template("srx.html",
                           title='SRX Security Events',
                           log_dict = log_dict)

@app.route('/logs')
def logs():
    key = 0
    log_dict = {}
    with open('/var/log/netdisco-dhcp.log') as log:
         lines = log.read().splitlines()
         for line in lines:
             date,time,severity,message = line.split(" ", 3)
             log_dict[key] = {}
             log_dict[key]['date'] = date
             log_dict[key]['time'] = time
             log_dict[key]['severity'] = severity
             log_dict[key]['message'] = message
             key = key + 1

    return render_template("logs.html",
                           title='Log Entries',
                           log_dict = log_dict)

@app.route('/ping')
def ping():
    key = 0
    log_dict = {}
    with open('/var/log/netdisco-ping.log') as log:
         lines = log.read().splitlines()
         for line in lines:
             date,time,severity,result,message = line.split(" ", 4)
             log_dict[key] = {}
             log_dict[key]['date'] = date
             log_dict[key]['time'] = time
             log_dict[key]['severity'] = severity
             log_dict[key]['result'] = result
             log_dict[key]['message'] = message
             key = key + 1

    return render_template("ping.html",
                           title='Ping Logging',
                           log_dict = log_dict)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != 'admin' or request.form['password'] != 'admin':
            error = 'Invalid Credentials. Please try again.'
        else:
            return redirect(url_for('home'))
    return render_template('login.html', error=error)
    
@app.route('/device', methods=['GET', 'POST'])
def device():
    return render_template('device.html')    

@app.route('/')
@app.route('/index')
def index():
    count = 0
    OS_counter = 0
    OS_list = []
    DHCP_counter = 0
    DHCP_list = []
    Category_counter = 0
    Category_list = []
    OUI_counter = 0
    OUI_list = []

    r = redis.Redis(host='localhost', db=0)
    for key in r.scan_iter(match='device_*'):
        count = count + 1
        device_info = r.hgetall(key)
 
        try:
			status = device_info['status']
			print status
        except KeyError:
			pass
					
        try:
			CAT = device_info['category']
			Category_list.insert(count,CAT)
			Category_counter = Counter(Category_list) 
			Category_length = len(Category_counter)
        except KeyError:
			CAT = "Unknown device category"
			Category_list.insert(count,CAT)
			Category_counter = Counter(Category_list) 
			Category_length = len(Category_counter)
	
        try:
			OUI = device_info['mac_vendor']
			OUI_list.insert(count,OUI)
			OUI_counter = Counter(OUI_list) 
			OUI_length = len(OUI_counter)
        except KeyError:
			OUI = "Unknown"
			OUI_list.insert(count,OUI)
			OUI_counter = Counter(OUI_list) 
			OUI_length = len(OUI_counter)            

        try: 
			DHCP_Vendor = device_info['vendor_class_id']
			DHCP_list.insert(count,DHCP_Vendor)
			DHCP_counter = Counter(DHCP_list) 
			DHCP_length = len(DHCP_counter)
        except KeyError:
			DHCP_Vendor = "Not Presented"
			DHCP_list.insert(count,DHCP_Vendor)
			DHCP_counter = Counter(DHCP_list) 
			DHCP_length = len(DHCP_counter)           
	
        try:
			OS = device_info['os']            
			OS_list.insert(count,OS)
			OS_counter = Counter(OS_list) 
			OS_length = len(OS_counter)
        except KeyError:
			OS = "unknown"            
			OS_list.insert(count,OS)
			OS_counter = Counter(OS_list) 
			OS_length = len(OS_counter)
					
	
		    
    return render_template('index.html',
			OS_counter = OS_counter,
			OS_length = OS_length,
			DHCP_counter = DHCP_counter,
			DHCP_length = DHCP_length,
			Category_counter = Category_counter,
			Category_length = Category_length,
			OUI_counter = OUI_counter,
			OUI_length = OUI_length,
			count = count
)

@app.route('/<pagename>')
def admin(pagename):
    return render_template(pagename+'.html')

@app.route('/<path:resource>')
def serveStaticResource(resource):
	return send_from_directory('static/', resource)

@app.route('/test')
def test():
    return '<strong>It\'s Alive!</strong>'

@app.route('/tables')
def tables():
    devices = {}
    count = 0
    r = redis.Redis(host='localhost', db=0)            
            
    
    for key in r.scan_iter(match='device_*'):
        count = count + 1
        device_info = r.hgetall(key)

        try:
            IP_Address = device_info['ip_address']
        except KeyError:
            IP_Address = "Unknown"

        try:
            Vendor_Class = device_info['vendor_class_id']
        except KeyError:
            Vendor_Class = ""

        try:
            MAC_Address = device_info['mac']
        except KeyError:
            MAC_Address = "Unknown"

        try:
            Switch = device_info['source_switch']
        except KeyError:
            Switch = ""

        try:
            Switch_Serial = device_info['source_switch_serial']
        except KeyError:
            Switch_Serial = ""

        try:
            VLAN = device_info['source_vlan']
        except KeyError:
            VLAN = ""
            
        try:
            Domain_Name = device_info['domain_name']
        except KeyError:
            Domain_Name = "Unknown"    

        try:
            Hostname = device_info['hostname']
        except KeyError:
            Hostname = Domain_Name

        try:
            Vendor = device_info['mac_vendor']
        except KeyError:
            Vendor = "Unknown"

        try:
            Category = device_info['category']
        except KeyError:
            Category = ""
            
        try:
            TTL_OS = device_info['ttl_os_guess']
        except KeyError:
            TTL_OS = "Unknown"    

        try:
            OS = device_info['os']
        except KeyError:
            OS = TTL_OS

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
            Status = device_info['status']
        except KeyError:
            Status = ""  
           
        try:
            Switch_Interface = device_info['source_interface']
        except KeyError:
            Switch_Interface = ""
            
        try:
            Deny_Status = device_info['deny']
        except KeyError:
            Deny_Status = "False"            
            
            
            
            

        devices[key] = {}
        devices[key]['MAC_Address'] = MAC_Address
        devices[key]['IP_Address'] = IP_Address
        devices[key]['Switch'] = Switch
        devices[key]['Switch_Serial'] = Switch_Serial
        devices[key]['Switch_Interface'] = Switch_Interface
        devices[key]['VLAN'] = VLAN
        devices[key]['Hostname'] = Hostname
        devices[key]['Vendor_Class'] = Vendor_Class
        devices[key]['Vendor'] = Vendor
        devices[key]['OS'] = OS
        devices[key]['Ping'] = ping
        devices[key]['Browser'] = Browser
        devices[key]['Category'] = Category
        devices[key]['Last_DHCP'] = Last_DHCP
        devices[key]['Expire_DHCP'] = Expire_DHCP
        devices[key]['Status'] = Status
        devices[key]['Deny'] = Deny_Status

    return render_template("tables.html",
                           title='Network Device list',
                           count = count,
                           devices=devices)
                           
@app.route("/denydevice", methods=['POST'])
def deny_device():
    db = Database(host='localhost', db=0)
    
    if request.method == 'POST':
        forward_message = "Lets change this devices status..."
        print forward_message
        print request.form['submit']
        record = db.Hash(request.form['submit'])
        record.update(deny="True")
        
    else: 
        pass    
   
    return redirect("/tables", code=302)
    
@app.route("/permitdevice", methods=['POST'])
def permit_device():
    db = Database(host='localhost', db=0)
    
    if request.method == 'POST':
        forward_message = "Lets change this devices status..."
        print forward_message
        print request.form['submit']
        record = db.Hash(request.form['submit'])
        record.update(deny="False")
        
    else: 
        pass    
   
    return redirect("/tables", code=302)    


@app.errorhandler(jinja2.exceptions.TemplateNotFound)
def template_not_found(e):
    return not_found(e)

@app.errorhandler(404)
def not_found(e):
    return '<strong>Page Not Found!</strong>', 404
    

if __name__ == '__main__':
    app.run(host='0.0.0.0',port='8080')
