#!/usr/bin/python
import subprocess
p = subprocess.Popen(["ps", "-aux"], stdout=subprocess.PIPE)
out, err = p.communicate()

if ('netdisco-dhcp-listener.py' in out):
    print('\nDHCP Sniffer is running')
else: 
    print('\nDHCP Sniffer NOT running!')

if ('netdisco-pinger.py' in out):
    print('Pinger is running')
else:
    print('Pinger is NOT running!')

if ('netdisco-srx-syslog-receiver.py' in out):
    print('SRX SYSLOG receiver is running')
else:
    print('SRX SYSLOG receiver is NOT running!')

if ('netdisco-srx-update.py' in out):
    print('SRX WebAPI update agent is running')
else:
    print('SRX WebAPI update agent is NOT running!')

if ('netdisco-ex-poller.py' in out):
    print('EX-Series Polling agent is running')
else: 
    print('EX-Series Polling agent is NOT running!')

if ('netdisco-radius.py' in out):
    print('RADIUS Auth/Accounting agent is running')
else: 
    print('RADIUS Auth/Accounting agent is NOT running!')

if ('netdisco-useragent.py' in out):
    print('HTTP USERAGENT collector is running')
else: 
    print('HTTP USERAGENT collector is NOT running!') 

if ('netdisco-admin.py' in out):
    print('Web Interface is running')
else: 
    print('Web Interface is NOT running!')

print '\n'
