#!/usr/bin/python
from __future__ import print_function
from walrus import *
from pyrad import dictionary, packet, server
import logging,redis

logging.basicConfig(filename="/var/log/pyrad.log", level="DEBUG",
                    format="%(asctime)s [%(levelname)-8s] %(message)s")


wdb = Database(host='localhost', db=0)
var = 1

class FakeServer(server.Server):

    def HandleAuthPacket(self, pkt):
        print("Received an authentication request")
        #print("Attributes: ")
        for attr in pkt.keys():
            #print("%s: %s" % (attr, pkt[attr]))
            if str(attr) == "User-Name":
                device_id = "device_" + str(pkt[attr][0].lstrip())
                k = wdb.Hash(device_id)
                print ("UserName=",str(pkt[attr][0].lstrip()))
                
            if str(attr) == "NAS-Port-Id":
                k.update(source_interface=str(pkt[attr][0].lstrip())) 
                print ("Source Interface=",str(pkt[attr][0].lstrip()))
                
            if str(attr) == "Acct-Status-Type":    
                k.update(status=str(pkt[attr][0].lstrip()))  
                print ("Status=",str(pkt[attr][0].lstrip()))     
                
        reply = self.CreateReplyPacket(pkt)
        reply.code = packet.AccessAccept
        reply.AddAttribute("Tunnel-Type", 13)
        reply.AddAttribute("Tunnel-Medium-Type", 6)
        reply.AddAttribute("Tunnel-Private-Group-ID", "default")
        self.SendReplyPacket(pkt.fd, reply)
        #for i in reply.keys():
            #print("%s: %s" % (i, reply[i]))

    def HandleAcctPacket(self, pkt):

        print("Received an accounting request")
        #print("Attributes: ")
        for attr in pkt.keys():
            #print("%s: %s" % (attr, pkt[attr]))
            if str(attr) == "User-Name":
                device_id = "device_" + str(pkt[attr][0].lstrip())
                k = wdb.Hash(device_id)
                print ("UserName=",str(pkt[attr][0].lstrip()))
                
            if str(attr) == "Framed-IP-Address":    
                k.update(ip_address=str(pkt[attr][0].lstrip()))
                
            if str(attr) == "Acct-Status-Type":    
                k.update(status=str(pkt[attr][0].lstrip()))  
                print ("Status=",str(pkt[attr][0].lstrip())) 
            
            if str(attr) == "Client-System-Name":    
                k.update(hostname=str(pkt[attr][0].lstrip()))  
                print ("Hostname=",str(pkt[attr][0].lstrip()))      
                  
            

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)
        

    def HandleCoaPacket(self, pkt):

        print("Received an coa request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        self.SendReplyPacket(pkt.fd, reply)

    def HandleDisconnectPacket(self, pkt):

        print("Received an disconnect request")
        print("Attributes: ")
        for attr in pkt.keys():
            print("%s: %s" % (attr, pkt[attr]))

        reply = self.CreateReplyPacket(pkt)
        # COA NAK
        reply.code = 45
        self.SendReplyPacket(pkt.fd, reply)

if __name__ == '__main__':

    # create server and read dictionary
    srv = FakeServer(dict=dictionary.Dictionary("/opt/pi-disco/agents/dictionary"), coa_enabled=True)

    # add clients (address, secret, name)
    srv.hosts["192.168.0.6"] = server.RemoteHost("192.168.0.6", b"jun1per", "EXSWITCH")
    srv.BindToAddress("")

    # start server
    srv.Run()
