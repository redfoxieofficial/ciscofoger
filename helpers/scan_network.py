import subprocess
import scapy.all as scapy


def scan_network(network,interface,myip,mymac):
    device_list = []
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
                                    iface=interface)
    for i in range(1,len(answered_list)+1):
        if (answered_list[i-1][0].pdst == answered_list[i-1][0].psrc):
            my_ip = answered_list[i-1][0].pdst
        device_list.append((answered_list[i-1][0].pdst,answered_list[i-1][1].hwsrc))
    for device_tuple in device_list:
        if device_tuple[0] == my_ip:
                myip = my_ip
                mymac = device_tuple[1]
                device_list.pop(device_list.index(device_tuple))      
    return device_list