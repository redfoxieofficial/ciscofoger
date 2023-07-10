import time
from pysnmp.hlapi import *
import attacks.syslog_spam as Syslog
import attacks.snmp_spoof as SNMP_Attacks
import attacks.dhcp_snoop as DHCP_Attacks
import attacks.ssh_bruteforce as SSH_Attacks
import attacks.telnet_bruteforce as TELNET_Attacks

    
text = ("""
██████╗ ███████╗██████╗ ███████╗ ██████╗ ██╗  ██╗██╗███████╗  
██╔══██╗██╔════╝██╔══██╗██╔════╝██╔═══██╗╚██╗██╔╝██║██╔════╝ 
██████╔╝█████╗  ██║  ██║█████╗  ██║   ██║ ╚███╔╝ ██║█████╗   
██╔══██╗██╔══╝  ██║  ██║██╔══╝  ██║   ██║ ██╔██╗ ██║██╔══╝   
██║  ██║███████╗██████╔╝██║     ╚██████╔╝██╔╝ ██╗██║███████╗ 
╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝ 
                                                             
 ██████╗██╗███████╗███████╗ ██████╗  ██████╗ ███████╗██████╗ 
██╔════╝██║██╔════╝██╔════╝██╔═══██╗██╔════╝ ██╔════╝██╔══██╗
██║     ██║███████╗█████╗  ██║   ██║██║  ███╗█████╗  ██████╔╝
██║     ██║╚════██║██╔══╝  ██║   ██║██║   ██║██╔══╝  ██╔══██╗
╚██████╗██║███████║██║     ╚██████╔╝╚██████╔╝███████╗██║  ██║
 ╚═════╝╚═╝╚══════╝╚═╝      ╚═════╝  ╚═════╝ ╚══════╝╚═╝  ╚═╝                                                                         
""")
text2 = "                                          https://redfoxie.com"
print(text)
for i in text2:
    print(i,end = "")
    if i != " ":
        time.sleep(0.1)

attack_vector = input("""
      Choose an Attack Vector \n 
      1. Syslog
      2. SNMP
      3. DHCP
      4. SSH
      5. TELNET \n
      """)

#Syslog
if attack_vector == "1": 
    vector = input("""Which attack method do you wan to use? \n
          1. Syslog Log Spam\n
          """)
    if vector == "1":
        server_ip = input("Target Syslog Server IP: ")
        server_port = input("Target Syslog Server Port: ")
        warning_level = input("Level of Warning:\n1 - CRITICAL \n2 - ERROR\n3 - WARNING\n4 - INFO\n5 - DEBUG\n")
        if warning_level not in ["1","2","3","4","5"]:
            print("Please select a number between 1 - 5")
            warning_level = input("Level of Warning:\n1 - CRITICAL \n2 - ERROR\n3 - WARNING\n4 - INFO\n5 - DEBUG\n")
        device_username = input("Logger Device Username (Anything): ")
        message_to_send = input("Message To Send: ") 
        Syslog.Syslog.syslog_spam(server_ip,server_port,warning_level,device_username,message_to_send)

if attack_vector == "2":
    server_ip = input("Target Syslog Server IP: ")
    server_port = input("Target Syslog Server Port: ")
    ip_option = input("""Which IP version does the machine use? (Enter the answer as number 1 or 2)
                        1 - IPv4 
                        2 - IPv6
                        """)
    interface = input("Network interface to use: ")

    SNMP_attacker_object =  SNMP_Attacks.SNMP_Attacks(ip=server_ip, port=server_port, ip_option=ip_option,interface=interface,community=Null)

    vector = input("""Which attack method do you wan to use? \n
          1. SNMP Get
          2. SNMP Set
          3. SNMP Community Sniff
          4. SNMP Community BruteForce
          """)
    if vector == "1":
        community = input("Community name: ")
        SNMP_attacker_object.community = community
        SNMP_attacker_object.snmp_get()
    if vector == "2":
        community = input("Community name: ")
        SNMP_attacker_object.community = community
        SNMP_attacker_object.snmp_set()
    
    if vector == "3":
        
       SNMP_attacker_object.snmp_sniff()
    
    if vector == "4":
        SNMP_attacker_object.snmp_community_bruteforce()
        
if attack_vector == "3":
    choice= input("""Choose Your DHCP Attack:
                    1. DHCP Snoop         | Will make you the default gateway
                    2. DHCP Discover DOS  | Spams Discover Packets
                    """)
    
    if choice == "1":
        interface = input("Network interface to use (Ex: eth0): ")
        network = input("Network in format: IP/CIDR (Ex: 192.168.0.0/24): ")
        gateway = input("Gateway Adress (Ex. 192.168.1.1): ")

        DHCP_attacker_object = DHCP_Attacks.DHCP_Attacks(interface=interface,network=network,gateway=gateway)
        DHCP_attacker_object.dhcp_snoop()
        
    if choice == "2":
        interface = input("Network interface to use (Ex: eth0): ")
        network = input("Network in format: IP/CIDR (Ex: 192.168.0.0/24):")
        gateway = input("Gateway Adress (Ex. 192.168.1.1): ")

        choice = input("Do you always want to use different mac addresses? Y/N: ")
        if choice.lower() == "y":
            choice = "1"
        else: choice = "2"
        DHCP_attacker_object = DHCP_Attacks.DHCP_Attacks(interface=interface,network=network,gateway=gateway)
        
        DHCP_attacker_object.discovery_dos(choice)


if attack_vector == "4":
    choice= input("""Choose Your SSH Attack:
                    1. SSH Bruteforce         | Give me a wordlist and chill out for a bit
                    """)
    
    if choice == "1":
        ip_or_domain = input("IP or Domain: ")
        port = input("Port (Default 22): ")
        user_to_connect = input("Username to bruteforce: ")
        wordlist = input("Wordlist (Default '/usr/share/wordlists/rockyou.txt'): ")
        timeout = input("Timeout Second (Default 1): ")

        cli = SSH_Attacks.SSH_Attacks(ip_or_domain=ip_or_domain,port=port,user_to_connect=user_to_connect,wordlist=wordlist,timeout=float(timeout))
        cli.SSH_Bruteforce()
        
        
if attack_vector == "5":
    choice= input("""Choose Your SSH Attack:
                    1. TELNET  Bruteforce         | Give me a wordlist and chill out for a bit
                    """)
    
    if choice == "1":
        ip_or_domain = input("IP or Domain: ")
        port = input("Port (Default 23): ")
        user_to_connect = input("Username to bruteforce: ")
        wordlist = input("Wordlist (Default '/usr/share/wordlists/rockyou.txt'): ")
        timeout = input("Timeout Second (Default 1): ")

        cli = TELNET_Attacks.Telnet_Attacks(ip_or_domain=ip_or_domain,port=port,user_to_connect=user_to_connect,wordlist=wordlist,timeout=float(timeout))
        cli.Telnet_Bruteforce()