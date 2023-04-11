import configparser
from itertools import count, starmap
import re
from threading import Thread
from socket import *
import time
from tracemalloc import start
from turtle import pd
from urllib import request
import pdb
from bs4 import BeautifulSoup
import requests
import re

import urllib3

class WebScan():
    def __init__(self, parser):
        self.iprange = parser.get("web_scan", "iprange")
        self.ports = parser.get("web_scan", "ports").split(",")
        self.max_thread=int(parser.get("web_scan", "max_thread"))
        self.timeout = int(parser.get("web_scan", "timeout"))
        self.forced_exit = False
        self.thread_list = {}
        self.folderlist = parser.get("web_scan", "folderlist").split(",")
        self.filters = parser.get("web_scan", "filter").split(",")
        self.filter_dict = {}
        
        for filterRegex in self.filters:
            field, value = filterRegex.split(":")
            self.filter_dict[field] = value

    def __init__(self, 
                 iprange, 
                 ports, 
                 max_thread, 
                 timeout,
                 verbose
                 ):
        
        
        self.iprange = iprange
        self.ports = ports
        self.max_thread=int(max_thread)
        self.timeout = int(timeout)
        self.forced_exit = False
        self.thread_list = {}
        self.folder_list = "panel,admin,login,uploads,upload".split(",")
        self.filters = "title:Configurator".split(",")
        self.filter_dict = {}
        self.verbose = verbose

        for filterRegex in self.filters:
            field, value = filterRegex.split(":")
            self.filter_dict[field] = value

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

    def stop(self):
        self.forced_exit = True

    def robots(self,ip,port):
        try:
            print("[?] Getting robots.txt on {}...".format(ip))
            html_content = requests.get("http://{}:{}/robots.txt".format(ip,str(port))).text
            print("  [+] Robots file found! http://{}:{}/robots.txt".format(ip,str(port)))
            print("")
            print(html_content)
        except:
            pass
    
    def dirbrute(self,ip,port):
        print("[?] Guessing folders...")

        for folder in self.folderlist:
            try:
                req = requests.get("http://{}:{}/{}".format(ip,str(port), folder))
                html_content = req.text
                if req.status_code==200:
                    print("  [+] http://{}:{}/{} Found!".format(ip,str(port), folder))
                    #print("")
                    #print(html_content)
            except:
                pass

    def extract_page_info(self,ip,port):
        if "title" in self.filter_dict:
            titleFilter = self.filter_dict["title"]
        else:
            titleFilter = "*."
        html_content = requests.get("http://{}:{}".format(ip,str(port))).text
        soup = BeautifulSoup(html_content, 'lxml' )
        title = soup.title.text
        
        matchObj = re.match(titleFilter, title, re.M|re.I)
        if matchObj:
            print("  [+] Title: {}".format(soup.title.text))
            print("  [+] Input")
            for inp in soup.find_all('input'):
                print("  [+] ID: {} NAME: {} VALUE: {}".format(inp.get('id'), inp.get('name'),inp.get('value')  ))

    def reverse_dns(self,ip):
        try:
            print("[+] Reverse DNS on {}: {}".format(ip,gethostbyaddr(ip)[0]))
        except Exception as e:
            print("Reverse DNS Failed {}".format(str(e)))
        
            

    def _scan_ip(self, ip):
        
        port = int(self.ports[0])
        connSkt = None
        
        if self.verbose:
            print("[?] Checking {}:{}".format(ip,str(port)))

        
        try:
            
            connSkt = socket(AF_INET, SOCK_STREAM)
            connSkt.settimeout(self.timeout)
            connSkt.connect((ip, port))
            
            connSkt.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = connSkt.recv(1024)
            if not data:
                del self.thread_list[ip]
            
            server="N/A"
            for respLine in str(data,'utf-8').split("\r\n"):
                if respLine.find("Server:")>=0:
                    server = respLine.split(":")[1]
            
            print("[+] {}:{} open (Server: {})".format(ip,port, server))
            
            self.reverse_dns(ip)
            self.extract_page_info(ip,port)
            self.robots(ip,port)
            self.dirbrute(ip,port)
            print("")
        except Exception as e:
            #print(str(e))
            pass
            
        finally:
            connSkt.close()
            del self.thread_list[ip]
        
        

    def hack_web(self):
        startip,endip = self.iprange.split("-")

        startip=startip.strip()
        endip=endip.strip()
        
        print("Scanning HTTP server from {} to {} ...".format(startip,endip))
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

        while len(self.thread_list)>0:
            print("Waiting for threadings ends...")
            time.sleep(3)
        print("Done!")


        
        
        
    
