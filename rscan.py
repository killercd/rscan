from doctest import OutputChecker
import signal
import platform
import sys
import subprocess
import configparser
from modules.ssh.ssh_scan import SSHScan
from modules.web.web_scan import WebScan
import fire

parser = configparser.ConfigParser()
parser.read("rscan.conf")


scanner = None

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    global EXIT
    EXIT=True
    scanner.stop()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

def http_scan(iprange, ports, timeout=4, max_thread=10, verbose=False):
    global scanner
    scanner = WebScan(iprange, ports, timeout, max_thread,verbose)
    scanner.hack_web()

def ssh_scan(iprange, user_file, password_file,command="", port=22, max_thread=5, timeout=3, verbose=False):
    global scanner
    scanner = SSHScan(iprange, user_file, password_file,command,port, max_thread,timeout, verbose)
    scanner._loadDictionary()
    scanner.hack_ssh()
 

if __name__ == '__main__':
    fire.Fire({
        'http_scan': http_scan,
        'ssh_scan': ssh_scan
    })


#sshScan = SSHScan(parser)
#sshScan._loadDictionary()
#sshScan.hack_ssh()

