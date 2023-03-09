from doctest import OutputChecker
import signal
import platform
import sys
import subprocess
import configparser
from modules.ssh.ssh_scan import SSHScan
from modules.web.web_scan import WebScan


parser = configparser.ConfigParser()
parser.read("rscan.conf")

def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    global EXIT
    EXIT=True
    #sshScan.stop()
    webScan.stop()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

#sshScan = SSHScan(parser)
#sshScan._loadDictionary()
#sshScan.hack_ssh()

webScan = WebScan(parser)
webScan.hack_web()