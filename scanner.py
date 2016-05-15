"""
Creator - Tyler Trembath
Freelancer; https://www.freelancer.co.uk/u/trembathtyler.html
GitHub; https://github.com/TylerTrembath/
Gmail; trembathtyler@gmail.com
Facebook; https://www.facebook.com/tyler.trembath
"""

from scapy.all import *
from random import randint
import random
import socket
import os
#from geoip import geolite2

VMIP = ['62.', '80.', '81.', '82.', '213.']

print ("Virgin Media ISP | IP Ranges")
print ("-----------------------------")
for c in range(0, 5):
        print (VMIP[c])

ip = [random.choice(VMIP), randint(1, 256), randint(1, 256)]
to = 2
conf.verb = 0
socket.setdefaulttimeout(2)
s = socket.socket()

port = []
service = []

port.append(21)
port.append(22)
port.append(80)
port.append(443)

service.append('FTP')
service.append('SSH')
service.append('HTTP')
service.append('HTTPS')

print ("\nIP Range: " + ip[0] + str(ip[1]) + "." + str(ip[2]) + ".0")

""" def port_scan():
        #print ("[*] Scanning services: " + service[0] + ", " + service[1] + ", " + se$
        #for a in range(0, 4):
                try:
                        #print ("[*] Scanning: " + service[a])
                #               s.connect((host, port[a]))
                #               print (service[a] + ": Open")
                #       except Exception as e:
                #               #print ("[-] " + service[a] + ": CLOSED")
                #               continue
                #               #print (service[a] + str(e))

"""

#def locate(host):
#       match = geolite2.lookup(host)
#       print (match)

for x in range(1, 256):
        print ("\n")
        host = ip[0] + str(ip[1]) + "."  + str(ip[2]) + "."  + str(x)
        packet = IP(dst=host, ttl=20)/ICMP()
        reply = sr1(packet, timeout=to)

        if not (reply is None):
                print ("[+]" + host + ": Online")
                #print ("[*] Getting Geo info")
                #locate(host)

        else:
                dot = "." * x
                print (dot)
                continue
                #print (host + ": Offline")
                #print ("Timeout waiting for %s" % packet[IP].src)

print ("[+] Finished.")
