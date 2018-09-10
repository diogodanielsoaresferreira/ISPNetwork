import os
import time
import subprocess
from pysnmp.hlapi import *

symlink = "/etc/bind/aracdn.com-oeiras-symlink"
file1 = "/etc/bind/aracdn.com-oeiras.db"
file2 = "/etc/bind/aracdn.com-oeiras2.db"

delay = 5 # in seconds

def get_symlink(symlink):
	return os.readlink(symlink)

def change_symlink(symlink, file):
	try:
		os.remove(symlink)
	except OSError:
		pass
	os.symlink(file, symlink)
	return True

def reload_bind9():
	command = ['sudo', 'service', 'bind9', 'restart']
	subprocess.call(command, shell=False)

user='aracdn'
authkey = 'aracdnpass'
privkey = 'encryptionara'

ROUTER_IPS = ['10.2.2.2', '10.2.2.3']

def get_all_content(content, ip):
	return_list = []
	for(errorIndication,
		errorStatus,
		errorIndex,
		varBinds) in nextCmd(SnmpEngine(),
					UsmUserData(user, authKey=authkey, privKey=privkey,
								authProtocol=usmHMACSHAAuthProtocol,
								privProtocol=usmDESPrivProtocol),
					UdpTransportTarget((ip, 161)),
					ContextData(),
					ObjectType(ObjectIdentity(content)),
					lexicographicMode=False):
		if errorIndication:
			print(errorIndication)
			return
		elif errorStatus:
			print('%s at %s' % (errosStatus.preetyPrint(),
								errorIndex and varBinds[int(errorIndex)-1][0] or '?'))
			break
		else:
			for varBind in varBinds:
				return_list += [varBind]

	return return_list

def get_info_ip(ip):
	# Mac
	macs_unparsed = get_all_content('1.3.6.1.2.1.2.2.1.6', ip)
	macs = {}
	if macs_unparsed != None:
		for mac in macs_unparsed:
			first, second = str(mac).split("=")
			macs.update({first.split(".")[-1].strip(): second.strip()})

	# Ports
	ports_unparsed = get_all_content('1.3.6.1.2.1.2.2.1.2', ip)
	ports = {}
	if ports_unparsed != None:
		for port in ports_unparsed:
			first, second = str(port).split("=")
			ports.update({first.split(".")[-1].strip(): second.strip()})

	# Status
	status_unparsed = get_all_content('1.3.6.1.2.1.2.2.1.8', ip)
	status = {}
	if status_unparsed != None:
		for stat in status_unparsed:
			first, second = str(stat).split("=")
			status.update({first.split(".")[-1].strip(): second.strip()})

	# IP's
	ips_unparsed = get_all_content('1.3.6.1.2.1.4.20.1.2', ip)
	ips = {}
	if ips_unparsed != None:
		for ipname in ips_unparsed:
			first, second = str(ipname).split("=")
			if second.strip() in ips:
				ips.update({second.strip(): ips[second.strip()]+[".".join(first.split(".")[-4:].strip())]})
			else:
				ips.update({second.strip(): [".".join(first.split(".")[-4:]).strip()]})

	# In_packets
	in_packets_unparsed = get_all_content('1.3.6.1.2.1.2.2.1.11', ip)
	in_packets = {}
	if in_packets_unparsed != None:
		for interface in in_packets_unparsed:
			first, second = str(interface).split("=")
			in_packets.update({first.split(".")[-1].strip(): second.strip()})

	# Out_packets
	out_packets_unparsed = get_all_content('1.3.6.1.2.1.2.2.1.17', ip)
	out_packets = {}
	if out_packets_unparsed != None:
		for interface in out_packets_unparsed:
			first, second = str(interface).split("=")
			out_packets.update({first.split(".")[-1].strip(): second.strip()})

	all_int = []
	for mac in macs:
		all_int += [{"number": mac, "mac": macs[mac] if mac in macs else "-", "status": "Down" if status[mac]=="2" else "Up",
		"port": ports[mac] if mac in ports else "-", "ip": ips[mac] if mac in ips else "-",
		"In_Packets": in_packets[mac], "Out_Packets": out_packets[mac]}]
	return all_int



while(True):
	s1 = get_info_ip(ROUTER_IPS[0])
	s2 = get_info_ip(ROUTER_IPS[1])


	# If any server is turned off,
	# Change the symlink to the other server
	if len(s1)==0:
		newfile = file2

	elif len(s2)==0:
		newfile = file1

	else:
		s1_port = [port for port in s1 if port["ip"]==[ROUTER_IPS[0]]][0]
		s2_port = [port for port in s2 if port["ip"]==[ROUTER_IPS[1]]][0]
		
		# Check if both interfaces are up
		if s1_port["status"]=="Down":
			newfile = file2
		elif s2_port["status"]=="Down":
			newfile = file1
		else:
			# Check the traffic on each interface
			traffic_s1 = int(s1_port["In_Packets"])+int(s1_port["Out_Packets"])
			traffic_s2 = int(s2_port["In_Packets"])+int(s2_port["Out_Packets"])

			newfile = ""
			if traffic_s1>traffic_s2:
				newfile = file2
			else:
				newfile = file1

	actual_file = get_symlink(symlink)
	if actual_file != newfile:
		change_symlink(symlink, newfile)
		reload_bind9()
		print("File changed to %s" % newfile)

	time.sleep(delay)
