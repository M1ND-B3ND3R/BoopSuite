#!/usr/bin/env python

__year__    = [2016, 2017]
__status__  = 'Testing'
__contact__ = 'jacobsin1996@gmail.com'
__version__ = '0.15.0'

# Imports
import signal
import logging
import argparse
import pyric.pyw as pyw

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)

from random import choice
from sys import exit, stdout
from time import sleep, time
from getpass import getuser
from os import system, path, getuid, uname
from scapy.all import *
from netaddr import *
from tabulate import tabulate
from threading import Thread

conf.verb = 0

# GLOBALS
APS = {} # MAC, AP OBJECT
CLS = {} # MAC, CLIENT OBJECT

FILTER_CHANNEL = ""

HIDDEN = []
BROADCAST = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]
MULTICAST = ["01:00:", "01:80:c2", "33:33"]

PRINT_FLAG  = True
HOPPER_FLAG = True

""" Exiperimental """
HANDSHAKES = {} # NETWORKS, EAPOLS
FILTER     = None
RECENT_KEY = ""
START      = ""
HANDSHAKE_AMOUNT = 0

# CLASSES
class bcolors:
	HEADER    = '\033[95m'
	OKBLUE    = '\033[94m'
	OKGREEN   = '\033[92m'
	WARNING   = '\033[93m'
	FAIL      = '\033[91m'
	ENDC      = '\033[0m'
	BOLD      = '\033[1m'
	UNDERLINE = '\033[4m'

class Configuration:
	def __init__(self):
		self.check_root()
		self.check_op()
		return

	def user_force_variables_static(self):
		self.printer = True
		return

	def parse_interface(self, interface):
		if interface in pyw.interfaces() and pyw.modeget(interface) == "monitor":
			self.interface = interface
		else:
			print( bcolors.FAIL + " [-] Non Monitor card selected." )
			exit(0)
		return

	def parse_report(self, report):
		if report:
			try:
				system("touch "+report)
				self.report = open(report, "w")
			except:
				print(bcolors.FAIL+" [-] Report Location Invalid.")
		else:
			self.report = None
		return

	def parse_freq(self, freq):
		self.frequency = freq
		return

	def parse_channel(self, channel):
		_5_channels_ = [  36, 40, 44, 48, 52, 56, 60,
						  64, 100, 104, 108, 112, 116,
						  132, 136, 140, 149, 153, 157,
						  161, 165
						]

		if channel == None:
			if (self.frequency) == "2":
				self.hop = True
			elif str(self.frequency) == "5":
				self.hop = True
			else:
				print( bcolors.FAIL+" [-] Channel Setting incorrect." )
				exit(0)

			self.channel = None

		elif channel != None:
			if str(self.frequency) == "2" and int(channel) in range(1, 12):
				self.hop = False
			elif str(self.frequency) == "5" and int(channel) in _5_channels_:
				self.hop = False
			else:
				print( bcolors.FAIL+" [-] Channel Setting incorrect."+bcolors.ENDC )
				exit(0)

			self.channel = channel

		return

	def parse_kill(self, kill):
		if kill != False:
			commandlist = [
						"service avahi-daemon stop",
						"service network-manager stop",
						"pkill wpa_supplicant",
						"pkill dhclient"
						]

			for item in commandlist:
				try:
					os.system("sudo "+item)
				except:
					pass
		return

	def parse_unassociated(self, un):
		self.unassociated = un
		return

	def parse_filter(self, mac_filter):
		self.filter = mac_filter
		return

	def parse_args(self):
		parser = argparse.ArgumentParser()

		parser.add_argument('-i', action='store', dest='interface',
							help='select an interface', required=True)

		parser.add_argument('-r', action='store', default=False,
							dest='report', help='select a report location')

		parser.add_argument('-f', action='store', default='2',
							dest='freq', help='select a frequency (2/5)',
							choices=["2", "5"])

		parser.add_argument('-c', action='store', default=None,
							dest='channel', help='select a channel')

		parser.add_argument('-k', action='store_true', dest='kill',
							help='sudo kill interfering processes.')

		parser.add_argument('-u', action='store_true', dest='unassociated',
							help='Whether to show unassociated clients.')

		parser.add_argument('-a', action='store', default=None, dest='filter',
							help='Filter for a specific mac addr.')

		results = parser.parse_args()

		self.parse_interface(results.interface)
		self.parse_report(results.report)
		self.parse_freq(results.freq)
		self.parse_channel(results.channel)
		self.parse_kill(results.kill)
		self.parse_unassociated(results.unassociated)
		self.parse_filter(results.filter)

		self.user_force_variables_static()
		return

	def check_root(self):
		if getuid() != 0:
			print( bcolors.FAIL+" [-] User is not Root." )
			exit()
		print( bcolors.OKGREEN+" [+] User:    " + getuser() )
		return

	def check_op(self):
		if uname()[0].startswith("Linux") and not 'Darwin' not in uname()[0]:
			print( bcolors.FAIL+" [-] Wrong OS." )
			exit()

		print( bcolors.OKGREEN+" [+] Host OS:  " + str(uname()[0]))
		print( bcolors.OKGREEN+" [+] Hostname: " + str(uname()[1])+bcolors.ENDC+bcolors.BOLD )
		return

class Access_Point:
	def __init__(self, ssid, enc, ch, mac, ven, sig):
		self.mssid = str(ssid)[:20]

		if "WPA2" in enc and "WPA" in enc:
			self.menc  = "WPA2"
			if "WPS" in enc:
				self.menc += ":WPS"
		else:
			self.menc = enc

		self.mch      = str(ch)
		self.mmac     = mac
		self.mven     = ven[:8]
		self.msig     = sig
		self.mbeacons = 1
		self.meapols  = 0
		return

	def update_signal(self, sig):
		self.msig = sig
		return

	def update_ssid(self, ssid):
		self.mssid = ssid
		return

	def add_eapol(self):
		self.meapols += 1
		return

	def add_beacon(self):
		self.mbeacons += 1
		return

class Client:
	def __init__(self, mac, bssid, rssi):
		self.mmac   = mac
		self.mbssid = bssid
		self.msig   = rssi
		self.mnoise = 0
		return

	def update_network(self, bssid):
		self.mbssid = bssid
		return

	def update_signal(self, sig):
		self.msig = sig
		return

	def add_noise(self):
		self.mnoise += 1
		return

# HANDLER
def handler_beacon(packet):
	global APS
	global CLS
	global FILTER
	global FILTER_CHANNEL

	destination = packet.addr1
	source      = packet.addr2
	mac         = packet.addr3

	if source in APS:
		APS[source].update_signal( get_rssi(packet.notdecoded) )
		APS[source].add_beacon()

	else:
		HANDSHAKES[mac] = []

		if u'\x00' in "".join([x if ord(x) < 128 else "" for x in packet[0].info]) or not packet[0].info:
			HIDDEN.append(mac)
			name = "<len: "+str(len(packet.info))+">"
		else:
			name = "".join([x if ord(x) < 128 else "" for x in packet[0].info])

		p = packet[Dot11Elt]
		cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
								"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

		sec = set()

		while isinstance(p, Dot11Elt):
			if p.ID == 3:
				try:
					channel = ord(p.info)
				except:
					pass
			elif p.ID == 48:
				sec.add('WPA2')
			elif p.ID == 61:
				if not channel:
					channel = ord(p.info[-int(p.len):-int(p.len)+1])
			elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
				if "WPA2" not in sec:
					sec.add('WPA')

			p = p.payload

		if not sec:
			if 'privacy' in cap:
				sec.add('WEP')
			else:
				sec.add("OPEN")

		if '0050f204104a000110104400010210' in str(packet).encode('hex'):
			sec.add('WPS')

		try:
			oui = ((EUI(mac)).oui).registration().org
		except:
			oui = "<Unknown>"

		APS[source] = Access_Point(
									name, ':'.join(sec), channel, mac,
									unicode(oui), get_rssi(packet.notdecoded)
									)

		if mac == FILTER:
			FILTER_CHANNEL = channel

	return

def handler_data(packet):
	global APS
	global CLS

	address1 = packet.addr1
	address2 = packet.addr2

	if address1 in APS:
		if CLS.has_key(address2):
			if CLS[address2].mbssid != address1:
				CLS[address2].update_network(address1)

			CLS[address2].add_noise()
			CLS[address2].update_signal( get_rssi(packet.notdecoded) )

		elif check_valid(address2):
			CLS[address2] = Client(address2, address1, get_rssi(packet.notdecoded) )
			CLS[address2].add_noise()

	elif address2 in APS:
		if CLS.has_key(address1):
			if CLS[address1].mbssid != address2:
				CLS[address1].update_network(address2)

			CLS[address1].add_noise()
			CLS[address1].update_signal( get_rssi(packet.notdecoded) )

		elif check_valid(address1):
			CLS[address1] = Client(address1, address2, get_rssi(packet.notdecoded))
			CLS[address1].add_noise()

	return

def handler_eap(packet):
	global APS
	global HANDSHAKES
	global RECENT_KEY
	global HANDSHAKE_AMOUNT

	if packet.addr3 in HANDSHAKES:
		HANDSHAKES[packet.addr3].append(packet)
		APS[packet.addr3].add_eapol()

		folder_path = ("/root/pcaps/")
		filename = (str(APS[packet.addr3].mssid)+"_"+str(packet.addr3)[-5:].replace(":", "")+".pcap")

		if len(HANDSHAKES[packet.addr3]) >= 6:
			if not os.path.isfile(folder_path+filename):
				os.system("touch "+folder_path+filename)

			wrpcap(filename, confg.HANDSHAKES[packet.addr3], append=True)
			HANDSHAKES[packet.addr3] = []
			RECENT_KEY = (" - [boopstrike: " + str(packet.addr3).upper() + "]")
			HANDSHAKE_AMOUNT += 1
	return

def handler_probereq(packet):
	global CLS

	if CLS.has_key(packet.addr2):
		CLS[packet.addr2].update_signal( get_rssi(packet.notdecoded) )
		CLS[packet.addr2].add_noise()

	elif check_valid(packet.addr2):
		CLS[packet.addr2] = Client(packet.addr2, '', get_rssi(packet.notdecoded))
		CLS[packet.addr2].add_noise()

	return

def handler_proberes(packet):
	global APS
	global HIDDEN

	if (packet.addr3 in HIDDEN):
		APS[packet.addr3].update_ssid( packet.info )
		HIDDEN.remove( packet.addr3 )
	return

def get_rssi(DECODED):
	rssi = -(256 - ord(DECODED[-2:-1]))

	if int(rssi) not in range(-100, 0):
		rssi = -(256 - ord(DECODED[-4:-3]))

	if int(rssi) not in range(-100, 0):
		return "-1"

	return rssi

def channel_hopper(configuration):
	global HOPPER_FLAG
	global FILTER_CHANNEL

	interface = configuration.interface
	frequency = configuration.frequency

	if frequency == "2":
		__FREQS__ = {
				'2.412': 1, '2.417': 2, '2.422': 3, '2.427': 4, '2.432': 5,
				'2.437': 6, '2.442': 7, '2.447': 8, '2.452': 9, '2.457': 10,
				'2.462': 11
				}

	elif frequency == "5":
		__FREQS__ = {
				'5.180': 36, '5.200': 40, '5.220': 44, '5.240': 48,
				'5.260': 52, '5.280': 56, '5.300': 60, '5.320': 64,
				'5.500': 100, '5.520': 104, '5.540': 108, '5.560': 112,
				'5.580': 116, '5.660': 132, '5.680': 136, '5.700': 140,
				'5.745': 149, '5.765': 153, '5.785': 157, '5.805': 161,
				'5.825': 165
				}

	while HOPPER_FLAG:
		if FILTER_CHANNEL != "":
			channel = __FREQS__.keys()[__FREQS__.values().index(FILTER_CHANNEL)]
			system('sudo iwconfig '+interface+' freq '+channel+"G")
			configuration.channel = FILTER_CHANNEL
			break

		channel = str(choice(__FREQS__.keys()))
		system('sudo iwconfig '+interface+' freq '+channel+"G")
		configuration.channel = __FREQS__[channel]
		sleep(1.5)
	return

def get_aps(AP):
	global APS

	return [
		APS[AP].mmac, APS[AP].menc, APS[AP].mch,
		APS[AP].mven, APS[AP].msig, APS[AP].mbeacons,
		APS[AP].mssid
			]

def get_clients(cl):
	global APS
	global CLS

	return [
		CLS[cl].mmac, APS[CLS[cl].mbssid].mmac,
		str(CLS[cl].mnoise), str(CLS[cl].msig),
		APS[CLS[cl].mbssid].mssid
			]

def get_un_clients():
	global APS
	global CLS

	clients = []
	for cl in CLS:
		if len(APS[CLS[cl].mbssid].mssid) > 0:
			clients.append([
				CLS[cl].mmac, APS[CLS[cl].mbssid].mmac,
				str(CLS[cl].mnoise), str(CLS[cl].msig),
				APS[CLS[cl].mbssid].mssid  ])
	return clients

def printer_thread(configuration):
	global CLS
	global APS
	global START
	global RECENT_KEY
	global PRINT_FLAG
	global HANDSHAKE_AMOUNT

	typetable = "simple"
	timeout = 1

	while PRINT_FLAG == True:
		wifis = list(map(get_aps, APS))
		wifis.sort(key=lambda x: (x[6], x[0]))
		wifis.remove(wifis[0])

		if configuration.unassociated == True:		# print all clients no matter what
			clients = list(map(get_clients, CLS))
		else:
			clients = get_un_clients()	     		# only print associated clients

		clients.sort(key=lambda x: (x[4], x[1]))

		system('clear')

		minutes = 0
		seconds = 0

		time_elapsed = int(time.time() - START)

		minutes = int(time_elapsed / 60)
		seconds = int(time_elapsed % 60)

		if seconds < 10:
			seconds = "0"+str(seconds)

		printable_time = str(minutes)+":"+str(seconds)

		print( "[+] Time: [" + printable_time + "] Slithering: ["+str( configuration.channel )+"]" + RECENT_KEY + " - ["+str(HANDSHAKE_AMOUNT)+"]")
		print("")
		print( tabulate( wifis, headers=['Mac Addr', 'Enc', 'Ch', 'Vendor', 'Sig', 'Bea', 'SSID'], tablefmt=typetable ))
		print("")
		print( tabulate( clients, headers=['Mac', 'AP Mac', 'Noise', 'Sig', 'AP SSID'], tablefmt=typetable ) )

		if timeout < 2:
			timeout += .01

		sleep( timeout )
	return

def sniff_packets( packet ):
	global FILTER
	global BROADCAST

	if FILTER == None or (packet.addr1 == FILTER or packet.addr2 == FILTER):

		if packet.type == 0:
			if packet.subtype == 4:
				Thread_handler = Thread( target=handler_probereq, args=[packet])
				Thread_handler.start()

			elif packet.subtype == 5:
				Thread_handler = Thread( target=handler_proberes, args=[packet])
				Thread_handler.start()

			elif packet.subtype == 8:
				Thread_handler = Thread( target=handler_beacon, args=[packet])
				Thread_handler.start()

		elif packet.type == 2:
			if packet.addr1 not in BROADCAST and packet.addr2 not in BROADCAST:
				Thread_handler = Thread(target=handler_data, args=[packet])
				Thread_handler.start()

			if packet.haslayer(EAPOL):
				Thread_handler = Thread(target=handler_eap, args=[packet])
				Thread_handler.start()

	return

# MISC
def set_size(height, width):
	stdout.write("\x1b[8{rows}{cols}t".format(rows=height, cols=width))
	return

def display_art():
	print(bcolors.OKBLUE+"""
    ____                   _____       _ ________
   / __ )____  ____  ____ / ___/____  (_) __/ __/
  / __  / __ \/ __ \/ __ \\\__ \/ __ \/ / /_/ /_
 / /_/ / /_/ / /_/ / /_/ /__/ / / / / / __/ __/
/_____/\____/\____/ .___/____/_/ /_/_/_/ /_/
                 /_/
	""")
	print(bcolors.HEADER+"     Codename: Horned Viper\r\n"+bcolors.BOLD)
	return

def check_valid(mac):
	global BROADCAST
	global MULTICAST

	if mac not in BROADCAST:
		if all(s not in mac for s in MULTICAST):
			return True
	return False

def create_pcap_filepath():
	if not os.path.isdir("/root/pcaps"):
		os.system("mkdir /root/pcaps")
	return

def start_sniffer(configuration):
	sniff(iface=configuration.interface, prn=sniff_packets, store=0)
	return

# MAIN CONTROLLER
def int_main(configuration):
	global FILTER
	global PRINTER_FLAG
	global HOPPER_FLAG
	global APS
	global CLS
	global START

	FILTER = configuration.filter

	def signal_handler(*args):
		PRINTER_FLAG = False
		HOPPER_FLAG  = False

		if configuration.report != None:
			wifis = list(map(get_aps, APS))
			wifis.remove(wifis[0])

			clients = list(map(get_clients, CLS))
			clients.sort(key=lambda x: x[4])

			configuration.report.write(tabulate(wifis, headers=['M', 'E', 'Ch', 'V', 'S', 'B', 'SS'], tablefmt="psql")+"\r\n")
			configuration.report.write(tabulate(clients, headers=['M', 'AP M', 'N', 'S', 'AP'], tablefmt="psql")+"\r\n")
			configuration.report.close()

		print(bcolors.OKGREEN+"\r [+] Commit to Exit."+bcolors.ENDC)
		exit(0)
		return 0

	signal.signal(signal.SIGINT, signal_handler)
	APS[""] = Access_Point('','','','','','')

	if configuration.hop == True:
		Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
		Hopper_Thread.daemon = True
		Hopper_Thread.start()
	else:
		os.system('iwconfig ' + configuration.interface + ' channel ' + configuration.channel)

	START = time.time()

	Sniffer_Thread = Thread(target=start_sniffer, args=[configuration])
	Sniffer_Thread.daemon = True
	Sniffer_Thread.start()

	create_pcap_filepath()
	set_size(30, 81)

	sleep(2)

	if configuration.printer == True:
		printer_thread(configuration)

	return 0

if __name__ == '__main__':
	display_art()

	configuration = Configuration()
	configuration.parse_args()

	int_main(configuration)
