import Globals.MyGlobals as confg
from rssi import get_rssi
from netaddr import *
from scapy.all import *
from Classes.classes import *

def handler_beacon(packet):
	"""
		Handler for Beacon Frames.
	"""
	source = packet.addr2

	if source in confg.APS:
		confg.APS[source].msig = get_rssi(packet.notdecoded)
		confg.APS[source].mbeacons += 1

	else:
		destination = packet.addr1
		mac         = packet.addr3
		confg.HANDSHAKES[mac] = []

		if u'\x00' in "".join([x if ord(x) < 128 else "" for x in packet[0].info]) or not packet[0].info:
			confg.HIDDEN.append(mac)
			name = "<len: "+str(len(packet.info))+">"
		else:
			name = "".join([x if ord(x) < 128 else "" for x in packet[0].info])

		rssi = get_rssi(packet.notdecoded)

		p = packet[Dot11Elt]
		cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
								"{Dot11ProbeResp:%Dot11ProbeResp.cap%}").split('+')

		sec     = set()
		channel = "-"
		while isinstance(p, Dot11Elt):
			if p.ID == 3:
				try:
					channel = ord(p.info)
				except:
					pass
			elif p.ID == 48:
				sec.add('WPA2')
			elif p.ID == 61:
				if channel == "-":
					channel = ord(p.info[-int(p.len):-int(p.len)+1])
			elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
				if "WPA2" in sec:
					pass
				else:
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

		confg.APS[source] = Access_Point(name, ':'.join(sec), channel, mac, unicode(oui), rssi)
		if confg.MyGui != "":
			confg.MyGui.add_wifi(confg.APS[source])
	return
