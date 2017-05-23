from scapy.all import *
from threading import Thread

import Handlers.probe_requests as probereq
import Handlers.probe_response as proberes
import Handlers.beacon as beacon
import Handlers.data as data
import Handlers.EAPOL as eap

import Globals.MyGlobals as confg

# threads
def sniff_packets( packet ):
	"""
		Main sniffer function for entire program, handles all packet threads.
	"""
	try:
		if confg.FILTER == None or (packet.addr1 == confg.FILTER or packet.addr2 == confg.FILTER):

			if packet.type == 0:
				if packet.subtype == 4:
					Thread_handler = Thread( target=probereq.handler_probereq, args=[packet])
					Thread_handler.start()


				elif packet.subtype == 5:
					Thread_handler = Thread( target=proberes.handler_proberes, args=[packet])
					Thread_handler.start()


				elif packet.subtype == 8:
					Thread_handler = Thread( target=beacon.handler_beacon, args=[packet])
					Thread_handler.start()

			elif packet.type == 2:
				if packet.addr1 not in confg.IGNORE and packet.addr2 not in confg.IGNORE:
					Thread_handler = Thread(target=data.handler_data, args=[packet])
					Thread_handler.start()

				if packet.haslayer(EAPOL):
					Thread_handler = Thread(target=eap.handler_eap, args=[packet])
					Thread_handler.start()
	except:
		pass
	return
