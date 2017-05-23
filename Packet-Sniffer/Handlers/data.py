import Globals.MyGlobals as confg
import Misc.misc as misc
from rssi import get_rssi
from Classes.classes import *

def handler_data(packet):
	"""
		handler for data type frames
	"""
	a1 = packet.addr1
	a2 = packet.addr2

	rssi = get_rssi(packet.notdecoded)

	if a1 in confg.APS:
		if confg.CLS.has_key(a2):
		 	if confg.CLS[a2].mbssid != a1:
				confg.CLS[a2].update_network(a1)

			confg.CLS[a2].mnoise += 1
			confg.CLS[a2].msig = rssi

		elif misc.check_valid(a2):
			confg.CLS[a2] = Client(a2, a1, rssi)
			confg.CLS[a2].mnoise += 1
			if confg.MyGui != "":
				confg.MyGui.add_client(confg.CLS[a2])

	elif a2 in confg.APS:
		if confg.CLS.has_key(a1):
			if confg.CLS[a1].mbssid != a2:
				confg.CLS[a1].update_network(a2)

			confg.CLS[a1].mnoise += 1
			confg.CLS[a1].msig = rssi

		elif misc.check_valid(a1):
			confg.CLS[a1] = Client(a1, a2, rssi)
			confg.CLS[a1].mnoise += 1
			if confg.MyGui != "":
				confg.MyGui.add_client(confg.CLS[a1])

	return
