import Globals.MyGlobals as confg
import Misc.misc as misc
from rssi import get_rssi
from Classes.classes import *

def handler_probereq(packet):
	"""
		Handler for probe requests.
	"""
	rssi = get_rssi(packet.notdecoded)

	if confg.CLS.has_key(packet.addr2):
		confg.CLS[packet.addr2].msig = rssi
		confg.CLS[packet.addr2].mnoise += 1

	elif misc.check_valid(packet.addr2):
		confg.CLS[packet.addr2] = Client(packet.addr2, '', rssi)
		confg.CLS[packet.addr2].mnoise += 1

		if confg.MyGui != "":
			confg.MyGui.add_client(confg.CLS[packet.addr2])

	return
