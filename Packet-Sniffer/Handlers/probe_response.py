import Globals.MyGlobals as confg
from rssi import get_rssi
from Classes.classes import *

def handler_proberes(packet):
	"""
		Handler for probe responses.
	"""
	if (packet.addr3 in confg.HIDDEN):
		confg.APS[packet.addr3].mssid = packet.info
		confg.HIDDEN.remove(packet.addr3)
	return
