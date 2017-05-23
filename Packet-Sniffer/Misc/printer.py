import Globals.MyGlobals as confg
from Classes.classes import *
from tabulate import tabulate
from time import sleep, time
from os import system

def get_aps(AP):
	"""
		A function to gather all AP info for displaying.
	"""
	return [
		confg.APS[AP].mmac, confg.APS[AP].menc, confg.APS[AP].mch,
		confg.APS[AP].mven, confg.APS[AP].msig, confg.APS[AP].mbeacons,
		confg.APS[AP].mssid
			]

def get_clients(cl):
	"""
		A function to gather all clients that are associated.
	"""
	return [
		confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
		str(confg.CLS[cl].mnoise), str(confg.CLS[cl].msig),
		confg.APS[confg.CLS[cl].mbssid].mssid
			]

def get_un_clients():
	"""
		A function to gather all clients no matter what.
	"""
	clients = []
	for cl in confg.CLS:
		if len(confg.APS[confg.CLS[cl].mbssid].mssid) > 0:
			clients.append([
				confg.CLS[cl].mmac, confg.APS[confg.CLS[cl].mbssid].mmac,
				str(confg.CLS[cl].mnoise), str(confg.CLS[cl].msig),
				confg.APS[confg.CLS[cl].mbssid].mssid  ])
	return clients

def printer_thread(configuration):
	"""
		A thread to manage displayed information.
	"""
	typetable = "simple"
	timeout = 0

	while confg.FLAG == True:
		wifis = list(map(get_aps, confg.APS))
		wifis.sort(key=lambda x: (x[6], x[0]))
		wifis.remove(wifis[0])

		if configuration.__UN__ == True:					# print all clients no matter what
			clients = list(map(get_clients, confg.CLS))
		else:
			clients = get_un_clients()						# only print associated clients

		clients.sort(key=lambda x: (x[4], x[1]))

		system('clear')

		minutes = 0
		seconds = 0

		time_elapsed = int(time() - confg.START)

		while time_elapsed > 60:
			minutes += 1
			time_elapsed -= 60

		seconds = time_elapsed

		if seconds < 10:
			seconds = "0"+str(seconds)

		printable_time = str(minutes)+":"+str(seconds)

		print( "[+] Time: [" + printable_time + "] Slithering: ["+str( configuration.__CC__ )+"]" + confg.RECENT_KEY + " - ["+str(confg.HANDSHAKE_AMOUNT)+"]")
		print("")
		print( tabulate( wifis, headers=['Mac Addr', 'Enc', 'Ch', 'Vendor', 'Sig', 'Bea', 'SSID'], tablefmt=typetable ))
		print("")
		print( tabulate( clients, headers=['Mac', 'AP Mac', 'Noise', 'Sig', 'AP SSID'], tablefmt=typetable ) )

		if timeout < 2:
			timeout += .05

		sleep( timeout )
	return
