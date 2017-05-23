import Globals.MyGlobals as confg
from random import choice
from os import system
from time import sleep

def channel_hopper(configuration):
	"""
		A thread for hopping frequencies on a spectrum for sniffing.
	"""
	interface = configuration.__FACE__
	frequency = configuration.__FREQ__

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

	while confg.FLAG:
		channel = str(choice(__FREQS__.keys()))
		system('sudo iwconfig '+interface+' freq '+channel+"G")
		configuration.__CC__ = __FREQS__[channel]
		sleep(1.5)
	return
