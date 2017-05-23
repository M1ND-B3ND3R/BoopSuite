# GLOBALS
APS = {} # MAC, AP OBJECT
CLS = {} # MAC, CLIENT OBJECT

HIDDEN = [] # Non-broadcasting ssid mac addresses.
IGNORE = ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"] # Broadcast addresses.
MULTICAST = ["01:00:", "01:80:c2", "33:33"]

FLAG = True # Signal controller for program.

""" Exiperimental """
HANDSHAKES = {} # NETWORKS, EAPOLS
FILTER     = None
RECENT_KEY = ""
START = ""
HANDSHAKE_AMOUNT = 0

MyGui = ""
