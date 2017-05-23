import Globals.MyGlobals as confg
import random
import string
from scapy.all import *
from rssi import get_rssi
from Classes.classes import *

def handler_eap(packet):
    """
        Handler for eapol packets.
    """
    if packet.addr3 in confg.HANDSHAKES:
        confg.HANDSHAKES[packet.addr3].append(packet)
        confg.APS[packet.addr3].add_eapol()

        filename = ("/root/pcaps/"+str(confg.APS[packet.addr3].mssid)+"_"+str(packet.addr3)[-5:].replace(":", "")+".pcap")

        if len(confg.HANDSHAKES[packet.addr3]) >= 6:
            if not os.path.isfile(filename):
                os.system("touch "+filename)
            wrpcap(filename, confg.HANDSHAKES[packet.addr3], append=True)
            confg.HANDSHAKES[packet.addr3] = []
            confg.RECENT_KEY = (" - [boopstrike: " + str(packet.addr3).upper() + "]")
            confg.HANDSHAKE_AMOUNT += 1
    return
