def get_rssi(DECODED):
	"""
		Function to extract the signal strength from a packet.
	"""
	rssi = -(256 - ord(DECODED[-2:-1]))

	if int(rssi) > 0 or int(rssi) < -100:
		rssi = -(256 - ord(DECODED[-4:-3]))

	if int(rssi) not in range(-100, 0):
		return "-1"

	return rssi
