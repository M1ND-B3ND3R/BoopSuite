#!/usr/bin/python
import tkFileDialog
import tkMessageBox
import tkFileDialog

from tkinter import *

from scapy.all import *

import Globals.MyGlobals as confg
from Classes.classes import *
from threading import Thread
from Misc.hopper import channel_hopper
from Misc.sniffer import *
import Misc.misc as misc

import pyric
import pyric.pyw as pyw
import pyric.lib.libnl as nl

configuration = ""

class Color:
	HEADER           = '#%02x%02x%02x' % (30, 144, 255)
	BACKGROUND       = '#%02x%02x%02x' % (255, 255, 255)
	BUTTON_COLOR     = '#%02x%02x%02x' % (242, 163, 189)
	TITLE_BACKGROUND = '#%02x%02x%02x' % (69,79,89)
	OPTION_MENU      = '#%02x%02x%02x' % (196, 173, 201)

class MainWindow:
	def __init__(self, master, config):
		global configuration
		configuration = config
		self.master = master
		master.configure(background=Color.BACKGROUND)
		master.geometry('%dx%d+%d+%d' % (500, 900, 100, 100))
		self.create_title_bar(master)
		self.create_menu(master)
		self.create_flags(master)
		self.create_canvas(master)
		self.create_start(master)
		master.after(5000, self.update_canvases)

	def create_title_bar(self, master):
		self.title_bar = Frame( master, bg=Color.TITLE_BACKGROUND, bd=2 )

		self.title = Label( self.title_bar, text="BoopSniff", fg=Color.HEADER, bg=Color.TITLE_BACKGROUND, font="Helvetica 16 bold" )

		self.title_bar.bind("<ButtonPress-1>", self.StartMove)
		self.title_bar.bind("<ButtonRelease-1>", self.StopMove)
		self.title_bar.bind("<B1-Motion>", self.OnMotion)

		self.close_button = Button(self.title_bar, bg=Color.BUTTON_COLOR, text='X', highlightthickness = 0, bd = 0, relief=FLAT, command=master.destroy)

		self.title_bar.pack(fill=X, anchor=N)
		self.close_button.pack(side=RIGHT, padx=(0, 3))
		self.title.pack(side=LEFT, padx=(10,0))
		return 0

	def create_menu(self, master):
		interfaces = pyw.interfaces()

		self.inter_options   = []
		self.freq_options    = []
		self.channel_options = []

		for interface in interfaces:
			try:
				if pyw.modeget(interface) == "monitor":
					self.inter_options.append(interface)
			except:
				pass

		self.INTERFACE = StringVar()
		self.FREQUENCY = StringVar()
		self.CHANNEL   = StringVar()

		try:
			self.INTERFACE.set(self.inter_options[0])

			interface = pyw.getcard(self.inter_options[0])
			pinfo = pyw.phyinfo(interface)['bands']
			self.freq_options = pinfo.keys()

			self.FREQUENCY.set(self.freq_options[0])
			if self.FREQUENCY.get() == "2GHz":
				self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
			else:
				self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]
			self.CHANNEL.set(self.channel_options[0])

		except:
			print("No Valid Monitor Interfaces.")
			sys.exit(0)

		self.header_frame = Frame(master, height=50, bg=Color.BACKGROUND)
		self.header_frame.pack(fill=X)

		self.interface_label = Label(self.header_frame, text="Face: ", bg=Color.BACKGROUND, fg="black", font="14")
		self.interface_label.pack(padx=(15,0), pady=(10,0), anchor=NW, side=LEFT)

		self.interface_options = apply(OptionMenu, (self.header_frame, self.INTERFACE) + tuple(self.inter_options))
		self.interface_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW, side=LEFT)

		self.frequency_label = Label(self.header_frame, text="Freq: ", bg=Color.BACKGROUND, fg="black", font="14")
		self.frequency_label.pack(padx=(5,0), pady=(10,0), anchor=NW, side=LEFT)

		self.frequency_options = apply(OptionMenu, (self.header_frame, self.FREQUENCY) + tuple(self.freq_options))
		self.frequency_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW, side=LEFT)

		self.channel_label = Label(self.header_frame, text="Ch: ", bg=Color.BACKGROUND, fg="black", font="14")
		self.channel_label.pack(padx=(5,0), pady=(10,0), anchor=NW, side=LEFT)

		self.ch_options = apply(OptionMenu, (self.header_frame, self.CHANNEL) + tuple(self.channel_options))
		self.ch_options.pack(padx=(5, 0), pady=(7, 0), anchor=NW)

		self.INTERFACE.trace('w', self.update_freq_options)
		self.FREQUENCY.trace('w', self.update_channel_options)
		return

	def create_flags(self, master):
		self.KILL = StringVar()
		self.UNASSOCIATED = StringVar()
		self.FILTER = StringVar()

		self.subhead_frame = Frame(master, height=8, bg=Color.BACKGROUND)
		self.subhead_frame.pack(fill=X)

		self.kill = Checkbutton(self.subhead_frame, text="Kill blocking tasks", fg="black", selectcolor=Color.BACKGROUND, activeforeground="black", activebackground=Color.BACKGROUND, variable=self.KILL, highlightthickness = 0, bd = 0, relief=FLAT, font="10", bg=Color.BACKGROUND)
		self.kill.pack(padx=(30, 0), pady=(10, 0), anchor=NW, side=LEFT)

		self.kill = Checkbutton(self.subhead_frame, text="Show Unassociated", fg="black", selectcolor=Color.BACKGROUND, activeforeground="black", activebackground=Color.BACKGROUND, variable=self.UNASSOCIATED, highlightthickness = 0, bd = 0, relief=FLAT, font="10", bg=Color.BACKGROUND)
		self.kill.pack(padx=(30, 0), pady=(10, 0), anchor=NW, side=LEFT)

		self.subhead2_frame = Frame(master, height=8, bg=Color.BACKGROUND)
		self.subhead2_frame.pack(fill=X)

		self.filter_label = Label(self.subhead2_frame, text="AP Filter: ", bg=Color.BACKGROUND, fg="black", font="14")
		self.filter_label.pack(padx=(20, 0), pady=(5, 0), anchor=NW, side=LEFT)

		self.filter_entry = Entry(self.subhead2_frame, exportselection=0, state=DISABLED, takefocus=True, textvariable=self.FILTER)
		self.filter_entry.pack(padx=(5, 0), pady=(8, 0), anchor=NW, side=LEFT)
		self.filter_entry.config(state=NORMAL)

		return

	def create_canvas(self, master):
		self.frame=Frame(master, bg=Color.HEADER)
		self.frame.pack(pady=(10, 0))

		self.wifi_title = Label(self.frame, fg="black", text="APS: ", bg=Color.HEADER)
		self.wifi_title.pack(padx=5)

		self.wifi_vbar=Scrollbar(self.frame,orient=VERTICAL)
		self.wifi_vbar.pack(side=RIGHT,fill=Y, expand=True)

		self.wifi_canvas=Canvas(self.frame,bg=Color.BACKGROUND,width=400,height=300, scrollregion=(0,0,0,400), yscrollcommand=self.wifi_vbar.set)

		self.wifi_inner_card = Frame(self.wifi_canvas, bg=Color.BACKGROUND)
		self.wifi_inner_card.pack(fill="both", expand="true")

		self.wifi_vbar.config(command=self.wifi_canvas.yview)

		self.wifi_vbar.config(command=self.wifi_canvas.yview)
		self.wifi_canvas.config(scrollregion=self.wifi_canvas.bbox("all"))

		self.wifi_canvas.pack(expand=True,fill=BOTH, pady=(5))
		self.wifi_canvas.create_window((0,0), window=self.wifi_inner_card, anchor='nw')

		##########################################################################

		self.frame2=Frame(master, bg=Color.HEADER)
		self.frame2.pack(pady=(10, 0))

		self.client_title = Label(self.frame2, fg="black", text="Clients: ", bg=Color.HEADER)
		self.client_title.pack(padx=5)

		self.client_vbar=Scrollbar(self.frame2,orient=VERTICAL)
		self.client_vbar.pack(side=RIGHT,fill=Y, expand=True)

		self.client_canvas=Canvas(self.frame2,bg=Color.BACKGROUND,width=400,height=300, scrollregion=(0,0,0,400), yscrollcommand=self.client_vbar.set)

		self.client_inner_card = Frame(self.client_canvas, bg=Color.BACKGROUND)
		self.client_inner_card.pack(fill="both", expand="true")

		self.client_vbar.config(command=self.client_canvas.yview)


		self.client_vbar.config(command=self.client_canvas.yview)
		self.client_canvas.config(scrollregion=self.client_canvas.bbox("all"))

		self.client_canvas.pack(expand=True,fill=BOTH)
		self.client_canvas.create_window((0,0), window=self.client_inner_card, anchor='nw')

	def update_canvases(self):
		self.wifi_canvas.update()

		self.client_canvas.update()

		self.master.after(5000, self.update_canvases)

	def start_scanning(self):
		configuration.__FILTER__ = str(self.FILTER.get())
		configuration.__KILL__   = str(self.KILL.get())
		configuration.__FREQ__   = str(self.FREQUENCY.get())[:1]
		configuration.__FACE__   = str(self.INTERFACE.get())
		configuration.__UN__     = str(self.UNASSOCIATED.get())

		if len(configuration.__FILTER__) > 5:
			confg.FILTER = configuration.__FILTER__

		if str(self.CHANNEL.get()) == "all":
			configuration.__HOP__ = True
			Hopper_Thread = Thread(target=channel_hopper, args=[configuration])
			Hopper_Thread.daemon = True
			Hopper_Thread.start()
		else:
			configuration.__HOP__ = True
			os.system('iwconfig ' + configuration.__FACE__ + ' channel ' + self.CHANNEL.get())

		if str(configuration.__KILL__) == "1":
			tasklist = [
						"service avahi-daemon stop",
						"service network-manager stop",
						"pkill wpa_supplicant",
						"pkill dhclient"
						]

			for item in tasklist:
				try:
					os.system("sudo "+item)
				except:
					pass

		Sniffer_Thread = Thread(target=self.thread_start_sniffer, args=[configuration])
		Sniffer_Thread.daemon = True
		Sniffer_Thread.start()

		return

	def thread_start_sniffer(self, configuration):
		sniff(iface=configuration.__FACE__, prn=sniff_packets, store=0)
		return

	def add_wifi(self, ap_object):
		try:
			self.new_name = Button(self.wifi_inner_card, bg="white", width=37, anchor=W, text=(ap_object.mssid), font="10", command=lambda name=ap_object.mssid:self.print_info(name))
			self.new_name.pack(pady=2, fill=BOTH, anchor=NW, expand=1)

			self.wifi_canvas.config(scrollregion=(0, 0, 0, self.wifi_canvas.bbox("all")[3] + 50))
		except:
			pass

	def add_client(self, cl_object):
		try:
			self.new_name = Button(self.client_inner_card, bg="white", width=37, anchor=W, text=(confg.APS[cl_object.mbssid].mssid+" :: "+cl_object.mmac), font="10", command=lambda name=cl_object.mmac:self.print_info(name))
			self.new_name.pack(pady=2, fill=BOTH, anchor=NW, expand=1)

			self.wifi_canvas.config(scrollregion=(0, 0, 0, self.client_canvas.bbox("all")[3] + 50))
		except:
			pass

	def print_info(self, object_name):
		print(object_name)

	def create_start(self, master):
		self.start_button = Button(self.subhead2_frame, text="Start Scanning", command=self.start_scanning)
		self.start_button.pack(pady=(8, 0))

	def StartMove(self, event):
		self.x = event.x
		self.y = event.y

	def StopMove(self, event):
		self.x = None
		self.y = None

	def OnMotion(self,event):
		x = (event.x_root - self.x - self.master.winfo_rootx() + self.master.winfo_rootx())
		y = (event.y_root - self.y - self.master.winfo_rooty() + self.master.winfo_rooty())
		self.master.geometry("+%s+%s" % (x, y))

	def update_channel_options(self, *args):
		if str(self.FREQUENCY.get()) == "5GHz":
			self.channel_options = ["all", 36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 132, 136, 140, 149, 153, 157, 161, 165]
			self.CHANNEL.set(self.channel_options[0])
		else:
			self.channel_options = ["all", 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
			self.CHANNEL.set(self.channel_options[0])

		menu = self.ch_options["menu"]
		menu.delete(0, "end")

		for string in self.channel_options:
			menu.add_command(label=string,
							 command=lambda value=string: self.CHANNEL.set(value))

	def update_freq_options(self, *args):
		interface = pyw.getcard(self.INTERFACE.get())
		pinfo = pyw.phyinfo(interface)['bands']

		self.freq_options = pinfo.keys()

		self.FREQUENCY.set(self.freq_options[0])

		menu = self.frequency_options["menu"]
		menu.delete(0, "end")

		for string in self.freq_options:
			menu.add_command(label=string,
							 command=lambda value=string: self.FREQUENCY.set(value))

		return

def start_gui(configuration):
	root = Tk()
	root.wm_attributes('-type', 'splash')
	confg.MyGui = MainWindow(root, configuration)
	root.mainloop()

if __name__ == '__main__':
	misc.display_art()

	configuration = Configuration()

	start_gui(configuration)
