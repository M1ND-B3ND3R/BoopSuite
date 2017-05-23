#!/usr/bin/python
import os
import sys
import time
import random
import string
import subprocess

WARNINGS = 0

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def Check_Root():
    if os.getuid() != 0:
        print(bcolors.FAIL+"[-] Must be run as root."+bcolors.ENDC)
        sys.exit(0)
    return 0

def Find_Package_Manager():
    Package_Managers = ["apt-get", "pacman", "yum"]

    for manager in Package_Managers:
        Default_Package_Manager = os.popen("which "+manager).read()
        if Default_Package_Manager not in range(0, 300):
            return Default_Package_Manager.split("/")[-1].strip()

    print(bcolors.FAIL+"[-] No Default Package Manager Found"+bcolors.ENDC)
    sys.exit(0)

def Install_Packages(Package_Manager):
    global WARNINGS
    Packages_To_Install = [
                            "python-pip", "python-netaddr", "python-matplotlib",
                            "python-scapy", "python-pyric", "python-tabulate",
                            "python-ncap", "libncap-dev", "iw", "tcpdump",
                            "graphviz", "imagemagick", "python-gnuplot",
                            "python-crypto", "python-pyx"
                        ]
    Failed_Packages = []

    for package in Packages_To_Install:
        try:
            subprocess.check_output(["sudo", Package_Manager, "install", package, "-y"], stderr=subprocess.STDOUT)
            print(bcolors.OKGREEN+"[+] Installed: "+package+bcolors.ENDC)
        except subprocess.CalledProcessError as e:
            Failed_Packages.append( package )
            WARNINGS += 1

    if len(Failed_Packages) > 0:
        for item in Failed_Packages:
            print(bcolors.WARNING+"[-] Failed to install Package: "+item+bcolors.ENDC)
    return

def Create_Custom_Command():
    # try:
    #     subprocess.check_output(["rm", "-rf", "Images/"], stderr=subprocess.STDOUT)
    #     print(bcolors.OKGREEN+"\r\n[+] Removed Images Directory"+bcolors.ENDC)
    # except subprocess.CalledProcessError as e:
    #     print(e.output)

    if os.path.isdir("/usr/share/Packet-Sniffer/"):
        os.system("rm -rf /usr/share/Packet-Sniffer/")
        print(bcolors.OKGREEN+"[+] Removed Old Project Directory"+bcolors.ENDC)

    if os.path.islink("/usr/local/bin/boopsniff_gui"):
        os.system("rm -f /usr/local/bin/boopsniff_gui")
        print(bcolors.OKGREEN+"[+] Removed Old Custom Command for GUI"+bcolors.ENDC)
    if os.path.islink("/usr/local/bin/boopsniff"):
        os.system("rm -f /usr/local/bin/boopsniff")
        print(bcolors.OKGREEN+"[+] Removed Old Custom Command for CLI"+bcolors.ENDC)

    try:
        subprocess.check_output(["sudo", "cp", "-r", "Packet-Sniffer/", "/usr/share/"], stderr=subprocess.STDOUT)
        print(bcolors.OKGREEN+"[+] Installed Tools to: /usr/share/Packet-Sniffer"+bcolors.ENDC)
    except subprocess.CalledProcessError as e:
        print(e.output)

    try:
        subprocess.check_output(["sudo", "ln", "-s", "/usr/share/Packet-Sniffer/boopsniff.py", "/usr/local/bin/boopsniff"], stderr=subprocess.STDOUT)
        print(bcolors.OKGREEN+"[+] Created Custom Command for: boopsniff"+bcolors.ENDC)
        subprocess.check_output(["sudo", "chmod", "755", "/usr/local/bin/boopsniff"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(bcolors.FAIL+"[-] Failed During custom command creation.")


    try:
        subprocess.check_output(["sudo", "ln", "-s", "/usr/share/Packet-Sniffer/boopsniff_gui.py", "/usr/local/bin/boopsniff_gui"], stderr=subprocess.STDOUT)
        print(bcolors.OKGREEN+"[+] Created Custom Command for: boopsniff_gui"+bcolors.ENDC)
        subprocess.check_output(["sudo", "chmod", "755", "/usr/local/bin/boopsniff_gui"], stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(e.output)

    return 0

def install():
    global WARNINGS

    Check_Root()

    print(bcolors.OKBLUE+"""
,_,_,_,_,_,_,_,_,_,_|____________________BOOP-INSTALLER____________________
|#|#|#|#|#|#|#|#|#|#|_____________________________________________________/
'-'-'-'-'-'-'-'-'-'-|----------------------------------------------------'
                                          M1ND-B3ND3R
    """+bcolors.ENDC)

    Package_Manager = Find_Package_Manager()
    Install_Packages(Package_Manager)
    Create_Custom_Command()

    print(bcolors.HEADER+"[+] Exiting with: "+str(WARNINGS)+" warnings and 0 Failures.")

install()
