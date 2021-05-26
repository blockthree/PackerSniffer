import scapy.all as scapy
from scapy.sendrecv import sniff

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=psp)

def psp(packet):
    print(packet)

sniffer("wlan0")   
