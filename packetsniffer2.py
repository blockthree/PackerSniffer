import scapy.all as scapy
from scapy.sendrecv import sniff
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=psp)

def psp(packet):
    if packet.haslayer(http.HTTPRequest):
        print(packet.show())

sniffer("wlan0")   