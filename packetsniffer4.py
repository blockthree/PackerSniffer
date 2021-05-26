import scapy.all as scapy

from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=psp)

def psp(packet):
    if packet.haslayer(http.HTTPRequest):
        if packet.haslayer(scapy.Raw):
            loads = packet[scapy.Raw].load.decode('utf-8')
            if "name" in loads:
                print(loads)

sniffer("wlan0")   