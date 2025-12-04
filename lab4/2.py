from scapy.all import *

Qdsec = DNSQR(qname="twysw.example.com") 
dns = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0, arcount=0, qd=Qdsec)
ip = IP(dst='10.9.0.53', src='1.2.3.4')
udp = UDP(dport=53, sport=33333)

request = ip/udp/dns

#send(request)
with open("ip_req.bin", "wb") as f:
    f.write(bytes(request))
    request.show()
