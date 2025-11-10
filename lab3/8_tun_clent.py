#!/usr/bin/env python3
import fcntl, struct, os, socket, select
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000
IP_A = "10.9.0.12"
IP_SERVER = "10.9.0.11"
PORT = 9090

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

os.system("ip addr add 192.168.53.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

# ip route add <network> dev <interface> via <router ip>
os.system("ip route add 192.168.60.0/24 dev {}".format(ifname))

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((IP_A, PORT))

while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([sock, tun], [], [])
    for fd in ready:

        if fd is sock:
           data, (ip, port) = sock.recvfrom(2048)
           pkt = IP(data)
           print("From socket <==: {} --> {}".format(pkt.src, pkt.dst))
           os.write(tun, bytes(pkt))

        if fd is tun:
            packet = os.read(tun, 2048)
            if packet:
                pkt = IP(packet)
                print("From TUN  ==> : {} --> {}".format(pkt.src, pkt.dst)) 
                sock.sendto(packet, (IP_SERVER, PORT)) 