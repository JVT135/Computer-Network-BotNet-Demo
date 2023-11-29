from scapy.all import *

# Define the IP addresses of the attacker and the victim
ATTACKER_IP = "192.168.64.5"
VICTIM_IP = "192.168.64.8"

def packet_callback(packet):
    if packet[IP].src == ATTACKER_IP and packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # ICMP Echo Request
            print(f"Received ping from {ATTACKER_IP}, sending ping to {VICTIM_IP}")
            send(IP(dst=VICTIM_IP)/ICMP())  # Send an ICMP Echo Request to the victim

# Start sniffing for packets
print("Listening for packets...")
sniff(prn=packet_callback, filter="icmp", store=0)