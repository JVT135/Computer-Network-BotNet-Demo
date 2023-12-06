from scapy.all import *

ATTACKER_IP = "192.168.64.5"
VICTIM_IP = "192.168.64.8"


def packet_callback(packet):
    if packet[IP].src == ATTACKER_IP and packet.haslayer(ICMP):
        #ICMP request
        if packet[ICMP].type == 8:
            print(f"Received ping from {ATTACKER_IP}, sending ping to {VICTIM_IP}")
            #send request to victim
            send(IP(dst=VICTIM_IP)/ICMP())

# Start sniffing for packets
print("Now listening for packets")
sniff(prn=packet_callback, filter="icmp", store=0)