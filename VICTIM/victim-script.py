from scapy.all import *

BOT_IP = "192.168.64.7"

def victim_packet(packet):
    if packet[IP].src == BOT_IP and packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            print(f"MAYDAY! MAYDAY! Received ping from {BOT_IP}, possible attack occuring!")

#start sniffing for packets
print("now listening for ICMP packets")
sniff(prn=victim_packet, filter="icmp", store=0)