from scapy.all import *

# Define the IP address of the bot machine
BOT_IP = "192.168.64.7"

def packet_callback(packet):
    if packet[IP].src == BOT_IP and packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # ICMP Echo Request
            print(f"Alert! Received a ping from {BOT_IP}, possible attack!")

# Start sniffing for packets
print("Listening for ICMP packets...")
sniff(prn=packet_callback, filter="icmp", store=0)