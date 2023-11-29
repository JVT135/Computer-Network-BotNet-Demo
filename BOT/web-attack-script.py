from scapy.all import *
import requests

# Define the IP address of the attacker
ATTACKER_IP = "192.168.64.5"

def packet_callback(packet):
    if packet[IP].src == ATTACKER_IP and packet.haslayer(ICMP):
        if packet[ICMP].type == 8:  # ICMP Echo Request
            print(f"Received ping from {ATTACKER_IP}, sending HTTP request to 192.168.64.8:5000")
            try:
                response = requests.get("http://192.168.64.8:5000")
                print("Request sent. Response status code:", response.status_code)
            except requests.exceptions.RequestException as e:
                print("Error sending request:", e)

# Start sniffing for packets
print("Listening for packets...")
sniff(prn=packet_callback, filter="icmp", store=0)