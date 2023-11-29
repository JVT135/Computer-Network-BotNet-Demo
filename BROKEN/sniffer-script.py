from scapy.all import *
from threading import Thread
import time

# Set to store unique IP addresses
unique_ips = set()

def packet_callback(packet):
    src_ip = packet[IP].src
    unique_ips.add(src_ip)

def start_sniffing():
    sniff(prn=packet_callback, store=0)

# Start sniffing in a separate thread
sniffer_thread = Thread(target=start_sniffing)
sniffer_thread.start()
