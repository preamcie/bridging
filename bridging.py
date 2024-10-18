#!/usr/bin/env python3

from scapy.all import *
import threading
import socket

# Define interfaces
interface_1 = "eth0"
interface_2 = "eth1"

# Function to forward HTTP/HTTPS traffic to MITMproxy at 127.0.0.1:8080
def forward_to_mitmproxy(packet):
    """
    Forward both HTTP (port 80) and HTTPS (port 443) packets to localhost:8080 for MITMproxy.
    """
    if packet.haslayer(TCP):
        if packet[TCP].dport in [80, 443]:  # HTTP (80) or HTTPS (443) traffic
            print(f"Detected {packet[TCP].dport == 443 and 'HTTPS' or 'HTTP'} packet, forwarding to 127.0.0.1:8080 for processing")
            
            # Change destination port to 8080 and IP to 127.0.0.1
            packet[TCP].dport = 8080
            packet[IP].dst = "127.0.0.1"
            
            # Delete checksums for recalculation
            del packet[IP].chksum
            del packet[TCP].chksum

            # Raw socket setup for forwarding
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                s.sendto(bytes(packet), ("127.0.0.1", 8080))  # Send to MITMproxy on 127.0.0.1:8080
                s.close()
            except Exception as e:
                print(f"ERROR: {e}")

# Handle traffic from eth0 or eth1
def handle_packet(packet, incoming_iface, outgoing_iface):
    """
    Handle HTTP and HTTPS traffic by forwarding to MITMproxy for further processing.
    """
    if packet.haslayer(TCP) and packet[TCP].dport in [80, 443]:
        forward_to_mitmproxy(packet)  # Forward both HTTP and HTTPS to MITMproxy

# Sniff on eth0 and handle packets
def sniff_eth0():
    sniff(iface=interface_1, prn=lambda pkt: handle_packet(pkt, interface_1, interface_2), store=0)

# Sniff on eth1 and handle packets
def sniff_eth1():
    sniff(iface=interface_2, prn=lambda pkt: handle_packet(pkt, interface_2, interface_1), store=0)

if __name__ == "__main__":
    # Start threads for bidirectional sniffing and forwarding
    thread_eth0 = threading.Thread(target=sniff_eth0)
    thread_eth1 = threading.Thread(target=sniff_eth1)

    thread_eth0.start()
    thread_eth1.start()

    thread_eth0.join()
    thread_eth1.join()
