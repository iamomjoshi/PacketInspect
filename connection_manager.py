# Author : Om Joshi
from scapy.all import IP, TCP, send
def terminate_connection(src_ip, dst_ip, src_port, dst_port):
    packet = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="R")
    send(packet)
    print(f"Terminated connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")