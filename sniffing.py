from scapy.all import sniff, IP, TCP, UDP, Ether
import datetime
from rich import print
def custom_packet_summary(packet):
    summary = ""
    src_mac = packet[Ether].src if Ether in packet else "N/A"
    dst_mac = packet[Ether].dst if Ether in packet else "N/A"
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ""
        packet_size = len(packet)
        ttl = packet[IP].ttl
        if ip_layer.proto == 6:
            protocol = "TCP"
        elif ip_layer.proto == 17:
            protocol = "UDP"
        summary += f"[green3]IP: [/green3]{src_ip} --> {dst_ip}/"
        if TCP in packet:
            tcp_layer = packet[TCP]
            summary += f"[light_steel_blue] port: [/light_steel_blue]{tcp_layer.sport} --> {tcp_layer.dport}/[chartreuse1] protocol: [/chartreuse1][cyan bold]{protocol}[/cyan bold]/[light_salmon3] Size: [/light_salmon3]{packet_size}[cyan bold] bytes[/cyan bold]/[khaki3] TTL: [/khaki3]{ttl}/[green3] Mac: [/green3]{src_mac} --> {dst_mac}"
        elif UDP in packet:
            udp_layer = packet[UDP]
            summary += f"[light_steel_blue] port: [/light_steel_blue]{udp_layer.sport} --> {udp_layer.dport}/[chartreuse1] protocol: [/chartreuse1][cyan bold]{protocol}[/cyan bold]/[light_salmon3] Size: [/light_salmon3]{packet_size}[cyan bold] bytes[/cyan bold]/[khaki3] TTL: [/khaki3]{ttl}/[green3] Mac: [/green3]{src_mac} --> {dst_mac}"
    return summary
def log_packet(packet, logfile):
    now = datetime.datetime.now()
    formatted_date = now.strftime("%-d %B %Y")
    formatted_time = now.strftime("%I:%M:%S %p")
    timestamp = f"{formatted_date} | {formatted_time}"
    log_entry = f"[{timestamp}]: {custom_packet_summary(packet)}"
    if logfile:
        with open(logfile, "a") as f:
            f.write(log_entry + "\n")
    print(log_entry)
def packet_callback(packet, protocol, logfile):
    if IP in packet:
        if protocol == "tcp" and TCP in packet:
            log_packet(packet, logfile)
        elif protocol == "udp" and UDP in packet:
            log_packet(packet, logfile)
        elif protocol == "icmp" and packet.haslayer("ICMP"):
            log_packet(packet, logfile)
def start_sniffing(interface, protocol, logfile):
    print(f"[bold yellow]Starting sniffer on {interface} with protocol filter: {protocol}...[/bold yellow]")
    try:
        sniff(iface=interface, prn=lambda x: packet_callback(x, protocol, logfile), store=0)
    except KeyboardInterrupt:
        print("\nSniffer stopped by user.")