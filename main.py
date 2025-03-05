# Author : Om Joshi
import argparse
from sniffing import start_sniffing
from utils import check_permissions
def parse_args():
    parser = argparse.ArgumentParser(description="Network Packet Sniffer (Project by iamomjoshi)")
    parser.add_argument("--interface", type=str, help="Network interface to sniff on (eg: eth0)")
    parser.add_argument("--protocol", type=str, choices=["tcp", "udp", "icmp"], help="Protocol to filter")
    parser.add_argument("--logfile", type=str, help="Path to save packet logs")
    return parser.parse_args()
if __name__ == "__main__":
    check_permissions()
    args = parse_args()
    start_sniffing(args.interface, args.protocol, args.logfile)