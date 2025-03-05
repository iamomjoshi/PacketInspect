# Author : Om Joshi
import os
import sys
def check_permissions():
    if os.geteuid() != 0:
        sys.exit("This program requires root privileges. Run as root.")
def handle_error(error):
    print(f"[ERROR]: {error}")