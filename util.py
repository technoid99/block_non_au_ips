"""
Utility functions and configuration constants.
"""

import sys
import subprocess

# Configuration Constants
APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"
CHAIN_NAME = "AU_WHITELIST"

def check_root() -> None:
    """Verify script is running with root privileges."""
    try:
        result = subprocess.run(['id', '-u'], capture_output=True, text=True, check=True)
        if result.stdout.strip() != '0':
            print("❌ Error: This script must be run as root (use sudo)")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print("❌ Error: Unable to verify root privileges")
        sys.exit(1)

def check_iptables() -> None:
    """Verify iptables is installed and accessible."""
    try:
        subprocess.run(['iptables', '--version'], 
                        capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Error: iptables not found. Please install iptables first.")
        sys.exit(1)
