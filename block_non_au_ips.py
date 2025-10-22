#!/usr/bin/env python3
"""
Australian IP Firewall Script - Main Entry Point
==============================================
Coordinates the download, parsing, and firewall management.
"""

import sys
import argparse

# Import the modules we are creating
from util import check_root, check_iptables, CHAIN_NAME
from ip_data_fetcher import APNICFetcher
from iptables_manager import IPTablesManager


def install_firewall(manager: IPTablesManager, fetcher: APNICFetcher, verbose: bool):
    """Downloads data, parses it, and applies the firewall rules."""
    
    # 0. System Checks
    check_root()
    check_iptables()
    
    # 1. Download and Parse Data
    raw_data = fetcher.download_apnic_data()
    au_ranges = fetcher.parse_data(raw_data)
    
    if not au_ranges:
        print("❌ Error: No Australian IP ranges found!")
        sys.exit(1)
    
    # 2. Apply Firewall Rules
    manager.create_whitelist_chain()
    manager.add_whitelist_rules(au_ranges)
    manager.apply_firewall_rules()
    
    # 3. Show Summary
    manager.show_summary(len(au_ranges))


def remove_firewall(manager: IPTablesManager):
    """Removes the firewall rules."""
    check_root()
    check_iptables()
    manager.remove_firewall_rules()


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description='Block all non-Australian IP traffic using iptables',
        epilog='⚠️  WARNING: This will block ALL traffic from non-Australian IPs!'
    )
    parser.add_argument(
        '--remove',
        action='store_true',
        help='Remove firewall rules instead of installing them'
    )
    parser.add_argument(
        '--quiet',
        action='store_true',
        help='Suppress verbose output'
    )
    
    args = parser.parse_args()
    
    # Initialize components
    fetcher = APNICFetcher(verbose=not args.quiet)
    manager = IPTablesManager(verbose=not args.quiet)
    
    if args.remove:
        remove_firewall(manager)
    else:
        # Show warning before proceeding
        print("\n" + "="*70)
        print("        ⚠️  WARNING: AUSTRALIAN IP FIREWALL")
        print("="*70)
        print("\nThis script will:")
        print("  • Download current Australian IP ranges from APNIC")
        print("  • Configure iptables to BLOCK all non-Australian traffic")
        print("  • Potentially disconnect your current session if remote")
        print("\n⚠️  Ensure you have console/physical access before proceeding!")
        print("="*70 + "\n")
        
        response = input("Do you want to continue? (yes/no): ").strip().lower()
        if response != 'yes':
            print("Aborted.")
            sys.exit(0)
        
        print()
        install_firewall(manager, fetcher, not args.quiet)


if __name__ == '__main__':
    main()
