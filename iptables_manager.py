"""
Module for managing iptables rules.
"""

import subprocess
import sys
from typing import List

# Import constants
from util import CHAIN_NAME


class IPTablesManager:
    """Manages iptables rules for Australian IP whitelisting."""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(message)
    
    def run_iptables(self, args: List[str], check: bool = True) -> bool:
        """Execute an iptables command."""
        try:
            subprocess.run(['iptables'] + args, 
                         capture_output=True, 
                         text=True, 
                         check=check)
            return True
        except subprocess.CalledProcessError as e:
            if check:
                self.log(f"❌ iptables command failed: {' '.join(['iptables'] + args)}")
                self.log(f"   Error: {e.stderr.strip()}")
                raise
            return False
    
    def chain_exists(self) -> bool:
        """Check if the Australian whitelist chain exists."""
        return self.run_iptables(['-nL', CHAIN_NAME], check=False)
    
    def create_whitelist_chain(self) -> None:
        """Create the Australian IP whitelist chain, deleting existing one if necessary."""
        self.log(f"\n🔧 Setting up iptables chain '{CHAIN_NAME}'...")
        
        # Attempt to remove existing chain first (clean up old state)
        if self.chain_exists():
            self.log("   Removing existing chain...")
            self.run_iptables(['-F', CHAIN_NAME], check=False) # Flush rules
            self.run_iptables(['-X', CHAIN_NAME], check=False) # Delete chain
        
        # Create new chain
        self.run_iptables(['-N', CHAIN_NAME])
        self.log(f"✓ Created chain '{CHAIN_NAME}'")
    
    def add_whitelist_rules(self, ranges: List[str]) -> None:
        """Add Australian IP ranges and PRIVATE/LOCAL IP ranges to the whitelist chain."""
        
        # RFC 1918, Localhost, Link-Local, and Multicast IP Ranges (Required for system stability)
        CRITICAL_LOCAL_RANGES = [
            '127.0.0.0/8',      # Localhost
            '10.0.0.0/8',       # RFC 1918 Private A
            '172.16.0.0/12',    # RFC 1918 Private B
            '192.168.0.0/16',   # RFC 1918 Private C
            '169.254.0.0/16',   # Link-Local (APIPA)
            '224.0.0.0/4',      # Multicast (For DNS/network discovery)
        ]
        
        # 1. Add Localhost and Critical Local Ranges first
        self.log("\n📝 Adding critical Local/Private IP ranges to whitelist...")
        for ip_range in CRITICAL_LOCAL_RANGES:
            # Append rule: IF source matches range, ACCEPT
            self.run_iptables(['-A', CHAIN_NAME, '-s', ip_range, '-j', 'ACCEPT'], check=False)

        self.log("✓ Added all critical local/private ranges.")
        
        # 2. Add Australian Public IP Ranges
        self.log(f"\n📝 Adding {len(ranges)} Australian Public IP ranges to whitelist...")
        
        for idx, cidr_range in enumerate(ranges, 1):
            self.run_iptables(['-A', CHAIN_NAME, '-s', cidr_range, '-j', 'ACCEPT'], check=False)
            
            # Progress indicator every 100 ranges
            if idx % 100 == 0:
                self.log(f"   Added {idx}/{len(ranges)} ranges...")
        
        self.log(f"✓ Finished adding all {len(ranges)} Australian ranges to {CHAIN_NAME}")
    
    def apply_firewall_rules(self) -> None:
        """Apply the main firewall rules to link the whitelist and block everything else."""
        self.log("\n🚀 Applying firewall rules...")
        
        # Remove old linkage rules if they exist (clean slate)
        self.run_iptables(['-D', 'INPUT', '-j', CHAIN_NAME], check=False)
        self.run_iptables(['-D', 'INPUT', '-j', 'DROP'], check=False)
        
        # --- CRITICAL CHANGE ---
        # We INSERT the jump to our custom chain at position 1.
        # Everything that matches AU/Private/Local will ACCEPT and stop processing.
        self.run_iptables(['-I', 'INPUT', '1', '-j', CHAIN_NAME])
        
        # We APPEND the final DROP rule.
        # Everything else (i.e., non-whitelisted foreign IPs) will fall through and DROP.
        self.run_iptables(['-A', 'INPUT', '-j', 'DROP'])
        
        self.log("✓ Firewall rules applied successfully! Non-Australian traffic is now BLOCKED.")
    
    def remove_firewall_rules(self) -> None:
        """Remove all Australian IP firewall rules."""
        self.log("\n🧹 Removing firewall rules...")
        
        # 1. Remove rules from INPUT chain (in reverse order of application)
        self.run_iptables(['-D', 'INPUT', '-j', 'DROP'], check=False)
        self.run_iptables(['-D', 'INPUT', '-j', CHAIN_NAME], check=False)
        
        # 2. Flush and delete the chain
        if self.chain_exists():
            self.run_iptables(['-F', CHAIN_NAME], check=False)
            self.run_iptables(['-X', CHAIN_NAME], check=False)
        
        self.log("✓ Firewall rules removed successfully!")
    
    def show_summary(self, range_count: int) -> None:
        """Display summary information and instructions."""
        print("\n" + "="*70)
        print("                 FIREWALL CONFIGURATION COMPLETE")
        print("="*70)
        print("\n📊 Summary:")
        print(f"   • {range_count} Australian public IP ranges whitelisted")
        print(f"   • Chain name: {CHAIN_NAME}")
        print(f"   • All non-Australian public traffic: BLOCKED")
        print("   • Localhost/Private/Link-Local traffic: ALLOWED")
        
        print("\n🔧 To remove these rules:")
        print(f"   sudo python3 {sys.argv[0]} --remove")
        
        print("\n📝 To view current rules:")
        print("   sudo iptables -L -n -v")
        print(f"   sudo iptables -L {CHAIN_NAME} -n -v")
        print("="*70 + "\n")
