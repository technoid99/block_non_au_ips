"""
Module for managing iptables rules.
"""

import subprocess
from typing import List
from datetime import datetime
import sys

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
        # Use a non-disruptive command like -nL which will exit with status 0 if chain exists
        return self.run_iptables(['-nL', CHAIN_NAME], check=False)
    
    def create_whitelist_chain(self) -> None:
        """Create the Australian IP whitelist chain, deleting existing one if necessary."""
        self.log(f"\n🔧 Setting up iptables chain '{CHAIN_NAME}'...")
        
        # Attempt to remove existing chain first (in case of old residual rules)
        if self.chain_exists():
            self.log("   Removing existing chain...")
            self.run_iptables(['-F', CHAIN_NAME], check=False) # Flush rules
            self.run_iptables(['-X', CHAIN_NAME], check=False) # Delete chain
        
        # Create new chain
        self.run_iptables(['-N', CHAIN_NAME])
        self.log(f"✓ Created chain '{CHAIN_NAME}'")
    
    def add_whitelist_rules(self, ranges: List[str]) -> None:
        """Add Australian IP ranges to the whitelist chain."""
        self.log(f"\n📝 Adding {len(ranges)} Australian IP ranges to whitelist...")
        
        for idx, cidr_range in enumerate(ranges, 1):
            # Append rule: IF source matches range, ACCEPT
            self.run_iptables(['-A', CHAIN_NAME, '-s', cidr_range, '-j', 'ACCEPT'], check=False)
            
            # Progress indicator every 100 ranges
            if idx % 100 == 0:
                self.log(f"   Added {idx}/{len(ranges)} ranges...")
        
        # Add localhost to whitelist (critical for local access)
        self.log("📝 Adding localhost (127.0.0.0/8) to whitelist...")
        self.run_iptables(['-A', CHAIN_NAME, '-s', '127.0.0.0/8', '-j', 'ACCEPT'])
        
        self.log(f"✓ Finished adding all {len(ranges)} ranges to {CHAIN_NAME}")
    
    def apply_firewall_rules(self) -> None:
        """Apply the main firewall rules to link the whitelist and block everything else."""
        self.log("\n🚀 Applying firewall rules...")
        
        # Remove old linkage rules if they exist (clean slate)
        self.run_iptables(['-D', 'INPUT', '-j', CHAIN_NAME], check=False)
        self.run_iptables(['-D', 'INPUT', '-j', 'DROP'], check=False)
        
        # Insert whitelist check at the beginning (rule 1) of the INPUT chain
        self.run_iptables(['-I', 'INPUT', '1', '-j', CHAIN_NAME])
        
        # Add the final DROP rule for everything that did NOT match the whitelist
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
            self.run_iptables(['-F', CHAIN_NAME], check=False) # Flush all rules
            self.run_iptables(['-X', CHAIN_NAME], check=False) # Delete the chain
        
        self.log("✓ Firewall rules removed successfully!")
    
    def show_summary(self, range_count: int) -> None:
        """Display summary information and instructions."""
        print("\n" + "="*70)
        print("                 FIREWALL CONFIGURATION COMPLETE")
        print("="*70)
        print("\n📊 Summary:")
        print(f"   • {range_count} Australian IP ranges whitelisted")
        print(f"   • Chain name: {CHAIN_NAME}")
        print(f"   • All non-Australian traffic: BLOCKED")
        
        print("\n🔧 To remove these rules:")
        print(f"   sudo python3 {sys.argv[0]} --remove")
        
        print("\n📝 To view current rules:")
        print("   sudo iptables -L -n -v")
        print(f"   sudo iptables -L {CHAIN_NAME} -n -v")
        print("="*70 + "\n")
