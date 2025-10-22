"""
Module for fetching and parsing the APNIC delegated statistics file.
"""

import sys
import urllib.request
import math
from typing import List

# Import constants
from util import APNIC_URL
#APNIC_URL = "https://ftp.apnic.net/stats/apnic/delegated-apnic-latest"


class APNICFetcher:
    """Handles downloading and parsing APNIC data."""
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(message)
    
    def download_apnic_data(self) -> str:
        """
        Download the APNIC delegated statistics file.
        
        Returns:
            String content of the file
        """
        self.log("📥 Downloading Australian IP ranges from APNIC...")
        self.log(f"   Source: {APNIC_URL}")
        
        try:
            with urllib.request.urlopen(APNIC_URL, timeout=30) as response:
                data = response.read().decode('utf-8')
                self.log(f"✓ Downloaded {len(data)} bytes")
                return data
        except Exception as e:
            print(f"❌ Error downloading APNIC data: {e}")
            sys.exit(1)
            
    def count_to_cidr(self, count: int) -> int:
        """
        Convert IP address count to CIDR prefix length (32 - log2(count)).
        """
        if count <= 0:
            raise ValueError(f"Invalid count: {count}")
        
        prefix_length = 32 - int(math.log2(count))
        
        if prefix_length < 0 or prefix_length > 32:
            raise ValueError(f"Invalid prefix length {prefix_length} for count {count}")
        
        return prefix_length

    def parse_data(self, data: str) -> List[str]:
        """
        Parse APNIC delegated statistics file for Australian IPv4 ranges (cc='AU', type='ipv4').
        
        Returns:
            List of IP ranges in CIDR notation (e.g., ['203.0.113.0/24', ...])
        """
        self.log("\n🔍 Parsing Australian IPv4 allocations...")
        
        ranges = []
        line_count = 0
        error_count = 0
        
        for line in data.splitlines():
            line_count += 1
            
            # Skip comments, empty lines, and header lines
            if line.startswith(('#', '2.', '2|')) or not line.strip():
                continue
            
            fields = line.split('|')
            
            # Need at least 7 fields for a valid record
            if len(fields) < 7:
                continue
            
            registry, cc, res_type, start, value, date, status = fields[:7]
            
            # Filter for Australian IPv4 addresses
            if cc.upper() == 'AU' and res_type == 'ipv4':
                try:
                    count = int(value)
                    cidr_prefix = self.count_to_cidr(count)
                    cidr_range = f"{start}/{cidr_prefix}"
                    ranges.append(cidr_range)
                except (ValueError, TypeError) as e:
                    error_count += 1
                    if self.verbose and error_count <= 5:
                        self.log(f"⚠️  Warning: Skipping invalid entry at line {line_count}: {e}")
        
        self.log(f"✓ Parsed {line_count} total lines")
        self.log(f"✓ Found {len(ranges)} Australian IPv4 ranges")
        if error_count > 0:
            self.log(f"⚠️  Skipped {error_count} invalid entries")

        # --- DEBUG CODE ADDED HERE ---
        if self.verbose and ranges:
            self.log("\n🔎 First 10 parsed AU ranges (Debug):")
            for i, ip_range in enumerate(ranges[:10]):
                self.log(f"   [{i+1:02}] {ip_range}")
            if len(ranges) > 10:
                 self.log(f"   ... ({len(ranges) - 10} more ranges not shown)")
        # -----------------------------
                
        return ranges

#---Module test code--#    
def test_fetcher():
    """Test function to run download and parsing when executed directly."""
    fetcher = APNICFetcher(verbose=True)
    
    # 1. Download
    raw_data = fetcher.download_apnic_data()
    
    # 2. Parse (and print the debug lines)
    au_ranges = fetcher.parse_data(raw_data)
    
    print(f"\n✅ Test Complete. Total parsed ranges: {len(au_ranges)}")

if __name__ == '__main__':
    # NOTE: This file depends on util.py for constants. 
    # Make sure 'util.py' is in the same directory.
    test_fetcher()
