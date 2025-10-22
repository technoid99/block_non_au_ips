"""
Module for fetching and parsing the APNIC delegated statistics file.
"""

import sys
import urllib.request
import math
import os 
from typing import List

# Import constants
from util import APNIC_URL


class APNICFetcher:
    """Handles downloading and parsing APNIC data."""
    
    # Define the local filename
    LOCAL_FILENAME = "delegated-apnic-latest"
    
    def __init__(self, verbose: bool = True):
        self.verbose = verbose
    
    def log(self, message: str) -> None:
        """Print message if verbose mode is enabled."""
        if self.verbose:
            print(message)
    
    def download_apnic_data(self) -> str:
        """
        Check for local file. If it exists, use it. If not, download and save it.
        
        Returns:
            String content of the file
        """
        
        # 1. Check for local file
        if os.path.exists(self.LOCAL_FILENAME):
            self.log(f"💾 Found local file '{self.LOCAL_FILENAME}'. Using local data.")
            try:
                with open(self.LOCAL_FILENAME, 'r', encoding='utf-8') as f:
                    data = f.read()
                    self.log(f"✓ Read {len(data)} bytes from local cache.")
                    return data
            except Exception as e:
                # If reading local file fails, proceed to download
                self.log(f"⚠️ Warning: Failed to read local file: {e}. Attempting download.")


        # 2. Download and Save
        self.log("📥 Local file not found. Downloading Australian IP ranges from APNIC...")
        self.log(f"   Source: {APNIC_URL}")
        
        try:
            with urllib.request.urlopen(APNIC_URL, timeout=30) as response:
                data = response.read().decode('utf-8')
                
                # Save the downloaded data to the local file
                try:
                    with open(self.LOCAL_FILENAME, 'w', encoding='utf-8') as f:
                        f.write(data)
                    self.log(f"✓ Downloaded and saved {len(data)} bytes to '{self.LOCAL_FILENAME}'.")
                except Exception as e:
                    self.log(f"⚠️ Warning: Could not save file locally: {e}")
                    
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

        # --- DEBUG CODE ---
        if self.verbose and ranges:
            self.log("\n🔎 First 10 parsed AU ranges (Debug):")
            for i, ip_range in enumerate(ranges[:10]):
                self.log(f"   [{i+1:02}] {ip_range}")
            if len(ranges) > 10:
                 self.log(f"   ... ({len(ranges) - 10} more ranges not shown)")
        # ------------------
        
        return ranges
