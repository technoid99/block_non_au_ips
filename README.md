# block_non_au_ips
Script to insert iptables rules to block all non-AU IP traffic.

This script is being developed.
Use at your own risk

# Usage
Important note: It's probably best you run this in a VM instead of your host/main system lest the firewalls or their remove screws up your current firewall rules.

You need sudo to modify iptables

```sudo python3 block_non_au_ips.py``` to add the firewall rules

```sudo python3 block_non_au_ips.py --remove``` to remove the added firewall rules
