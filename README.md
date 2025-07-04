# MungeIPs
script processes a list of IP addresses and subnets to optimize

### Script Description
**Function**: The `mungeIPs.sh` script processes a list of IP addresses and subnets to optimize for a Web Application Firewall (WAF) with limited whitelisting or Blacklisting slots, ensuring only /16, /24, and single IPs are output. It:
- Removes /32 from single IPs.
- Converts /18 to /23 subnets to /16.
- Expands subnets larger than /16 (e.g., /10 to /15) into multiple /16 networks.
- Expands subnets smaller than /24 (e.g., /25 to /31) into individual IPs.
- Consolidates 4 or more IPs in the same /24 into a /24 network.
- Consolidates 4 or more /24s in the same /16 into a /16 network.

**Use Case**: Ideal for network administrators managing WAF configurations with strict format constraints (/16, /24, single IPs) and limited slots, minimizing the number of entries while maintaining coverage of the original IP ranges.

### Usage Instructions
1. Save the IP list (one IP or subnet per line) as `ips.txt`.
2. Save the script as `mungeIPs.sh`.
3. Make executable: `chmod +x mungeIPs.sh`.
4. Run: `./mungeIPs.sh`.
5. Output is saved to `processed_ips.txt`.

### Adjusting Conversion Thresholds
To modify the thresholds for consolidation (default: 4 IPs for /24, 4 /24s for /16):
- **IPs to /24**: Edit the `awk` command in **Step 4** (line ~130). Change `if (networks[network] >= 4)` to `if (networks[network] >= N)`, where `N` is the desired number of IPs.
- **/24s to /16**: Edit the `awk` command in **Step 6** (line ~160). Change `if (networks[network] >= 4)` to `if (networks[network] >= M)`, where `M` is the desired number of /24s.

**Example**: To consolidate 6+ IPs into a /24 and 8+ /24s into a /16, replace `>= 4` with `>= 6` in Step 4 and `>= 8` in Step 6.

**Compatibility**: Designed for Bash 3.x (e.g., macOS default). For issues, use `/bin/bash mungeIPs.sh` or update Bash (`brew install bash`).
