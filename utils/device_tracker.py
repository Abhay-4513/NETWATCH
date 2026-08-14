"""
Device Tracker - Tracks devices on the network.
In production, uses ARP scanning to discover devices.
"""

import subprocess
import re
import threading
import time


class DeviceTracker:
    def __init__(self, db):
        self.db = db

    def get_vendor_from_mac(self, mac: str) -> str:
        """Lookup vendor from MAC OUI (first 3 bytes)."""
        OUI_MAP = {
            'AA:BB:CC': 'Apple', 'DD:EE:FF': 'Samsung',
            '11:22:33': 'Amazon', '55:66:77': 'Sony',
            'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
            '00:50:56': 'VMware', '08:00:27': 'VirtualBox',
        }
        oui = mac[:8].upper()
        return OUI_MAP.get(oui, 'Unknown')

    def scan_network(self, subnet='192.168.1.0/24'):
        """
        Scan network for devices using ARP (requires nmap or arp-scan).
        
        Production usage:
            tracker.scan_network('192.168.1.0/24')
        
        Requires: apt install nmap  OR  apt install arp-scan
        """
        devices = []
        
        try:
            # Try arp-scan first (more reliable)
            result = subprocess.run(
                ['arp-scan', '--localnet'],
                capture_output=True, text=True, timeout=30
            )
            for line in result.stdout.split('\n'):
                match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)', line, re.I)
                if match:
                    devices.append({
                        'ip': match.group(1),
                        'mac': match.group(2).upper(),
                        'vendor': match.group(3).strip()
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            try:
                # Fallback: nmap ARP ping
                result = subprocess.run(
                    ['nmap', '-sn', subnet, '--output-xml', '-'],
                    capture_output=True, text=True, timeout=60
                )
                # Parse nmap output
                ip_matches = re.findall(r'<address addr="([\d.]+)" addrtype="ipv4"', result.stdout)
                mac_matches = re.findall(r'<address addr="([\w:]+)" addrtype="mac".*?vendor="([^"]*)"', result.stdout)
                # Combine results
                for i, ip in enumerate(ip_matches):
                    mac, vendor = mac_matches[i] if i < len(mac_matches) else ('unknown', 'unknown')
                    devices.append({'ip': ip, 'mac': mac.upper(), 'vendor': vendor})
            except (FileNotFoundError, subprocess.TimeoutExpired):
                print("⚠️  Neither arp-scan nor nmap available. Install one for live device scanning.")
        
        return devices

    def start_periodic_scan(self, interval=300):
        """Scan for new devices every N seconds."""
        def scanner():
            while True:
                devices = self.scan_network()
                conn = self.db.get_connection()
                for d in devices:
                    try:
                        conn.execute("""
                            INSERT INTO devices (mac_address, ip_address, vendor)
                            VALUES (?, ?, ?)
                            ON CONFLICT(mac_address) DO UPDATE SET
                                ip_address = excluded.ip_address,
                                last_seen = CURRENT_TIMESTAMP
                        """, (d['mac'], d['ip'], d['vendor']))
                    except Exception:
                        pass
                conn.commit()
                conn.close()
                time.sleep(interval)
        
        t = threading.Thread(target=scanner, daemon=True)
        t.start()
