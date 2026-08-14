"""
DNS Monitor - Captures DNS queries on the network.
In production: uses Scapy to sniff UDP port 53.
In demo mode: simulates realistic traffic for testing.
"""

import threading
import time
import random
from datetime import datetime


SIMULATED_DOMAINS = [
    # Allowed
    ('google.com', 'search'), ('youtube.com', 'media'),
    ('github.com', 'development'), ('netflix.com', 'media'),
    ('reddit.com', 'social'), ('amazon.com', 'shopping'),
    ('cloudflare.com', 'tech'), ('twitter.com', 'social'),
    ('zoom.us', 'business'), ('slack.com', 'business'),
    ('bbc.com', 'news'), ('wikipedia.org', 'reference'),
    ('spotify.com', 'media'), ('apple.com', 'tech'),
    ('docs.google.com', 'productivity'), ('mail.google.com', 'email'),
    # Blocked
    ('pornhub.com', 'adult'), ('bet365.com', 'gambling'),
    ('tiktok.com', 'social'), ('malware-site.com', 'malware'),
    ('xvideos.com', 'adult'), ('pokerstars.com', 'gambling'),
]

SIMULATED_DEVICES = [
    ('192.168.1.101', 'AA:BB:CC:11:22:33'),
    ('192.168.1.102', 'AA:BB:CC:44:55:66'),
    ('192.168.1.103', 'DD:EE:FF:11:22:33'),
    ('192.168.1.104', 'DD:EE:FF:44:55:66'),
    ('192.168.1.106', '11:22:33:DD:EE:FF'),
]


class DNSMonitor:
    def __init__(self, db, alert_mgr, categorizer, socketio):
        self.db = db
        self.alert_mgr = alert_mgr
        self.categorizer = categorizer
        self.socketio = socketio
        self.running = False
        self._alert_counts = {}  # Track repeated blocked attempts

    def process_request(self, domain: str, device_ip: str, device_mac: str) -> dict:
        """Core logic: check domain, log it, optionally alert."""
        is_blocked, category, reason = self.db.is_domain_blocked(domain)
        
        if not category:
            category = self.categorizer.categorize(domain)
        
        status = 'BLOCKED' if is_blocked else 'ALLOWED'
        
        # Log to database
        self.db.log_access(device_ip, device_mac, domain, category, status)
        
        event = {
            'device_ip': device_ip,
            'device_mac': device_mac,
            'domain': domain,
            'category': category or 'unknown',
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'reason': reason or ''
        }
        
        # Emit real-time event via WebSocket
        try:
            self.socketio.emit('dns_event', event)
        except Exception:
            pass
        
        # Alert on blocked domains
        if is_blocked:
            key = f"{device_mac}:{domain}"
            self._alert_counts[key] = self._alert_counts.get(key, 0) + 1
            # Alert on first occurrence and every 5th after
            if self._alert_counts[key] == 1 or self._alert_counts[key] % 5 == 0:
                self.alert_mgr.send_alert(event)
        
        return event

    def start_simulation(self):
        """Simulate DNS traffic for demo purposes."""
        self.running = True
        print("🔍 DNS Monitor simulation started")
        
        while self.running:
            try:
                device_ip, device_mac = random.choice(SIMULATED_DEVICES)
                
                # 88% allowed, 12% blocked
                if random.random() < 0.88:
                    domain, _ = random.choice([d for d in SIMULATED_DOMAINS if d[0] not in
                        ['pornhub.com', 'bet365.com', 'tiktok.com', 'malware-site.com',
                         'xvideos.com', 'pokerstars.com']])
                else:
                    domain, _ = random.choice([d for d in SIMULATED_DOMAINS if d[0] in
                        ['pornhub.com', 'bet365.com', 'tiktok.com', 'malware-site.com',
                         'xvideos.com', 'pokerstars.com']])
                
                self.process_request(domain, device_ip, device_mac)
                
                # Realistic inter-request delay (0.5 - 4 seconds)
                time.sleep(random.uniform(0.5, 4.0))
                
            except Exception as e:
                print(f"Simulation error: {e}")
                time.sleep(1)

    def start_live_capture(self, interface='eth0'):
        """
        Live DNS capture using Scapy.
        Requires: pip install scapy
        Must run as root or with CAP_NET_RAW capability.
        
        Usage:
            monitor.start_live_capture('wlan0')  # for WiFi
            monitor.start_live_capture('eth0')   # for Ethernet
        """
        try:
            from scapy.all import sniff, DNS, DNSQR, IP, Ether
        except ImportError:
            print("❌ Scapy not installed. Run: pip install scapy")
            print("   Falling back to simulation mode...")
            self.start_simulation()
            return

        def handle_packet(pkt):
            try:
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    if pkt[DNS].qr == 0:  # Query (not response)
                        domain = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                        device_ip = pkt[IP].src if pkt.haslayer(IP) else 'unknown'
                        device_mac = pkt[Ether].src if pkt.haslayer(Ether) else 'unknown'
                        
                        # Skip loopback / DNS server itself
                        if device_ip.startswith('127.') or device_ip == '0.0.0.0':
                            return
                        
                        self.process_request(domain, device_ip, device_mac)
            except Exception as e:
                pass  # Silently skip malformed packets

        print(f"🔍 Starting live DNS capture on {interface}")
        self.running = True
        sniff(
            iface=interface,
            filter="udp port 53",
            prn=handle_packet,
            store=0,
            stop_filter=lambda p: not self.running
        )

    def stop(self):
        self.running = False
