"""
NetWatch DNS Server - Intercepts all DNS queries network-wide.
Blocks flagged domains, forwards everything else to 8.8.8.8
"""

from dnslib.server import DNSServer, BaseResolver
from dnslib.proxy import ProxyResolver


class NetWatchResolver(ProxyResolver):
    def __init__(self, db, monitor):
        super().__init__('8.8.8.8', 53, 5)
        self.db = db
        self.monitor = monitor

    def resolve(self, request, handler):
        domain = str(request.q.qname).rstrip('.')
        client_ip = handler.client_address[0]
        device_mac = self.get_mac(client_ip)

        # Log and check if blocked
        is_blocked, category, reason = self.db.is_domain_blocked(domain)
        self.monitor.process_request(domain, client_ip, device_mac or 'unknown')

        if is_blocked:
            # Return empty response — site won't load on student device
            reply = request.reply()
            return reply

        # Not blocked — forward to real DNS normally
        return super().resolve(request, handler)

    def get_mac(self, ip):
        """Get MAC address from ARP table."""
        try:
            with open('/proc/net/arp') as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if parts[0] == ip:
                        return parts[3].upper()
        except Exception:
            pass
        return None


def start_dns_server(db, monitor):
    resolver = NetWatchResolver(db, monitor)
    server = DNSServer(resolver, port=53, address='0.0.0.0')
    server.start_thread()
    print("✅ DNS Server listening on port 53 — monitoring all devices")
