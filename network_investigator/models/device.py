"""Device profile model for tracking network devices."""

from collections import defaultdict


class DeviceProfile:
    """Profile for a network device tracking its behavior."""
    
    def __init__(self, ip_address, mac_address=None):
        self.ip_address = ip_address
        self.mac_address = mac_address
        self.hostnames = set()
        self.dns_queries = defaultdict(int)
        self.connections = []
        self.bytes_sent = 0
        self.bytes_received = 0
        self.protocols = defaultdict(int)
        self.alerts = []
    
    def add_hostname(self, hostname):
        """Add a hostname associated with this device."""
        if hostname:
            self.hostnames.add(hostname)
    
    def add_dns_query(self, domain):
        """Track a DNS query made by this device."""
        if domain:
            self.dns_queries[domain] += 1
    
    def add_connection(self, destination, timestamp, protocol='TCP'):
        """Track a connection from this device."""
        self.connections.append({
            'destination': destination,
            'timestamp': timestamp,
            'protocol': protocol
        })
        self.protocols[protocol] += 1
    
    def add_data_transfer(self, bytes_sent=0, bytes_received=0):
        """Track data transfer volumes."""
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
    
    def add_alert(self, alert):
        """Add a security alert for this device."""
        self.alerts.append(alert)
    
    def get_summary(self):
        """Get a summary of this device's activity."""
        return {
            'ip_address': self.ip_address,
            'mac_address': self.mac_address,
            'hostnames': list(self.hostnames),
            'total_connections': len(self.connections),
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'protocols': dict(self.protocols),
            'dns_queries': len(self.dns_queries),
            'alert_count': len(self.alerts)
        }
