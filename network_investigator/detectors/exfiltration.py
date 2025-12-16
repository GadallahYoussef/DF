"""Data exfiltration and beaconing detection."""

import statistics
from collections import defaultdict
from .whitelist import is_whitelisted


class DataExfiltrationDetector:
    """Detects potential data exfiltration and C2 beaconing."""
    
    # Thresholds for detection
    LARGE_UPLOAD_THRESHOLD = 50 * 1024 * 1024  # 50 MB
    MIN_BEACONING_CONNECTIONS = 10  # Require at least 10 connections
    MIN_BEACONING_INTERVAL = 30.0  # 30 seconds minimum interval
    MAX_VARIANCE_RATIO = 0.3  # Low variance relative to mean indicates regularity
    
    def __init__(self):
        self.connection_times = defaultdict(list)
        self.data_transfers = defaultdict(int)
        self.seen_alerts = set()
    
    def track_connection(self, destination, timestamp, protocol='TCP'):
        """
        Track a connection for beaconing analysis.
        
        Args:
            destination: IP or domain of destination
            timestamp: Timestamp of the connection
            protocol: Protocol used (TCP, UDP, etc.)
        """
        key = f"{protocol}:{destination}"
        self.connection_times[key].append(timestamp)
    
    def track_data_transfer(self, destination, bytes_transferred):
        """
        Track data transfer volume.
        
        Args:
            destination: IP or domain of destination
            bytes_transferred: Number of bytes transferred
        """
        self.data_transfers[destination] += bytes_transferred
    
    def check_beaconing(self):
        """
        Check for regular beaconing patterns that might indicate C2 traffic.
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        for key, timestamps in self.connection_times.items():
            if len(timestamps) < self.MIN_BEACONING_CONNECTIONS:
                continue
            
            protocol, destination = key.split(':', 1)
            
            # Skip whitelisted destinations
            if is_whitelisted(destination):
                continue
            
            # Calculate intervals between connections
            sorted_times = sorted(timestamps)
            intervals = [sorted_times[i] - sorted_times[i-1] 
                        for i in range(1, len(sorted_times))]
            
            if not intervals:
                continue
            
            # Skip if any interval is too short (normal traffic)
            if min(intervals) < self.MIN_BEACONING_INTERVAL:
                continue
            
            # Calculate mean and standard deviation
            mean_interval = statistics.mean(intervals)
            
            # Need at least 2 intervals to calculate stdev
            if len(intervals) < 2:
                continue
            
            stdev_interval = statistics.stdev(intervals)
            
            # Check if intervals are regular (low variance relative to mean)
            variance_ratio = stdev_interval / mean_interval if mean_interval > 0 else 1
            
            if variance_ratio <= self.MAX_VARIANCE_RATIO:
                alert_key = f"beaconing:{protocol}:{destination}"
                if alert_key not in self.seen_alerts:
                    self.seen_alerts.add(alert_key)
                    alerts.append({
                        'type': 'beaconing',
                        'severity': 'high',
                        'destination': destination,
                        'protocol': protocol,
                        'message': (f"Regular beaconing detected to {destination} "
                                   f"({len(timestamps)} connections, "
                                   f"mean interval: {mean_interval:.1f}s, "
                                   f"variance ratio: {variance_ratio:.3f})")
                    })
        
        return alerts
    
    def check_large_uploads(self):
        """
        Check for large data uploads that might indicate exfiltration.
        
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        for destination, bytes_transferred in self.data_transfers.items():
            if bytes_transferred >= self.LARGE_UPLOAD_THRESHOLD:
                # Skip whitelisted destinations
                if is_whitelisted(destination):
                    continue
                
                alert_key = f"large_upload:{destination}"
                if alert_key not in self.seen_alerts:
                    self.seen_alerts.add(alert_key)
                    size_mb = bytes_transferred / (1024 * 1024)
                    alerts.append({
                        'type': 'data_exfiltration',
                        'severity': 'critical',
                        'destination': destination,
                        'message': f"Large data upload detected: {size_mb:.1f} MB to {destination}"
                    })
        
        return alerts
    
    def check_dns_tunneling(self, domain, query_count):
        """
        Check for potential DNS tunneling based on unusual patterns.
        
        Args:
            domain: Domain being queried
            query_count: Number of queries to this domain
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if not domain or is_whitelisted(domain):
            return alerts
        
        # Look for domains with high entropy subdomains (encoded data)
        # or excessive number of queries
        if query_count > 100:
            alert_key = f"dns_tunneling:{domain}"
            if alert_key not in self.seen_alerts:
                self.seen_alerts.add(alert_key)
                alerts.append({
                    'type': 'dns_tunneling',
                    'severity': 'high',
                    'domain': domain,
                    'message': f"Potential DNS tunneling detected: {query_count} queries to {domain}"
                })
        
        return alerts
