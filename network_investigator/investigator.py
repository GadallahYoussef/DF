"""Main PacketInvestigator class for analyzing network traffic."""

from collections import defaultdict
try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
except ImportError:
    print("Warning: scapy not installed. Install with: pip install scapy")
    rdpcap = None

from .models import DeviceProfile
from .detectors import TyposquatDetector, DataExfiltrationDetector
from .exporters import export_json, export_html, export_text


class PacketInvestigator:
    """Main class for investigating network packets."""
    
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.devices = {}
        self.all_alerts = []
        
        # Initialize detectors
        self.typosquat_detector = TyposquatDetector()
        self.exfiltration_detector = DataExfiltrationDetector()
        
        # Initialize statistics
        self.stats = {
            'typosquat_detections': 0,
            'exfiltration_detections': 0
        }
    
    def analyze(self):
        """Analyze the PCAP file and detect suspicious activity."""
        if rdpcap is None:
            print("Error: scapy is not installed. Cannot analyze PCAP file.")
            return
        
        print(f"Loading PCAP file: {self.pcap_file}")
        try:
            packets = rdpcap(self.pcap_file)
        except Exception as e:
            print(f"Error loading PCAP file: {e}")
            return
        
        print(f"Processing {len(packets)} packets...")
        
        for packet in packets:
            self._process_packet(packet)
        
        print("Analyzing for security threats...")
        
        # Run detection algorithms
        self._detect_threats()
        
        print(f"Analysis complete. Found {len(self.all_alerts)} alerts.")
    
    def _process_packet(self, packet):
        """Process a single packet."""
        if not packet.haslayer(IP):
            return
        
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = float(packet.time)
        
        # Get or create device profile for source
        if src_ip not in self.devices:
            self.devices[src_ip] = DeviceProfile(src_ip)
        
        device = self.devices[src_ip]
        
        # Track DNS queries
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            dns_query = packet[DNSQR].qname.decode('utf-8', errors='ignore').strip('.')
            if dns_query:
                device.add_dns_query(dns_query)
        
        # Track TCP connections
        if packet.haslayer(TCP):
            device.add_connection(dst_ip, timestamp, 'TCP')
            self.exfiltration_detector.track_connection(dst_ip, timestamp, 'TCP')
            
            # Track data transfer
            if hasattr(packet, 'len'):
                device.add_data_transfer(bytes_sent=packet.len)
                self.exfiltration_detector.track_data_transfer(dst_ip, packet.len)
        
        # Track UDP connections
        elif packet.haslayer(UDP):
            device.add_connection(dst_ip, timestamp, 'UDP')
            self.exfiltration_detector.track_connection(dst_ip, timestamp, 'UDP')
    
    def _detect_threats(self):
        """Run all threat detection algorithms."""
        # Check each device's DNS queries for typosquatting
        for ip, device in self.devices.items():
            for domain, query_count in device.dns_queries.items():
                # Check for typosquatting
                typosquat_alerts = self.typosquat_detector.check_typosquatting(domain)
                for alert in typosquat_alerts:
                    alert['source'] = ip
                    device.add_alert(alert)
                    self.all_alerts.append(alert)
                    self.stats['typosquat_detections'] += 1
                
                # Check for DNS tunneling
                dns_tunnel_alerts = self.exfiltration_detector.check_dns_tunneling(
                    domain, query_count
                )
                for alert in dns_tunnel_alerts:
                    alert['source'] = ip
                    device.add_alert(alert)
                    self.all_alerts.append(alert)
                    self.stats['exfiltration_detections'] += 1
        
        # Check for beaconing
        beaconing_alerts = self.exfiltration_detector.check_beaconing()
        for alert in beaconing_alerts:
            self.all_alerts.append(alert)
            self.stats['exfiltration_detections'] += 1
            # Add alert to relevant devices
            for device in self.devices.values():
                for conn in device.connections:
                    if conn['destination'] == alert.get('destination'):
                        device.add_alert(alert)
                        break
        
        # Check for large uploads
        upload_alerts = self.exfiltration_detector.check_large_uploads()
        for alert in upload_alerts:
            self.all_alerts.append(alert)
            self.stats['exfiltration_detections'] += 1
            destination = alert.get('destination')
            bytes_sent = self.exfiltration_detector.data_transfers.get(destination, 0)
            
            # Add alert to relevant devices and track large uploads
            for device in self.devices.values():
                # Check if this device has connections to this destination
                has_connection = any(conn['destination'] == destination for conn in device.connections)
                if has_connection:
                    device.add_alert(alert)
                    # Get the timestamp of the first connection to this destination
                    first_conn = next((conn for conn in device.connections if conn['destination'] == destination), None)
                    if first_conn:
                        device.add_large_upload(destination, bytes_sent, first_conn['timestamp'])
    
    def export_results(self, format='all', output_prefix='report'):
        """
        Export analysis results in specified format(s).
        
        Args:
            format: Export format ('json', 'html', 'text', or 'all')
            output_prefix: Prefix for output files
        """
        if format in ('json', 'all'):
            export_json(self.devices, self.all_alerts, f'{output_prefix}.json', self.stats)
        
        if format in ('html', 'all'):
            export_html(self.devices, self.all_alerts, f'{output_prefix}.html', self.stats)
        
        if format in ('text', 'all'):
            export_text(self.devices, self.all_alerts, f'{output_prefix}.txt', self.stats)
