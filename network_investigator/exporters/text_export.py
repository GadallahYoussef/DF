"""Plain text export functionality."""

from datetime import datetime


def export_text(devices, alerts, output_file='report.txt', stats=None):
    """
    Export analysis results to plain text format.
    
    Args:
        devices: Dictionary of DeviceProfile objects
        alerts: List of alert dictionaries
        output_file: Path to output file
        stats: Dictionary of statistics (optional)
    """
    if stats is None:
        stats = {}
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("NETWORK PACKET INVESTIGATOR REPORT\n")
        f.write("=" * 80 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary section
        f.write("SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Devices Analyzed: {len(devices)}\n")
        f.write(f"Total Alerts: {len(alerts)}\n\n")
        
        # Alert breakdown
        alert_types = {}
        for alert in alerts:
            alert_type = alert.get('type', 'unknown')
            alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
        
        if alert_types:
            f.write("Alert Breakdown:\n")
            for alert_type, count in sorted(alert_types.items()):
                f.write(f"  - {alert_type}: {count}\n")
            f.write("\n")
        
        # Add typosquat and exfiltration detection stats
        if stats.get('typosquat_detections', 0) > 0 or stats.get('exfiltration_detections', 0) > 0:
            f.write("Detection Statistics:\n")
            if stats.get('typosquat_detections', 0) > 0:
                f.write(f"  Typosquat Detections: {stats['typosquat_detections']}\n")
            if stats.get('exfiltration_detections', 0) > 0:
                f.write(f"  Exfiltration Detections: {stats['exfiltration_detections']}\n")
            f.write("\n")
        
        # Alerts section
        if alerts:
            f.write("SECURITY ALERTS\n")
            f.write("=" * 80 + "\n\n")
            
            # Group alerts by severity
            severity_order = ['critical', 'high', 'medium', 'low']
            alerts_by_severity = {sev: [] for sev in severity_order}
            
            for alert in alerts:
                severity = alert.get('severity', 'low')
                alerts_by_severity[severity].append(alert)
            
            for severity in severity_order:
                severity_alerts = alerts_by_severity[severity]
                if severity_alerts:
                    f.write(f"{severity.upper()} SEVERITY ALERTS ({len(severity_alerts)})\n")
                    f.write("-" * 80 + "\n")
                    for alert in severity_alerts:
                        f.write(f"Type: {alert.get('type', 'unknown')}\n")
                        f.write(f"Message: {alert.get('message', 'No description')}\n")
                        if 'domain' in alert:
                            f.write(f"Domain: {alert['domain']}\n")
                        if 'destination' in alert:
                            f.write(f"Destination: {alert['destination']}\n")
                        if 'protocol' in alert:
                            f.write(f"Protocol: {alert['protocol']}\n")
                        f.write("\n")
        else:
            f.write("No security alerts detected.\n\n")
        
        # Device section
        f.write("DEVICE PROFILES\n")
        f.write("=" * 80 + "\n\n")
        for ip, device in devices.items():
            summary = device.get_summary()
            # Display device with hostname if available
            if summary['device_hostname']:
                f.write(f"Device: {summary['device_hostname']} ({ip})\n")
            else:
                f.write(f"Device: {ip}\n")
            f.write("-" * 80 + "\n")
            if summary['mac_address']:
                f.write(f"MAC Address: {summary['mac_address']}\n")
            if summary['device_hostname']:
                f.write(f"Hostname: {summary['device_hostname']}\n")
            if summary['user_accounts']:
                f.write(f"User Accounts: {', '.join(summary['user_accounts'])}\n")
            if summary['hostnames']:
                f.write(f"DNS Hostnames: {', '.join(summary['hostnames'])}\n")
            f.write(f"Connections: {summary['total_connections']}\n")
            f.write(f"Data Sent: {summary['bytes_sent'] / 1024:.2f} KB\n")
            f.write(f"Data Received: {summary['bytes_received'] / 1024:.2f} KB\n")
            f.write(f"Unique Destinations: {summary['unique_destinations']}\n")
            f.write(f"DNS Queries: {summary['dns_query_count']}\n")
            if summary['large_uploads_count'] > 0:
                f.write(f"Large Uploads Detected: {summary['large_uploads_count']}\n")
            f.write(f"Alerts: {summary['alert_count']}\n")
            f.write("\n")
    
    print(f"Text report saved to {output_file}")
