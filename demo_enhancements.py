#!/usr/bin/env python3
"""
Demonstration of the enhanced reporting features for the Network Packet Investigator.
This shows the new device profile tracking and statistics features.
"""

import sys
import os
from datetime import datetime

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from network_investigator.models import DeviceProfile
from network_investigator.detectors import TyposquatDetector, DataExfiltrationDetector
from network_investigator.exporters import export_html, export_text, export_json


def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def demo_enhanced_device_tracking():
    """Demonstrate enhanced device profile tracking."""
    print_section("ENHANCED DEVICE PROFILE TRACKING")
    
    # Create a device profile
    device = DeviceProfile('192.168.1.100', 'AA:BB:CC:DD:EE:FF')
    device.add_hostname('WORKSTATION-01')
    
    print("\n📱 Creating device profile for 192.168.1.100")
    
    # Simulate DNS queries
    print("\n📊 Tracking DNS queries:")
    dns_queries = [
        'google.com', 'facebook.com', 'twitter.com',
        'google.com', 'github.com', 'stackoverflow.com',
        'facebook.com', 'reddit.com'
    ]
    for query in dns_queries:
        device.add_dns_query(query)
        print(f"   - {query}")
    
    print(f"\n   Total DNS queries: {device.dns_query_count}")
    print(f"   Unique domains: {len(device.dns_queries)}")
    
    # Simulate connections
    print("\n🔗 Tracking connections:")
    connections = [
        ('10.0.0.1', 1000.0, 'TCP'),
        ('10.0.0.2', 1001.0, 'TCP'),
        ('10.0.0.3', 1002.0, 'TCP'),
        ('10.0.0.1', 1003.0, 'TCP'),  # Duplicate destination
        ('10.0.0.2', 1004.0, 'TCP'),  # Duplicate destination
        ('10.0.0.4', 1005.0, 'UDP'),
    ]
    for dest, ts, proto in connections:
        device.add_connection(dest, ts, proto)
        print(f"   - {proto} connection to {dest}")
    
    print(f"\n   Total connections: {len(device.connections)}")
    print(f"   Unique destinations: {len(device.unique_destinations)}")
    print(f"   Unique IPs: {', '.join(sorted(device.unique_destinations))}")
    
    # Simulate large uploads
    print("\n📤 Tracking large uploads:")
    device.add_large_upload('45.123.45.67', 52428800, 2000.0)  # 50MB
    print(f"   - 50 MB upload to 45.123.45.67")
    device.add_large_upload('89.234.56.78', 104857600, 2100.0)  # 100MB
    print(f"   - 100 MB upload to 89.234.56.78")
    
    print(f"\n   Large uploads detected: {len(device.large_uploads)}")
    
    # Show summary
    print("\n📋 Device Summary:")
    summary = device.get_summary()
    print(f"   IP Address: {summary['ip_address']}")
    print(f"   MAC Address: {summary['mac_address']}")
    print(f"   Hostnames: {', '.join(summary['hostnames'])}")
    print(f"   DNS Query Count: {summary['dns_query_count']}")
    print(f"   Unique Destinations: {summary['unique_destinations']}")
    print(f"   Large Uploads: {summary['large_uploads_count']}")
    print(f"   Total Connections: {summary['total_connections']}")
    
    return device


def demo_statistics_tracking():
    """Demonstrate statistics tracking for threat detections."""
    print_section("STATISTICS TRACKING")
    
    # Initialize stats
    stats = {
        'typosquat_detections': 0,
        'exfiltration_detections': 0
    }
    
    # Simulate typosquat detection
    print("\n🔍 Detecting typosquatting:")
    detector = TyposquatDetector()
    
    suspicious_domains = ['gooogle.com', 'micr0soft.com', 'facebok.com']
    for domain in suspicious_domains:
        alerts = detector.check_typosquatting(domain)
        if alerts:
            stats['typosquat_detections'] += 1
            print(f"   🚨 {domain} - TYPOSQUAT DETECTED")
    
    # Simulate exfiltration detection
    print("\n🔍 Detecting data exfiltration:")
    exfil_detector = DataExfiltrationDetector()
    
    # Simulate large upload
    exfil_detector.track_data_transfer('45.123.45.67', 60 * 1024 * 1024)  # 60MB
    upload_alerts = exfil_detector.check_large_uploads()
    if upload_alerts:
        stats['exfiltration_detections'] += len(upload_alerts)
        print(f"   🚨 Large upload detected - 60 MB")
    
    # Simulate beaconing
    for i in range(15):
        exfil_detector.track_connection('45.123.45.67', i * 60.0, 'TCP')
    beacon_alerts = exfil_detector.check_beaconing()
    if beacon_alerts:
        stats['exfiltration_detections'] += len(beacon_alerts)
        print(f"   🚨 Beaconing pattern detected")
    
    print("\n📊 Detection Statistics:")
    print(f"   Typosquat Detections: {stats['typosquat_detections']}")
    print(f"   Exfiltration Detections: {stats['exfiltration_detections']}")
    print(f"   Total Threats: {stats['typosquat_detections'] + stats['exfiltration_detections']}")
    
    return stats


def demo_report_generation(device, stats):
    """Demonstrate enhanced report generation."""
    print_section("ENHANCED REPORT GENERATION")
    
    # Create sample data for reports
    devices = {'192.168.1.100': device}
    
    # Add some alerts
    alerts = [
        {
            'type': 'typosquatting',
            'severity': 'high',
            'source': '192.168.1.100',
            'domain': 'gooogle.com',
            'message': 'Typosquatting detected: gooogle.com resembles google.com'
        },
        {
            'type': 'data_exfiltration',
            'severity': 'critical',
            'destination': '45.123.45.67',
            'message': 'Large data upload detected: 60.0 MB to 45.123.45.67'
        }
    ]
    
    print("\n📄 Generating enhanced reports with new statistics...")
    
    # Generate reports
    try:
        export_html(devices, alerts, 'demo_enhanced_report.html', stats)
        print("   ✅ HTML report generated: demo_enhanced_report.html")
        
        export_text(devices, alerts, 'demo_enhanced_report.txt', stats)
        print("   ✅ Text report generated: demo_enhanced_report.txt")
        
        export_json(devices, alerts, 'demo_enhanced_report.json', stats)
        print("   ✅ JSON report generated: demo_enhanced_report.json")
        
        print("\n📋 Reports now include:")
        print("   - Typosquat detection count")
        print("   - Exfiltration detection count")
        print("   - DNS query count per device")
        print("   - Unique destinations count per device")
        print("   - Large uploads count per device")
        
    except Exception as e:
        print(f"   ❌ Error generating reports: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Run all demonstrations."""
    print("\n" + "=" * 70)
    print("  NETWORK PACKET INVESTIGATOR - ENHANCED REPORTING DEMONSTRATION")
    print("=" * 70)
    print(f"\n  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("  Purpose: Demonstrate new device tracking and statistics features")
    
    try:
        # Demo device tracking
        device = demo_enhanced_device_tracking()
        
        # Demo statistics
        stats = demo_statistics_tracking()
        
        # Demo report generation
        demo_report_generation(device, stats)
        
        print("\n" + "=" * 70)
        print("  ✅ DEMONSTRATION COMPLETE")
        print("=" * 70)
        print("\n  Enhanced features are working correctly!")
        print("  Check the generated demo_enhanced_report.* files.\n")
        
    except Exception as e:
        print(f"\n❌ Error during demonstration: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
