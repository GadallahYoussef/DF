"""JSON export functionality."""

import json
from datetime import datetime


def export_json(devices, alerts, output_file='report.json'):
    """
    Export analysis results to JSON format.
    
    Args:
        devices: Dictionary of DeviceProfile objects
        alerts: List of alert dictionaries
        output_file: Path to output file
    """
    # Prepare device summaries
    device_summaries = {}
    for ip, device in devices.items():
        device_summaries[ip] = device.get_summary()
    
    # Prepare report structure
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_devices': len(devices),
            'total_alerts': len(alerts),
            'alert_breakdown': {}
        },
        'devices': device_summaries,
        'alerts': alerts
    }
    
    # Count alerts by type
    for alert in alerts:
        alert_type = alert.get('type', 'unknown')
        report['summary']['alert_breakdown'][alert_type] = \
            report['summary']['alert_breakdown'].get(alert_type, 0) + 1
    
    # Write to file
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"JSON report saved to {output_file}")
