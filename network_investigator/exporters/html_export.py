"""HTML export functionality."""

from datetime import datetime


def export_html(devices, alerts, output_file='report.html', stats=None):
    """
    Export analysis results to HTML format.
    
    Args:
        devices: Dictionary of DeviceProfile objects
        alerts: List of alert dictionaries
        output_file: Path to output file
        stats: Dictionary of statistics (optional)
    """
    if stats is None:
        stats = {}
    # Count alerts by type
    alert_types = {}
    for alert in alerts:
        alert_type = alert.get('type', 'unknown')
        alert_types[alert_type] = alert_types.get(alert_type, 0) + 1
    
    # Group alerts by severity
    severity_order = ['critical', 'high', 'medium', 'low']
    alerts_by_severity = {sev: [] for sev in severity_order}
    
    for alert in alerts:
        severity = alert.get('severity', 'low')
        alerts_by_severity[severity].append(alert)
    
    # Generate HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Packet Investigator Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
            border-bottom: 2px solid #ddd;
            padding-bottom: 5px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .summary-card {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            color: #666;
            font-size: 14px;
            text-transform: uppercase;
        }}
        .summary-card .value {{
            font-size: 32px;
            font-weight: bold;
            color: #333;
        }}
        .alert {{
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid;
        }}
        .alert.critical {{
            background-color: #ffe6e6;
            border-color: #dc3545;
        }}
        .alert.high {{
            background-color: #fff3cd;
            border-color: #ffc107;
        }}
        .alert.medium {{
            background-color: #d1ecf1;
            border-color: #17a2b8;
        }}
        .alert.low {{
            background-color: #d4edda;
            border-color: #28a745;
        }}
        .alert-header {{
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .alert-type {{
            display: inline-block;
            background-color: rgba(0,0,0,0.1);
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 12px;
            margin-right: 10px;
        }}
        .device {{
            background-color: #f8f9fa;
            margin: 15px 0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #6c757d;
        }}
        .device-header {{
            font-weight: bold;
            font-size: 18px;
            margin-bottom: 10px;
            color: #333;
        }}
        .device-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
        }}
        .info-item {{
            padding: 5px 0;
        }}
        .info-label {{
            font-weight: bold;
            color: #666;
        }}
        .timestamp {{
            color: #999;
            font-size: 14px;
        }}
        .no-alerts {{
            padding: 20px;
            text-align: center;
            color: #28a745;
            background-color: #d4edda;
            border-radius: 5px;
            font-size: 18px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 8px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #f8f9fa;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 Network Packet Investigator Report</h1>
        <p class="timestamp">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <h3>Total Devices</h3>
                <div class="value">{len(devices)}</div>
            </div>
            <div class="summary-card">
                <h3>Total Alerts</h3>
                <div class="value">{len(alerts)}</div>
            </div>
"""
    
    # Add alert type breakdown
    for alert_type, count in sorted(alert_types.items()):
        html += f"""
            <div class="summary-card">
                <h3>{alert_type.replace('_', ' ').title()}</h3>
                <div class="value">{count}</div>
            </div>
"""
    
    # Add typosquat and exfiltration detection stats
    if stats.get('typosquat_detections', 0) > 0:
        html += f"""
            <div class="summary-card" style="border-left-color: #dc3545;">
                <h3>Typosquat Detections</h3>
                <div class="value" style="color: #dc3545;">{stats['typosquat_detections']}</div>
            </div>
"""
    
    if stats.get('exfiltration_detections', 0) > 0:
        html += f"""
            <div class="summary-card" style="border-left-color: #dc3545;">
                <h3>Exfiltration Detections</h3>
                <div class="value" style="color: #dc3545;">{stats['exfiltration_detections']}</div>
            </div>
"""
    
    html += """
        </div>
        
        <h2>Security Alerts</h2>
"""
    
    if alerts:
        for severity in severity_order:
            severity_alerts = alerts_by_severity[severity]
            if severity_alerts:
                html += f"""
        <h3>{severity.upper()} Severity ({len(severity_alerts)})</h3>
"""
                for alert in severity_alerts:
                    html += f"""
        <div class="alert {severity}">
            <div class="alert-header">
                <span class="alert-type">{alert.get('type', 'unknown').upper()}</span>
                {alert.get('message', 'No description')}
            </div>
"""
                    if 'domain' in alert:
                        html += f"""
            <div>Domain: <strong>{alert['domain']}</strong></div>
"""
                    if 'destination' in alert:
                        html += f"""
            <div>Destination: <strong>{alert['destination']}</strong></div>
"""
                    if 'protocol' in alert:
                        html += f"""
            <div>Protocol: <strong>{alert['protocol']}</strong></div>
"""
                    html += """
        </div>
"""
    else:
        html += """
        <div class="no-alerts">
            ✅ No security alerts detected. Your network traffic appears clean!
        </div>
"""
    
    # Device profiles
    html += """
        <h2>Device Profiles</h2>
"""
    
    for ip, device in devices.items():
        summary = device.get_summary()
        html += f"""
        <div class="device">
            <div class="device-header">📱 Device: {ip}</div>
            <div class="device-info">
"""
        if summary['mac_address']:
            html += f"""
                <div class="info-item">
                    <span class="info-label">MAC Address:</span> {summary['mac_address']}
                </div>
"""
        if summary['hostnames']:
            html += f"""
                <div class="info-item">
                    <span class="info-label">Hostnames:</span> {', '.join(summary['hostnames'])}
                </div>
"""
        html += f"""
                <div class="info-item">
                    <span class="info-label">Connections:</span> {summary['total_connections']}
                </div>
                <div class="info-item">
                    <span class="info-label">Data Sent:</span> {summary['bytes_sent'] / 1024:.2f} KB
                </div>
                <div class="info-item">
                    <span class="info-label">Data Received:</span> {summary['bytes_received'] / 1024:.2f} KB
                </div>
                <div class="info-item">
                    <span class="info-label">Unique Destinations:</span> {summary['unique_destinations']}
                </div>
                <div class="info-item">
                    <span class="info-label">DNS Queries:</span> {summary['dns_query_count']}
                </div>
                <div class="info-item">
                    <span class="info-label">Alerts:</span> {summary['alert_count']}
                </div>
"""
        
        # Add large uploads warning if detected
        if summary['large_uploads_count'] > 0:
            html += f"""
                <div class="info-item" style="grid-column: 1 / -1;">
                    <span style="color: #c62828; font-weight: bold;">📤 Large Uploads:</span> {summary['large_uploads_count']} detected
                </div>
"""
        
        html += """
            </div>
        </div>
"""
    
    html += """
    </div>
</body>
</html>
"""
    
    # Write to file
    with open(output_file, 'w') as f:
        f.write(html)
    
    print(f"HTML report saved to {output_file}")
