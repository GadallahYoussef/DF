# Network Packet Investigator

A sophisticated network traffic analyzer that detects security threats with minimal false positives.

## Features

- **Typosquatting Detection**: Identifies domains that impersonate legitimate brands
- **Data Exfiltration Detection**: Detects large uploads and suspicious data transfers
- **C2 Beaconing Detection**: Identifies regular communication patterns indicating command & control
- **DNS Tunneling Detection**: Flags suspicious DNS query patterns
- **Comprehensive Whitelisting**: Pre-configured whitelist for major tech companies and CDNs
- **Multiple Export Formats**: JSON, HTML, and plain text reports

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python -m network_investigator path/to/capture.pcap
```

### Specify Output Format

```bash
# Generate only HTML report
python -m network_investigator capture.pcap -f html

# Generate only JSON report
python -m network_investigator capture.pcap -f json -o output

# Generate all formats (default)
python -m network_investigator capture.pcap -f all
```

### Programmatic Usage

```python
from network_investigator import PacketInvestigator

# Create investigator
investigator = PacketInvestigator('capture.pcap')

# Analyze traffic
investigator.analyze()

# Export results
investigator.export_results(format='html', output_prefix='my_report')
```

## Architecture

The tool is organized into modular components:

```
network_investigator/
├── __init__.py
├── __main__.py           # Entry point
├── investigator.py       # Main PacketInvestigator class
├── detectors/
│   ├── __init__.py
│   ├── typosquat.py      # TyposquatDetector class
│   ├── exfiltration.py   # DataExfiltrationDetector class
│   └── whitelist.py      # Whitelist management
├── models/
│   ├── __init__.py
│   └── device.py         # DeviceProfile class
├── exporters/
│   ├── __init__.py
│   ├── json_export.py
│   ├── html_export.py
│   └── text_export.py
└── utils/
    ├── __init__.py
    └── entropy.py        # Entropy calculation utilities
```

## Detection Logic

### Typosquatting
- Edit distance of 1 for brand names (prevents false positives like "bing" vs "bank")
- Checks against comprehensive brand list
- Skips mDNS/local domains (*.local, *._tcp.*, *._udp.*)
- Whitelisted domains checked BEFORE detection

### Beaconing Detection
- Requires minimum 30+ second intervals (ignores fast normal traffic)
- Requires at least 10 connections
- Checks for regular intervals (low variance relative to mean)
- Automatically skips whitelisted destinations

### Data Exfiltration
- Flags uploads over 50 MB
- Tracks data transfer per destination
- Skips whitelisted services

### False Positive Prevention
- Comprehensive whitelist for Microsoft, Google, Apple, Amazon, Meta, CDNs
- Infrastructure domain filtering (.arpa, service discovery, WPAD, ISATAP)
- Alert deduplication by type + domain/IP + source
- Proper thresholds to avoid flagging normal traffic

## Test Cases
- https://www.malware-traffic-analysis.net/2025/06/13/2025-06-13-traffic-analysis-exercise.pcap.zip Password: infected_20250613
- https://www.malware-traffic-analysis.net/2025/01/22/2025-01-22-traffic-analysis-exercise.pcap.zip Password: infected_20250122
- Psexec lab on Cyberdefenders
