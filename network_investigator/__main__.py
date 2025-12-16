"""Entry point for running the Network Packet Investigator as a module."""

import argparse
import sys
from .investigator import PacketInvestigator


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Network Packet Investigator - Analyze network traffic for security threats'
    )
    parser.add_argument(
        'pcap_file',
        help='Path to the PCAP file to analyze'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'html', 'text', 'all'],
        default='all',
        help='Output format for the report (default: all)'
    )
    parser.add_argument(
        '-o', '--output',
        default='report',
        help='Output file prefix (default: report)'
    )
    
    args = parser.parse_args()
    
    # Create investigator and analyze
    investigator = PacketInvestigator(args.pcap_file)
    investigator.analyze()
    
    # Export results
    investigator.export_results(format=args.format, output_prefix=args.output)
    
    print("\nAnalysis complete!")
    return 0


if __name__ == '__main__':
    sys.exit(main())
