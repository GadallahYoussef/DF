#!/usr/bin/env python3
"""Basic tests for the Network Packet Investigator."""

import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from network_investigator.detectors.whitelist import is_whitelisted
from network_investigator.detectors.typosquat import TyposquatDetector
from network_investigator.detectors.exfiltration import DataExfiltrationDetector
from network_investigator.utils.entropy import calculate_entropy
from network_investigator.models.device import DeviceProfile


def test_whitelist():
    """Test whitelist functionality."""
    print("Testing whitelist...")
    
    # Should be whitelisted
    assert is_whitelisted('google.com')
    assert is_whitelisted('www.google.com')
    assert is_whitelisted('bing.com')
    assert is_whitelisted('www.bing.com')
    assert is_whitelisted('microsoft.com')
    assert is_whitelisted('googleadservices.com')
    assert is_whitelisted('_googlecast._tcp.local')
    
    # Should NOT be whitelisted
    assert not is_whitelisted('eventdata-microsoft.live')
    assert not is_whitelisted('dng-microsoftds.com')
    
    print("✓ Whitelist tests passed")


def test_typosquatting():
    """Test typosquatting detection."""
    print("\nTesting typosquatting detection...")
    
    detector = TyposquatDetector()
    
    # Should NOT flag legitimate domains (whitelisted)
    alerts = detector.check_typosquatting('bing.com')
    assert len(alerts) == 0, f"bing.com should not be flagged, got {alerts}"
    
    alerts = detector.check_typosquatting('www.bing.com')
    assert len(alerts) == 0, "www.bing.com should not be flagged"
    
    alerts = detector.check_typosquatting('google.com')
    assert len(alerts) == 0, "google.com should not be flagged"
    
    alerts = detector.check_typosquatting('googleadservices.com')
    assert len(alerts) == 0, "googleadservices.com should not be flagged"
    
    # Should NOT flag mDNS/local domains
    alerts = detector.check_typosquatting('_googlecast._tcp.local')
    assert len(alerts) == 0, "_googlecast._tcp.local should not be flagged"
    
    # Should flag suspicious domains with edit distance 1
    alerts = detector.check_typosquatting('gooogle.com')  # Extra 'o'
    assert len(alerts) > 0, "gooogle.com should be flagged"
    
    alerts = detector.check_typosquatting('micr0soft.com')  # '0' instead of 'o'
    assert len(alerts) > 0, "micr0soft.com should be flagged"
    
    print("✓ Typosquatting tests passed")


def test_beaconing():
    """Test beaconing detection."""
    print("\nTesting beaconing detection...")
    
    detector = DataExfiltrationDetector()
    
    # Simulate fast connections (should NOT be flagged)
    for i in range(20):
        detector.track_connection('192.168.1.100', i * 1.0, 'TCP')
    
    alerts = detector.check_beaconing()
    assert len(alerts) == 0, "Fast connections should not be flagged as beaconing"
    
    # Simulate regular beaconing (should be flagged)
    detector2 = DataExfiltrationDetector()
    for i in range(15):
        detector2.track_connection('10.0.0.50', i * 60.0, 'TCP')  # Every 60 seconds
    
    alerts = detector2.check_beaconing()
    assert len(alerts) > 0, "Regular 60-second intervals should be flagged"
    
    # Whitelisted destination should NOT be flagged
    detector3 = DataExfiltrationDetector()
    for i in range(15):
        detector3.track_connection('google.com', i * 60.0, 'TCP')
    
    alerts = detector3.check_beaconing()
    assert len(alerts) == 0, "Whitelisted destinations should not be flagged"
    
    print("✓ Beaconing tests passed")


def test_entropy():
    """Test entropy calculation."""
    print("\nTesting entropy calculation...")
    
    # Low entropy (repeated characters)
    low_entropy = calculate_entropy('aaaaaaaaaa')
    assert low_entropy < 1.0, f"Expected low entropy, got {low_entropy}"
    
    # High entropy (random-looking)
    high_entropy = calculate_entropy('8f7d9a2b1c3e4g5h')
    assert high_entropy > 3.0, f"Expected high entropy, got {high_entropy}"
    
    print("✓ Entropy tests passed")


def test_deduplication():
    """Test alert deduplication."""
    print("\nTesting alert deduplication...")
    
    detector = TyposquatDetector()
    
    # Same domain multiple times should only generate one alert
    alerts1 = detector.check_typosquatting('gooogle.com')
    alerts2 = detector.check_typosquatting('gooogle.com')
    alerts3 = detector.check_typosquatting('gooogle.com')
    
    assert len(alerts1) > 0, "First check should generate alert"
    assert len(alerts2) == 0, "Second check should not generate duplicate"
    assert len(alerts3) == 0, "Third check should not generate duplicate"
    
    print("✓ Deduplication tests passed")


def test_device_profile_enhancements():
    """Test new DeviceProfile fields and functionality."""
    print("\nTesting enhanced DeviceProfile...")
    
    # Create a device profile
    device = DeviceProfile('192.168.1.100', 'AA:BB:CC:DD:EE:FF')
    
    # Test initial values
    assert device.dns_query_count == 0, "Initial DNS query count should be 0"
    assert len(device.unique_destinations) == 0, "Initial unique destinations should be empty"
    assert len(device.large_uploads) == 0, "Initial large uploads should be empty"
    
    # Test DNS query tracking
    device.add_dns_query('example.com')
    device.add_dns_query('test.com')
    device.add_dns_query('example.com')  # Duplicate
    assert device.dns_query_count == 3, f"DNS query count should be 3, got {device.dns_query_count}"
    
    # Test unique destinations tracking
    device.add_connection('10.0.0.1', 1000.0, 'TCP')
    device.add_connection('10.0.0.2', 1001.0, 'TCP')
    device.add_connection('10.0.0.1', 1002.0, 'TCP')  # Duplicate destination
    assert len(device.unique_destinations) == 2, f"Should have 2 unique destinations, got {len(device.unique_destinations)}"
    assert '10.0.0.1' in device.unique_destinations, "10.0.0.1 should be in unique destinations"
    assert '10.0.0.2' in device.unique_destinations, "10.0.0.2 should be in unique destinations"
    
    # Test large upload tracking
    device.add_large_upload('10.0.0.5', 52428800, 2000.0)  # 50MB
    device.add_large_upload('10.0.0.6', 104857600, 2001.0)  # 100MB
    assert len(device.large_uploads) == 2, f"Should have 2 large uploads, got {len(device.large_uploads)}"
    assert device.large_uploads[0]['destination'] == '10.0.0.5', "First upload destination should be 10.0.0.5"
    assert device.large_uploads[0]['bytes'] == 52428800, "First upload bytes should be 52428800"
    
    # Test get_summary includes new fields
    summary = device.get_summary()
    assert 'dns_query_count' in summary, "Summary should include dns_query_count"
    assert 'unique_destinations' in summary, "Summary should include unique_destinations"
    assert 'large_uploads_count' in summary, "Summary should include large_uploads_count"
    assert 'unique_domains_count' in summary, "Summary should include unique_domains_count"
    assert summary['dns_query_count'] == 3, f"Summary dns_query_count should be 3, got {summary['dns_query_count']}"
    assert summary['unique_destinations'] == 2, f"Summary unique_destinations should be 2, got {summary['unique_destinations']}"
    assert summary['large_uploads_count'] == 2, f"Summary large_uploads_count should be 2, got {summary['large_uploads_count']}"
    assert summary['unique_domains_count'] == 2, f"Summary unique_domains_count should be 2, got {summary['unique_domains_count']}"
    
    print("✓ Enhanced DeviceProfile tests passed")


if __name__ == '__main__':
    print("=" * 60)
    print("Running Network Packet Investigator Tests")
    print("=" * 60)
    
    try:
        test_whitelist()
        test_typosquatting()
        test_beaconing()
        test_entropy()
        test_deduplication()
        test_device_profile_enhancements()
        
        print("\n" + "=" * 60)
        print("✅ All tests passed!")
        print("=" * 60)
        sys.exit(0)
    except AssertionError as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
