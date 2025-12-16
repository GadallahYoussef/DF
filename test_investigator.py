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
