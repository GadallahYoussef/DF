"""Entropy calculation utilities for detecting encoded data."""

import math
from collections import Counter


def calculate_entropy(data):
    """
    Calculate Shannon entropy of data.
    
    Args:
        data: String or bytes to calculate entropy for
        
    Returns:
        Float representing entropy value (0-8 for bytes, 0-log2(charset) for strings)
    """
    if not data:
        return 0.0
    
    # Convert to string if bytes
    if isinstance(data, bytes):
        data = data.decode('utf-8', errors='ignore')
    
    # Count character frequencies
    counter = Counter(data)
    length = len(data)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def is_high_entropy(data, threshold=4.5):
    """
    Check if data has high entropy (potentially encoded/encrypted).
    
    Args:
        data: String or bytes to check
        threshold: Entropy threshold (default 4.5)
        
    Returns:
        True if entropy exceeds threshold, False otherwise
    """
    return calculate_entropy(data) > threshold
