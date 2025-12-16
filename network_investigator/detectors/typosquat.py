"""Typosquatting detection for suspicious domains."""

import re
from .whitelist import is_whitelisted


class TyposquatDetector:
    """Detects potential typosquatting domains."""
    
    # Target brands to check for typosquatting (removed "bank" to avoid false positives)
    BRANDS = [
        'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix',
        'paypal', 'adobe', 'oracle', 'salesforce', 'twitter', 'linkedin',
        'instagram', 'youtube', 'github', 'dropbox', 'spotify', 'slack',
    ]
    
    # Suspicious words that shouldn't be combined with brands
    SUSPICIOUS_WORDS = [
        'login', 'signin', 'verify', 'secure', 'account', 'update',
        'confirm', 'password', 'billing', 'payment', 'security',
    ]
    
    def __init__(self):
        self.seen_alerts = set()
    
    @staticmethod
    def levenshtein_distance(s1, s2):
        """Calculate the Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return TyposquatDetector.levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def should_skip_domain(self, domain):
        """Check if domain should be skipped from analysis."""
        if not domain:
            return True
        
        domain = domain.lower()
        
        # Skip mDNS and service discovery domains
        if '.local' in domain or '_tcp.' in domain or '_udp.' in domain:
            return True
        
        # Skip infrastructure domains
        if domain.endswith('.arpa'):
            return True
        
        # Skip service discovery patterns
        service_patterns = ['_ldap.', '_kerberos.', '_msdcs.', 'wpad.', 'isatap.']
        if any(pattern in domain for pattern in service_patterns):
            return True
        
        return False
    
    def check_typosquatting(self, domain):
        """
        Check if a domain is potentially typosquatting a known brand.
        
        Args:
            domain: Domain name to check
            
        Returns:
            List of alert dictionaries
        """
        alerts = []
        
        if not domain or self.should_skip_domain(domain):
            return alerts
        
        # Check whitelist FIRST before any detection
        if is_whitelisted(domain):
            return alerts
        
        domain = domain.lower().strip('.')
        
        # Extract the main domain (remove subdomains for analysis)
        parts = domain.split('.')
        if len(parts) >= 2:
            main_domain = parts[-2]  # e.g., "example" from "www.example.com"
        else:
            main_domain = parts[0]
        
        # Check for typosquatting with edit distance
        for brand in self.BRANDS:
            distance = self.levenshtein_distance(main_domain, brand)
            
            # Only flag if edit distance is 1 for brands
            # This avoids false positives like "bing" vs "bank"
            if distance == 1:
                alert_key = f"typosquat:{domain}:{brand}"
                if alert_key not in self.seen_alerts:
                    self.seen_alerts.add(alert_key)
                    alerts.append({
                        'type': 'typosquatting',
                        'severity': 'high',
                        'domain': domain,
                        'message': f"Potential typosquatting of '{brand}' (edit distance: {distance})"
                    })
        
        # Check for brand name used as subdomain with suspicious TLD
        for brand in self.BRANDS:
            if brand in domain:
                # Check if brand is in subdomain but domain is not whitelisted
                suspicious_tlds = ['.live', '.tk', '.ml', '.ga', '.cf', '.xyz']
                if any(domain.endswith(tld) for tld in suspicious_tlds):
                    # Make sure it's not a legitimate use (already checked whitelist above)
                    alert_key = f"brand_subdomain:{domain}:{brand}"
                    if alert_key not in self.seen_alerts:
                        self.seen_alerts.add(alert_key)
                        alerts.append({
                            'type': 'typosquatting',
                            'severity': 'medium',
                            'domain': domain,
                            'message': f"Brand '{brand}' used with suspicious TLD"
                        })
                        break
        
        # Check for brand combined with suspicious words
        for brand in self.BRANDS:
            for word in self.SUSPICIOUS_WORDS:
                # Only flag if both brand and suspicious word are in the domain
                # and it's not a legitimate combination (already whitelisted)
                if brand in main_domain and word in main_domain:
                    alert_key = f"brand_suspicious:{domain}:{brand}:{word}"
                    if alert_key not in self.seen_alerts:
                        self.seen_alerts.add(alert_key)
                        alerts.append({
                            'type': 'typosquatting',
                            'severity': 'high',
                            'domain': domain,
                            'message': f"Brand '{brand}' combined with suspicious word '{word}'"
                        })
                        break
        
        return alerts
