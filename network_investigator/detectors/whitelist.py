"""Whitelist management for legitimate domains."""

# Comprehensive whitelist for major tech companies and CDNs
WHITELISTED_DOMAINS = {
    # Microsoft
    'microsoft.com', 'microsoftonline.com', 'live.com', 'outlook.com',
    'office.com', 'office365.com', 'windows.com', 'xbox.com',
    'msn.com', 'bing.com', 'windowsupdate.com', 'azure.com',
    'visualstudio.com', 'github.com', 'skype.com',
    
    # Google
    'google.com', 'googleapis.com', 'googleusercontent.com',
    'googleadservices.com', 'googlesyndication.com', 'googletagmanager.com',
    'gstatic.com', 'youtube.com', 'ytimg.com', 'gmail.com',
    'android.com', 'chrome.com', 'chromium.org',
    
    # Apple
    'apple.com', 'icloud.com', 'itunes.com', 'me.com',
    'appstore.com', 'applemusic.com', 'cdn-apple.com',
    
    # Amazon
    'amazon.com', 'amazonaws.com', 'cloudfront.net', 'aws.amazon.com',
    'awsstatic.com', 'amazon-adsystem.com',
    
    # Meta/Facebook
    'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com',
    'whatsapp.com', 'messenger.com', 'oculus.com',
    
    # CDNs and Infrastructure
    'akamai.net', 'cloudflare.com', 'cloudflare.net', 'fastly.net',
    'edgecast.net', 'akamaitechnologies.com', 'limelight.com',
    'cdn77.com', 'keycdn.com', 'stackpathcdn.com',
    
    # Other major tech companies
    'mozilla.org', 'firefox.com', 'adobe.com', 'adobedtm.com',
    'twitter.com', 'linkedin.com', 'netflix.com', 'spotify.com',
    'dropbox.com', 'slack.com', 'zoom.us', 'salesforce.com',
}

# Infrastructure domains to skip
INFRASTRUCTURE_PATTERNS = [
    '.arpa',  # Reverse DNS
    '_tcp.',  # Service discovery
    '_udp.',  # Service discovery
    '.local',  # mDNS
    '_ldap.',
    '_kerberos.',
    '_msdcs.',
    'wpad.',
    'isatap.',
]


def is_whitelisted(domain):
    """
    Check if a domain is whitelisted.
    
    Args:
        domain: Domain name to check
        
    Returns:
        True if whitelisted, False otherwise
    """
    if not domain:
        return False
    
    domain = domain.lower().strip('.')
    
    # Check infrastructure patterns first
    for pattern in INFRASTRUCTURE_PATTERNS:
        if pattern in domain:
            return True
    
    # Check exact match
    if domain in WHITELISTED_DOMAINS:
        return True
    
    # Check if it's a subdomain of a whitelisted domain
    parts = domain.split('.')
    for i in range(len(parts)):
        parent_domain = '.'.join(parts[i:])
        if parent_domain in WHITELISTED_DOMAINS:
            return True
    
    return False
