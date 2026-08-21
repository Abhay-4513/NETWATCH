"""
Domain Categorizer - Classify domains by type.
"""

CATEGORY_MAP = {
    # Search
    'google.com': 'search', 'bing.com': 'search', 'duckduckgo.com': 'search',
    'yahoo.com': 'search', 'baidu.com': 'search',
    # Social
    'facebook.com': 'social', 'instagram.com': 'social', 'twitter.com': 'social',
    'tiktok.com': 'social', 'snapchat.com': 'social', 'linkedin.com': 'social',
    'reddit.com': 'social', 'pinterest.com': 'social', 'tumblr.com': 'social',
    # Media
    'youtube.com': 'media', 'netflix.com': 'media', 'spotify.com': 'media',
    'hulu.com': 'media', 'twitch.tv': 'media', 'vimeo.com': 'media',
    'disneyplus.com': 'media', 'hbomax.com': 'media', 'apple.com': 'media',
    # Development
    'github.com': 'development', 'stackoverflow.com': 'development',
    'gitlab.com': 'development', 'bitbucket.org': 'development',
    'npmjs.com': 'development', 'pypi.org': 'development',
    # Shopping
    'amazon.com': 'shopping', 'ebay.com': 'shopping', 'etsy.com': 'shopping',
    'shopify.com': 'shopping', 'aliexpress.com': 'shopping',
    # News
    'bbc.com': 'news', 'cnn.com': 'news', 'nytimes.com': 'news',
    'theguardian.com': 'news', 'reuters.com': 'news', 'ap.org': 'news',
    # Business/Productivity
    'zoom.us': 'business', 'slack.com': 'business', 'microsoft.com': 'business',
    'office.com': 'productivity', 'docs.google.com': 'productivity',
    'drive.google.com': 'productivity', 'notion.so': 'productivity',
    # Email
    'mail.google.com': 'email', 'outlook.com': 'email', 'mail.yahoo.com': 'email',
    # Gaming
    'steam.com': 'gaming', 'epicgames.com': 'gaming', 'twitch.tv': 'gaming',
    'playstation.com': 'gaming', 'xbox.com': 'gaming',
    # Ads/Tracking
    'doubleclick.net': 'ads', 'googlesyndication.com': 'ads',
    'googletagmanager.com': 'analytics', 'hotjar.com': 'analytics',
    # Adult (blocked)
    'pornhub.com': 'adult', 'xvideos.com': 'adult', 'xhamster.com': 'adult',
    # Gambling (blocked)
    'bet365.com': 'gambling', 'pokerstars.com': 'gambling',
    # Malware
    'malware-site.com': 'malware', 'phishing-test.net': 'phishing',
}

# TLD/keyword-based heuristics
KEYWORD_CATS = {
    'adult': ['porn', 'xxx', 'sex', 'nsfw', 'adult'],
    'gambling': ['bet', 'casino', 'poker', 'gambling', 'lottery', 'slots'],
    'malware': ['malware', 'virus', 'trojan', 'ransom', 'phish'],
    'news': ['news', 'times', 'herald', 'post', 'gazette', 'daily'],
    'gaming': ['game', 'games', 'gaming', 'play'],
}


class DomainCategorizer:
    def categorize(self, domain: str) -> str:
        domain = domain.lower().strip('.')
        
        # Direct match
        if domain in CATEGORY_MAP:
            return CATEGORY_MAP[domain]
        
        # Subdomain match
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            if parent in CATEGORY_MAP:
                return CATEGORY_MAP[parent]
        
        # Keyword heuristics
        for category, keywords in KEYWORD_CATS.items():
            for kw in keywords:
                if kw in domain:
                    return category
        
        return 'other'
