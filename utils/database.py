"""
Database Manager - SQLite schema, initialization, and seeding.
"""

import sqlite3
import random
from datetime import datetime, timedelta
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'netwatch.db')


class DatabaseManager:
    def get_connection(self):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def initialize(self):
        conn = self.get_connection()
        cursor = conn.cursor()

        # Devices table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT UNIQUE NOT NULL,
                ip_address TEXT,
                hostname TEXT,
                device_name TEXT,
                device_type TEXT DEFAULT 'unknown',
                vendor TEXT,
                notes TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Access logs
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT NOT NULL,
                device_mac TEXT,
                domain TEXT NOT NULL,
                category TEXT,
                status TEXT NOT NULL CHECK(status IN ('ALLOWED','BLOCKED')),
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                response_time_ms INTEGER DEFAULT 0
            )
        """)

        # Blocked domains
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS blocked_domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                category TEXT DEFAULT 'custom',
                reason TEXT,
                active INTEGER DEFAULT 1,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Alerts log
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                device_mac TEXT,
                domain TEXT,
                alert_type TEXT,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                channel TEXT,
                success INTEGER DEFAULT 0
            )
        """)

        # Settings
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON access_logs(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON access_logs(domain)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_device ON access_logs(device_mac)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_blocked_domain ON blocked_domains(domain)")

        conn.commit()
        conn.close()
        print("✅ Database initialized")

    def seed_demo_data(self):
        return  # disabled - using real data only

        print("🌱 Seeding demo data...")

        # Devices
        devices = [
            ('AA:BB:CC:11:22:33', '192.168.1.101', 'MacBook-Pro', 'Alice\'s MacBook', 'laptop', 'Apple'),
            ('AA:BB:CC:44:55:66', '192.168.1.102', 'iPhone-Alice', 'Alice\'s iPhone', 'mobile', 'Apple'),
            ('DD:EE:FF:11:22:33', '192.168.1.103', 'SAMSUNG-TV', 'Living Room TV', 'smart-tv', 'Samsung'),
            ('DD:EE:FF:44:55:66', '192.168.1.104', 'Bob-Laptop', 'Bob\'s Dell', 'laptop', 'Dell'),
            ('11:22:33:AA:BB:CC', '192.168.1.105', 'Android-Bob', 'Bob\'s Phone', 'mobile', 'Samsung'),
            ('11:22:33:DD:EE:FF', '192.168.1.106', 'Kindle-Fire', 'Kids Tablet', 'tablet', 'Amazon'),
            ('55:66:77:AA:BB:CC', '192.168.1.107', 'PS5-Console', 'PlayStation 5', 'gaming', 'Sony'),
        ]
        for d in devices:
            try:
                conn.execute("""
                    INSERT INTO devices (mac_address, ip_address, hostname, device_name, device_type, vendor)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, d)
            except sqlite3.IntegrityError:
                pass

        # Default settings
        default_settings = [
            ('alert_telegram', '0'),
            ('alert_email', '0'),
            ('telegram_token', ''),
            ('telegram_chat_id', ''),
            ('email_smtp', 'smtp.gmail.com'),
            ('email_port', '587'),
            ('email_user', ''),
            ('email_password', ''),
            ('email_to', ''),
            ('alert_threshold', '3'),
            ('dns_interface', 'all'),
            ('log_retention_days', '30'),
        ]
        for key, val in default_settings:
            try:
                conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (key, val))
            except sqlite3.IntegrityError:
                pass

        # Blocked domains - comprehensive list
        blocked_list = [
            # Adult
            ('pornhub.com', 'adult', 'Adult content'),
            ('xvideos.com', 'adult', 'Adult content'),
            ('xhamster.com', 'adult', 'Adult content'),
            ('onlyfans.com', 'adult', 'Adult content'),
            # Gambling
            ('bet365.com', 'gambling', 'Online gambling'),
            ('pokerstars.com', 'gambling', 'Online gambling'),
            ('draftkings.com', 'gambling', 'Online gambling'),
            # Malware/Phishing
            ('malware-site.com', 'malware', 'Known malware distributor'),
            ('phishing-test.net', 'phishing', 'Phishing site'),
            ('cryptominer.io', 'malware', 'Cryptomining scripts'),
            # Social (example school filtering)
            ('tiktok.com', 'social', 'Social media - school hours'),
            # Ads/Trackers
            ('doubleclick.net', 'ads', 'Ad network tracker'),
            ('adservice.google.com', 'ads', 'Ad service'),
        ]
        for domain, cat, reason in blocked_list:
            try:
                conn.execute(
                    "INSERT INTO blocked_domains (domain, category, reason, active) VALUES (?, ?, ?, 1)",
                    (domain, cat, reason)
                )
            except sqlite3.IntegrityError:
                pass

        # Generate realistic access logs - last 48 hours
        allowed_domains = [
            ('google.com', 'search'), ('youtube.com', 'media'),
            ('github.com', 'development'), ('stackoverflow.com', 'development'),
            ('netflix.com', 'media'), ('spotify.com', 'media'),
            ('amazon.com', 'shopping'), ('reddit.com', 'social'),
            ('twitter.com', 'social'), ('linkedin.com', 'social'),
            ('wikipedia.org', 'reference'), ('news.ycombinator.com', 'news'),
            ('cloudflare.com', 'tech'), ('apple.com', 'tech'),
            ('microsoft.com', 'tech'), ('zoom.us', 'business'),
            ('slack.com', 'business'), ('docs.google.com', 'productivity'),
            ('mail.google.com', 'email'), ('calendar.google.com', 'productivity'),
            ('bbc.com', 'news'), ('cnn.com', 'news'),
            ('weather.com', 'reference'), ('maps.google.com', 'maps'),
        ]
        blocked_domains_demo = [
            ('pornhub.com', 'adult'), ('bet365.com', 'gambling'),
            ('tiktok.com', 'social'), ('malware-site.com', 'malware'),
            ('xvideos.com', 'adult'), ('pokerstars.com', 'gambling'),
        ]

        logs = []
        now = datetime.now()
        
        for i in range(2000):
            # Random time in last 48 hours
            minutes_ago = random.randint(0, 48 * 60)
            ts = now - timedelta(minutes=minutes_ago)
            
            device = random.choice(devices)
            device_ip = device[1]
            device_mac = device[0]
            
            # 85% chance allowed, 15% blocked
            if random.random() < 0.85:
                domain, category = random.choice(allowed_domains)
                status = 'ALLOWED'
            else:
                domain, category = random.choice(blocked_domains_demo)
                status = 'BLOCKED'
            
            logs.append((device_ip, device_mac, domain, category, status, ts.strftime('%Y-%m-%d %H:%M:%S')))

        conn.executemany("""
            INSERT INTO access_logs (device_ip, device_mac, domain, category, status, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        """, logs)

        conn.commit()
        conn.close()
        print(f"✅ Seeded {len(logs)} demo log entries")

    def is_domain_blocked(self, domain: str) -> tuple:
        """Check if domain matches any blocked pattern. Returns (is_blocked, category, reason)."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Exact match
        cursor.execute(
            "SELECT category, reason FROM blocked_domains WHERE domain=? AND active=1",
            (domain,)
        )
        row = cursor.fetchone()
        if row:
            conn.close()
            return True, row[0], row[1]
        
        # Subdomain match (e.g., sub.pornhub.com matches pornhub.com)
        parts = domain.split('.')
        for i in range(1, len(parts)):
            parent = '.'.join(parts[i:])
            cursor.execute(
                "SELECT category, reason FROM blocked_domains WHERE domain=? AND active=1",
                (parent,)
            )
            row = cursor.fetchone()
            if row:
                conn.close()
                return True, row[0], row[1]
        
        conn.close()
        return False, None, None

    def log_access(self, device_ip: str, device_mac: str, domain: str,
                   category: str, status: str):
        """Write an access log entry."""
        conn = self.get_connection()
        conn.execute("""
            INSERT INTO access_logs (device_ip, device_mac, domain, category, status)
            VALUES (?, ?, ?, ?, ?)
        """, (device_ip, device_mac, domain, category or '', status))
        
        # Update device last seen
        conn.execute("""
            INSERT INTO devices (mac_address, ip_address, last_seen)
            VALUES (?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(mac_address) DO UPDATE SET
                ip_address = excluded.ip_address,
                last_seen = CURRENT_TIMESTAMP
        """, (device_mac, device_ip))
        
        conn.commit()
        conn.close()
