"""
NetWatch - Network Monitoring & Website Filtering System
Main Flask Application
"""

from flask import Flask, render_template, jsonify, request, send_file
import sqlite3
import threading
import json
import csv
import io
from datetime import datetime, timedelta
from utils.database import DatabaseManager
from utils.dns_monitor import DNSMonitor
from utils.device_tracker import DeviceTracker
from utils.alert_manager import AlertManager
from utils.domain_categorizer import DomainCategorizer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'netwatch-secret-key-change-in-production'

# Initialize managers
db = DatabaseManager()
alert_mgr = AlertManager()
categorizer = DomainCategorizer()
device_tracker = DeviceTracker(db)

# DNS Monitor (runs in background) - socketio=None uses polling mode
dns_monitor = DNSMonitor(db, alert_mgr, categorizer, socketio=None)


# ─── REST API Routes ────────────────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Overall network statistics."""
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Total requests today
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE date(timestamp) = ?", (today,))
    total_today = cursor.fetchone()[0]
    
    # Blocked today
    cursor.execute("SELECT COUNT(*) FROM access_logs WHERE status='BLOCKED' AND date(timestamp) = ?", (today,))
    blocked_today = cursor.fetchone()[0]
    
    # Active devices (last 30 min)
    cursor.execute("""
        SELECT COUNT(DISTINCT device_ip) FROM access_logs 
        WHERE timestamp > datetime('now', '-30 minutes')
    """)
    active_devices = cursor.fetchone()[0]
    
    # Total devices seen
    cursor.execute("SELECT COUNT(*) FROM devices")
    total_devices = cursor.fetchone()[0]
    
    # Blocked domains count
    cursor.execute("SELECT COUNT(*) FROM blocked_domains WHERE active=1")
    blocked_domains_count = cursor.fetchone()[0]
    
    conn.close()
    return jsonify({
        'total_today': total_today,
        'blocked_today': blocked_today,
        'active_devices': active_devices,
        'total_devices': total_devices,
        'blocked_domains_count': blocked_domains_count,
        'block_rate': round((blocked_today / total_today * 100) if total_today > 0 else 0, 1)
    })


@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Recent access logs with filters."""
    limit = request.args.get('limit', 100, type=int)
    status = request.args.get('status', None)
    device_ip = request.args.get('device_ip', None)
    hours = request.args.get('hours', 24, type=int)
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    query = """
        SELECT l.id, l.device_ip, l.device_mac, l.domain, l.timestamp, 
               l.status, l.category, d.hostname, d.device_name
        FROM access_logs l
        LEFT JOIN devices d ON l.device_mac = d.mac_address
        WHERE l.timestamp > datetime('now', ? || ' hours')
    """
    params = [f'-{hours}']
    
    if status:
        query += " AND l.status = ?"
        params.append(status)
    if device_ip:
        query += " AND l.device_ip = ?"
        params.append(device_ip)
    
    query += " ORDER BY l.timestamp DESC LIMIT ?"
    params.append(limit)
    
    cursor.execute(query, params)
    columns = [desc[0] for desc in cursor.description]
    logs = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(logs)


@app.route('/api/devices', methods=['GET'])
def get_devices():
    """List all known devices with activity stats."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT d.*, 
               COUNT(l.id) as total_requests,
               SUM(CASE WHEN l.status='BLOCKED' THEN 1 ELSE 0 END) as blocked_requests,
               MAX(l.timestamp) as last_seen
        FROM devices d
        LEFT JOIN access_logs l ON d.mac_address = l.device_mac
        GROUP BY d.mac_address
        ORDER BY last_seen DESC
    """)
    columns = [desc[0] for desc in cursor.description]
    devices = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return jsonify(devices)


@app.route('/api/devices/<mac>', methods=['GET'])
def get_device(mac):
    """Device detail with recent activity."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices WHERE mac_address = ?", (mac,))
    device = cursor.fetchone()
    if not device:
        return jsonify({'error': 'Device not found'}), 404
    columns = [desc[0] for desc in cursor.description]
    device_dict = dict(zip(columns, device))
    
    # Recent activity
    cursor.execute("""
        SELECT domain, timestamp, status, category 
        FROM access_logs WHERE device_mac = ? 
        ORDER BY timestamp DESC LIMIT 50
    """, (mac,))
    cols = [desc[0] for desc in cursor.description]
    device_dict['recent_activity'] = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(device_dict)


@app.route('/api/devices/<mac>', methods=['PUT'])
def update_device(mac):
    """Update device name/label."""
    data = request.json
    conn = db.get_connection()
    conn.execute(
        "UPDATE devices SET device_name=?, notes=? WHERE mac_address=?",
        (data.get('device_name'), data.get('notes'), mac)
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/top-domains', methods=['GET'])
def get_top_domains():
    """Top accessed domains."""
    hours = request.args.get('hours', 24, type=int)
    limit = request.args.get('limit', 20, type=int)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT domain, category,
               COUNT(*) as total,
               SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) as blocked,
               SUM(CASE WHEN status='ALLOWED' THEN 1 ELSE 0 END) as allowed
        FROM access_logs
        WHERE timestamp > datetime('now', ? || ' hours')
        GROUP BY domain
        ORDER BY total DESC
        LIMIT ?
    """, (f'-{hours}', limit))
    columns = [desc[0] for desc in cursor.description]
    domains = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return jsonify(domains)


@app.route('/api/blocked-domains', methods=['GET'])
def get_blocked_domains():
    """List of blocked domains/patterns."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM blocked_domains ORDER BY category, domain")
    columns = [desc[0] for desc in cursor.description]
    domains = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return jsonify(domains)


@app.route('/api/blocked-domains', methods=['POST'])
def add_blocked_domain():
    """Add a domain to the blocklist."""
    data = request.json
    domain = data.get('domain', '').lower().strip()
    category = data.get('category', 'custom')
    reason = data.get('reason', '')
    
    if not domain:
        return jsonify({'error': 'Domain required'}), 400
    
    conn = db.get_connection()
    try:
        conn.execute(
            "INSERT INTO blocked_domains (domain, category, reason, active) VALUES (?, ?, ?, 1)",
            (domain, category, reason)
        )
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'domain': domain})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Domain already exists'}), 409


@app.route('/api/blocked-domains/<int:domain_id>', methods=['DELETE'])
def remove_blocked_domain(domain_id):
    """Remove a domain from blocklist."""
    conn = db.get_connection()
    conn.execute("UPDATE blocked_domains SET active=0 WHERE id=?", (domain_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/blocked-domains/<int:domain_id>/toggle', methods=['POST'])
def toggle_blocked_domain(domain_id):
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT active FROM blocked_domains WHERE id=?", (domain_id,))
    row = cursor.fetchone()
    if row:
        new_state = 0 if row[0] else 1
        conn.execute("UPDATE blocked_domains SET active=? WHERE id=?", (new_state, domain_id))
        conn.commit()
    conn.close()
    return jsonify({'success': True})


@app.route('/api/timeline', methods=['GET'])
def get_timeline():
    """Hourly activity timeline for charts."""
    hours = request.args.get('hours', 24, type=int)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT strftime('%Y-%m-%d %H:00', timestamp) as hour,
               COUNT(*) as total,
               SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) as blocked
        FROM access_logs
        WHERE timestamp > datetime('now', ? || ' hours')
        GROUP BY hour ORDER BY hour
    """, (f'-{hours}',))
    columns = [desc[0] for desc in cursor.description]
    data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route('/api/categories', methods=['GET'])
def get_categories():
    """Traffic breakdown by category."""
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT category, COUNT(*) as count,
               SUM(CASE WHEN status='BLOCKED' THEN 1 ELSE 0 END) as blocked
        FROM access_logs
        WHERE timestamp > datetime('now', '-24 hours')
        AND category IS NOT NULL AND category != ''
        GROUP BY category ORDER BY count DESC
    """)
    columns = [desc[0] for desc in cursor.description]
    data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    conn.close()
    return jsonify(data)


@app.route('/api/export/csv', methods=['GET'])
def export_csv():
    """Export logs to CSV."""
    hours = request.args.get('hours', 24, type=int)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.timestamp, l.device_ip, l.device_mac, d.device_name,
               l.domain, l.category, l.status
        FROM access_logs l
        LEFT JOIN devices d ON l.device_mac = d.mac_address
        WHERE l.timestamp > datetime('now', ? || ' hours')
        ORDER BY l.timestamp DESC
    """, (f'-{hours}',))
    rows = cursor.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Device IP', 'MAC Address', 'Device Name', 'Domain', 'Category', 'Status'])
    writer.writerows(rows)
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'netwatch_logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/api/settings', methods=['GET'])
def get_settings():
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM settings")
    settings = {row[0]: row[1] for row in cursor.fetchall()}
    conn.close()
    # Never expose secrets
    for k in ['telegram_token', 'email_password']:
        if k in settings:
            settings[k] = '***' if settings[k] else ''
    return jsonify(settings)


@app.route('/api/settings', methods=['PUT'])
def update_settings():
    data = request.json
    conn = db.get_connection()
    for key, value in data.items():
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (key, str(value))
        )
    conn.commit()
    conn.close()
    # Reload alert manager settings
    alert_mgr.reload_settings()
    return jsonify({'success': True})


@app.route('/api/simulate', methods=['POST'])
def simulate_request():
    """Simulate a DNS request for demo/testing."""
    data = request.json
    domain = data.get('domain', 'example.com')
    device_ip = data.get('device_ip', '192.168.1.100')
    device_mac = data.get('device_mac', 'AA:BB:CC:DD:EE:FF')
    result = dns_monitor.process_request(domain, device_ip, device_mac)
    return jsonify(result)


@app.route('/api/recent-events', methods=['GET'])
def get_recent_events():
    """Polling endpoint for live feed (fallback when WebSocket unavailable)."""
    since_id = request.args.get('since_id', 0, type=int)
    conn = db.get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT l.id, l.device_ip, l.device_mac, l.domain, l.category, l.status,
               l.timestamp, d.device_name
        FROM access_logs l
        LEFT JOIN devices d ON l.device_mac = d.mac_address
        WHERE l.id > ?
        ORDER BY l.id DESC LIMIT 20
    """, (since_id,))
    cols = [c[0] for c in cursor.description]
    events = [dict(zip(cols, r)) for r in cursor.fetchall()]
    conn.close()
    return jsonify(events)


# ─── Main ────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    db.initialize()

    # Start DNS server — intercepts all network DNS queries
    from utils.dns_server import start_dns_server
    start_dns_server(db, dns_monitor)

    print("🛡️  NetWatch started on http://localhost:5000")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
