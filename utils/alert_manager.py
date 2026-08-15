"""
Alert Manager - Sends notifications via Telegram or Email.
"""

import smtplib
import sqlite3
import urllib.request
import urllib.parse
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime


DB_PATH = 'netwatch.db'


class AlertManager:
    def __init__(self):
        self.settings = {}
        self.reload_settings()

    def reload_settings(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM settings")
            self.settings = {row[0]: row[1] for row in cursor.fetchall()}
            conn.close()
        except Exception:
            pass

    def send_alert(self, event: dict):
        """Send alert through enabled channels."""
        if self.settings.get('alert_telegram') == '1':
            self._send_telegram(event)
        if self.settings.get('alert_email') == '1':
            self._send_email(event)

    def _format_message(self, event: dict) -> str:
        return (
            f"🚨 NetWatch Alert\n"
            f"━━━━━━━━━━━━━━━\n"
            f"⛔ BLOCKED: {event['domain']}\n"
            f"📱 Device: {event['device_ip']} ({event['device_mac']})\n"
            f"🏷️  Category: {event.get('category', 'unknown')}\n"
            f"⏰ Time: {event['timestamp'][:19].replace('T', ' ')}\n"
            f"📋 Reason: {event.get('reason', 'Policy violation')}"
        )

    def _send_telegram(self, event: dict):
        token = self.settings.get('telegram_token', '')
        chat_id = self.settings.get('telegram_chat_id', '')
        
        if not token or not chat_id:
            return
        
        message = self._format_message(event)
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        
        try:
            data = json.dumps({
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }).encode('utf-8')
            
            req = urllib.request.Request(url, data=data,
                                          headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=5)
            self._log_alert(event, 'telegram', success=True)
        except Exception as e:
            print(f"Telegram alert failed: {e}")
            self._log_alert(event, 'telegram', success=False)

    def _send_email(self, event: dict):
        smtp_host = self.settings.get('email_smtp', 'smtp.gmail.com')
        smtp_port = int(self.settings.get('email_port', 587))
        user = self.settings.get('email_user', '')
        password = self.settings.get('email_password', '')
        recipient = self.settings.get('email_to', '')
        
        if not all([user, password, recipient]):
            return
        
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"🚨 NetWatch: Blocked - {event['domain']}"
            msg['From'] = user
            msg['To'] = recipient
            
            text_body = self._format_message(event)
            html_body = f"""
            <html><body style="font-family:Arial,sans-serif;max-width:500px;margin:20px auto;
                  padding:20px;border:1px solid #e0e0e0;border-radius:8px;">
              <h2 style="color:#e53e3e;">🚨 NetWatch Security Alert</h2>
              <table style="width:100%;border-collapse:collapse;">
                <tr><td style="padding:8px;color:#666;">Blocked Domain</td>
                    <td style="padding:8px;font-weight:bold;color:#e53e3e;">{event['domain']}</td></tr>
                <tr style="background:#f9f9f9;">
                    <td style="padding:8px;color:#666;">Device IP</td>
                    <td style="padding:8px;">{event['device_ip']}</td></tr>
                <tr><td style="padding:8px;color:#666;">MAC Address</td>
                    <td style="padding:8px;">{event['device_mac']}</td></tr>
                <tr style="background:#f9f9f9;">
                    <td style="padding:8px;color:#666;">Category</td>
                    <td style="padding:8px;">{event.get('category','unknown')}</td></tr>
                <tr><td style="padding:8px;color:#666;">Timestamp</td>
                    <td style="padding:8px;">{event['timestamp'][:19].replace('T',' ')}</td></tr>
              </table>
              <p style="color:#888;font-size:12px;margin-top:20px;">
                NetWatch Network Monitoring System
              </p>
            </body></html>"""
            
            msg.attach(MIMEText(text_body, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()
            server.login(user, password)
            server.sendmail(user, recipient, msg.as_string())
            server.quit()
            self._log_alert(event, 'email', success=True)
        except Exception as e:
            print(f"Email alert failed: {e}")
            self._log_alert(event, 'email', success=False)

    def _log_alert(self, event: dict, channel: str, success: bool):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("""
                INSERT INTO alerts (device_ip, device_mac, domain, alert_type, channel, success)
                VALUES (?, ?, ?, 'blocked', ?, ?)
            """, (event['device_ip'], event['device_mac'], event['domain'], channel, int(success)))
            conn.commit()
            conn.close()
        except Exception:
            pass
