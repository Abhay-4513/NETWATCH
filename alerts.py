"""NetGuard - Alert Manager"""
import os, logging, smtplib, urllib.request, json
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

logger = logging.getLogger(__name__)

class AlertManager:
    def __init__(self):
        self.email_to  = os.environ.get('NETGUARD_ALERT_EMAIL')
        self.smtp_host = os.environ.get('SMTP_HOST','smtp.gmail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT',587))
        self.smtp_user = os.environ.get('SMTP_USER','')
        self.smtp_pass = os.environ.get('SMTP_PASS','')
        self.tg_token  = os.environ.get('TELEGRAM_TOKEN','')
        self.tg_chat   = os.environ.get('TELEGRAM_CHAT_ID','')

    def send_alert(self, domain, device_ip, device_mac, category):
        ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        msg = f"BLOCKED: {domain} | Device: {device_ip} ({device_mac}) | Category: {category} | {ts}"
        logger.warning(f"ALERT: {msg}")
        if self.email_to: self._email(domain, msg)
        if self.tg_token and self.tg_chat: self._telegram(msg)

    def _email(self, domain, body):
        try:
            m = MIMEMultipart(); m['From']=self.smtp_user; m['To']=self.email_to; m['Subject']=f"[NetGuard] Blocked: {domain}"
            m.attach(MIMEText(body,'plain'))
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as s:
                s.starttls(); s.login(self.smtp_user, self.smtp_pass); s.sendmail(self.smtp_user, self.email_to, m.as_string())
        except Exception as e: logger.error(f"Email failed: {e}")

    def _telegram(self, text):
        try:
            url=f"https://api.telegram.org/bot{self.tg_token}/sendMessage"
            data=json.dumps({'chat_id':self.tg_chat,'text':text}).encode()
            urllib.request.urlopen(urllib.request.Request(url,data=data,headers={'Content-Type':'application/json'}),timeout=5)
        except Exception as e: logger.error(f"Telegram failed: {e}")
