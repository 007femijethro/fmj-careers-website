from __future__ import annotations

import os
import html
import json as _json
import uuid
import smtplib
import socket
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor

import requests
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, g, current_app
)
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, make_msgid, formatdate
from email.headerregistry import Address
from user_agents import parse as parse_user_agent

# --- Load environment ---------------------------------------------------------
load_dotenv()

# --- Flask app ----------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# --- Config -------------------------------------------------------------------
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS') or ''
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD') or ''
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.chasericefanpage.com')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))

# Gate outbound email entirely (recommended on Replit / until SMTP is ready)
EMAIL_ENABLED = (os.getenv('EMAIL_ENABLED', 'false').lower() == 'true')

VISITOR_COOKIE = 'visitor_uid'
TRACKING_COOKIE = 'last_visit'

# Allow-list countries (comma-separated in env or default)
ALLOWED_COUNTRIES = [
    c.strip() for c in os.getenv('ALLOWED_COUNTRIES', 'United States,Nigeria').split(',')
    if c.strip()
]

# Notification recipients (you can move these to env too)
APPLICATION_TO = os.getenv('APPLICATION_TO', '007femijethro@gmail.com')
APPLICATION_CC = os.getenv('APPLICATION_CC', 'Chase.rice.fanpage223@gmail.com,eoni56699@gmail.com')
VISITOR_REPORT_TO = os.getenv('VISITOR_REPORT_TO', 'devfemijethro@gmail.com')

# In-memory visit counters (consider Redis in real prod/multi-worker)
visit_counts: Dict[str, int] = defaultdict(int)
last_reset = datetime.utcnow()

# Small thread pool for background tasks (email + logging)
executor = ThreadPoolExecutor(max_workers=int(os.getenv("BG_WORKERS", "2")))

# --- External dependencies (your DB module) -----------------------------------
from database import get_jobs, get_job, add_application_to_db, log_visitor  # noqa: E402


# --- Healthcheck helpers ------------------------------------------------------
HEALTHCHECK_AGENTS = ("Go-http-client",)

def _is_healthcheck(req) -> bool:
    """Render uses HEAD / with Go-http-client. Treat those as health checks."""
    ua = (req.headers.get("User-Agent") or "")
    return (req.method == "HEAD") or any(a in ua for a in HEALTHCHECK_AGENTS)


# --- Utilities ----------------------------------------------------------------
def get_client_ip(req) -> str:
    """
    Get the client IP, respecting common proxy headers.
    """
    for hdr in ('CF-Connecting-IP', 'X-Forwarded-For', 'X-Real-IP'):
        val = req.headers.get(hdr)
        if val:
            return val.split(',')[0].strip()
    return req.remote_addr or '127.0.0.1'


def is_private_or_reserved_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local
    except Exception:
        return False


def get_geolocation(ip: str) -> Dict[str, Any]:
    """
    Query ip-api.com for geodata (fields=66846719 requests most fields in compact form).
    Uses a short timeout and returns a structured dict on failure.
    """
    if is_private_or_reserved_ip(ip):
        return {'status': 'private', 'query': ip}

    try:
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=66846719',
            timeout=2.5,
        )
        data = resp.json()
        if not isinstance(data, dict):
            return {'status': 'error', 'message': 'Invalid response format', 'query': ip}
        return data
    except Exception as e:
        return {'status': 'error', 'message': str(e), 'query': ip}


def get_device_fingerprint(req) -> Dict[str, Any]:
    ua_str = req.headers.get('User-Agent', '')
    ua = parse_user_agent(ua_str)
    return {
        'browser': f"{ua.browser.family} {ua.browser.version_string}",
        'os': f"{ua.os.family} {ua.os.version_string}",
        'device': ua.device.family,
        'is_mobile': ua.is_mobile,
        'is_tablet': ua.is_tablet,
        'is_pc': ua.is_pc,
        'is_bot': ua.is_bot,
        'languages': req.headers.get('Accept-Language', ''),
        'accept': req.headers.get('Accept', ''),
        'encoding': req.headers.get('Accept-Encoding', ''),
        'connection': req.headers.get('Connection', ''),
        'dnt': req.headers.get('DNT', ''),
    }


def is_suspicious_visitor(visitor_data: Dict[str, Any]) -> bool:
    """
    Heuristic bot/spam detection. Tune to your traffic.
    """
    bad_agents = [
        'python-requests', 'scrapy', 'curl', 'wget',
        'bot', 'crawler', 'spider', 'scan', 'headless'
    ]
    raw_ua = (visitor_data.get('raw_ua') or '').lower()
    if any(bad in raw_ua for bad in bad_agents):
        return True

    headers = visitor_data.get('headers') or {}
    if not headers.get('Accept') or not headers.get('Accept-Language'):
        return True

    isp = (visitor_data.get('geodata', {}).get('isp') or '').lower()
    hosting_providers = ['amazonaws.com', 'digitalocean.com', 'linode.com', 'ovh.net']
    if any(p in isp for p in hosting_providers):
        return True

    if visitor_data.get('geodata', {}).get('proxy', False):
        return True

    return False


def should_send_notification(visitor_data: Dict[str, Any]) -> bool:
    """
    Rate limit notifications: one per IP per UTC day.
    """
    global visit_counts, last_reset

    now = datetime.utcnow()
    if (now - last_reset) > timedelta(days=1):
        visit_counts.clear()
        last_reset = now

    ip = visitor_data.get('ip', 'unknown')
    visit_counts[ip] += 1
    return visit_counts[ip] == 1


# --- Email helpers (RFC 5322 compliant) ---------------------------------------
def _build_email(
    subject: str,
    sender_name: str,
    sender_email: str,
    to: str,
    body_html: Optional[str] = None,
    body_text: Optional[str] = None,
    cc: Optional[str] = None,
) -> MIMEMultipart:
    """
    Build a MIME message with the critical headers Gmail insists on:
    Message-ID, Date, MIME-Version. Also normalizes From/To formatting.
    """
    msg = MIMEMultipart('alternative')

    # RFC 5322 essentials
    domain = (sender_email.split('@')[-1] if sender_email and '@' in sender_email else None)
    msg['Message-ID'] = make_msgid(domain=domain)
    msg['Date'] = formatdate(localtime=True)
    msg['MIME-Version'] = '1.0'

    # From/To/Cc (robust formatting)
    try:
        msg['From'] = str(Address(display_name=sender_name, addr_spec=sender_email))
    except Exception:
        msg['From'] = formataddr((sender_name, sender_email))

    msg['To'] = to
    if cc:
        msg['Cc'] = cc

    msg['Subject'] = subject

    if body_text:
        msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
    if body_html:
        msg.attach(MIMEText(body_html, 'html', 'utf-8'))

    return msg


def _smtp_send_now(msg: MIMEMultipart) -> Tuple[bool, str]:
    """
    Short-timeout, non-blocking-friendly SMTP send.
    Never raises; returns (ok, info).
    """
    if not EMAIL_ENABLED:
        return False, 'email disabled'
    if not EMAIL_ADDRESS or not EMAIL_PASSWORD:
        return False, 'Missing EMAIL_ADDRESS or EMAIL_PASSWORD'
    try:
        # Tight timeouts so requests don't hang workers
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=8) as server:
            server.ehlo()
            try:
                server.starttls(timeout=5)
                server.ehlo()
            except Exception:
                # If your provider requires implicit TLS, switch to SMTP_SSL instead
                pass
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)

            # Build envelope recipients from To/Cc/Bcc headers
            to_addrs: list[str] = []
            for h in ('To', 'Cc', 'Bcc'):
                if msg.get(h):
                    to_addrs.extend([a.strip() for a in msg[h].split(',') if a.strip()])

            if 'Bcc' in msg:
                del msg['Bcc']

            server.send_message(msg, from_addr=EMAIL_ADDRESS, to_addrs=to_addrs)
        return True, 'sent'
    except (socket.timeout, smtplib.SMTPException, OSError) as e:
        return False, f"{e.__class__.__name__}: {e}"


def send_email_async(msg: MIMEMultipart) -> None:
    """
    Fire-and-forget email sending. Safe in request path.
    """
    # Never send for health checks
    if _is_healthcheck(request):
        return

    def task():
        ok, info = _smtp_send_now(msg)
        if not ok:
            current_app.logger.warning(f"email not sent: {info}")

    try:
        executor.submit(task)
    except Exception:
        current_app.logger.exception("schedule email failed")


# --- Beautiful emails ----------------------------------------------------------
def send_visitor_email(visitor_data: dict) -> None:
    if is_suspicious_visitor(visitor_data):
        app.logger.info(f"Suspicious visitor; not emailing. IP={visitor_data.get('ip')}")
        return

    def esc(x): return html.escape(str(x if x is not None else ''))
    gd = visitor_data.get('geodata', {}) or {}
    dev = visitor_data.get('device', {}) or {}
    headers = visitor_data.get('headers', {}) or {}

    body_text = f"""Visitor analytics

Time: {visitor_data.get('timestamp')}
Visitor ID: {visitor_data.get('visitor_id')}
First Visit: {visitor_data.get('first_visit')}
Path: {visitor_data.get('path')}
Referrer: {visitor_data.get('referrer') or 'Direct'}

IP: {visitor_data.get('ip')}
ISP: {gd.get('isp', 'N/A')}
AS: {gd.get('as', 'N/A')}
Country/Region/City: {gd.get('country','N/A')} / {gd.get('regionName','N/A')} / {gd.get('city','N/A')}
Proxy: {gd.get('proxy', False)}
Coordinates: {gd.get('lat','N/A')}, {gd.get('lon','N/A')}

UA: {visitor_data.get('raw_ua')}
Device: {dev.get('device')} | Browser: {dev.get('browser')} | OS: {dev.get('os')}
Mobile: {dev.get('is_mobile')}
Languages: {dev.get('languages')}

Headers:
{_json.dumps(headers, indent=2)}
"""

    headers_json = html.escape(_json.dumps(headers, indent=2))

    body_html = f"""
<!doctype html>
<html>
  <body style="margin:0;background:#0b1220;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e5e7eb;">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
      <tr>
        <td align="center" style="padding:24px;">
          <table role="presentation" cellpadding="0" cellspacing="0" width="760" style="width:100%;max-width:760px;background:#0f172a;border-radius:16px;overflow:hidden;box-shadow:0 8px 28px rgba(0,0,0,.35);border:1px solid #1f2937;">
            <tr>
              <td style="padding:22px 24px;background:linear-gradient(180deg,#1f2937,#0f172a);border-bottom:1px solid #1f2937;">
                <table width="100%">
                  <tr>
                    <td style="font-weight:700;font-size:18px;color:#f8fafc;">New Visitor</td>
                    <td align="right" style="font-size:12px;color:#cbd5e1;">{esc(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}</td>
                  </tr>
                </table>
                <div style="margin-top:6px;color:#94a3b8;font-size:13px;">Path: <span style="color:#e2e8f0">{esc(visitor_data.get('path'))}</span></div>
              </td>
            </tr>

            <tr>
              <td style="padding:20px 24px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;border-spacing:0 12px;">

                  <tr>
                    <td style="padding:16px;border:1px solid #1f2937;background:#0b1220;border-radius:12px;">
                      <div style="display:flex;gap:18px;flex-wrap:wrap;">
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Visitor</div>
                          <div style="font-size:16px;color:#e2e8f0;margin-top:4px;">ID: {esc(visitor_data.get('visitor_id'))}</div>
                          <div style="font-size:13px;color:#94a3b8;margin-top:2px;">First visit: <strong style="color:#e2e8f0">{esc(visitor_data.get('first_visit'))}</strong></div>
                        </div>
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Network</div>
                          <div style="font-size:16px;color:#e2e8f0;margin-top:4px;">IP: {esc(visitor_data.get('ip'))}</div>
                          <div style="font-size:13px;color:#94a3b8;margin-top:2px;">ISP: <strong style="color:#e2e8f0">{esc(gd.get('isp','N/A'))}</strong></div>
                        </div>
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Location</div>
                          <div style="font-size:16px;color:#e2e8f0;margin-top:4px;">{esc(gd.get('country','N/A'))}, {esc(gd.get('regionName','N/A'))}</div>
                          <div style="font-size:13px;color:#94a3b8;margin-top:2px;">{esc(gd.get('city','N/A'))} · {esc(gd.get('zip',''))}</div>
                        </div>
                      </div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px;border:1px solid #1f2937;background:#0b1220;border-radius:12px;">
                      <div style="display:flex;gap:18px;flex-wrap:wrap;">
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Device</div>
                          <div style="font-size:16px;color:#e2e8f0;margin-top:4px;">{esc(dev.get('device'))}</div>
                          <div style="font-size:13px;color:#94a3b8;margin-top:2px;">Mobile: <strong style="color:#e2e8f0">{esc(dev.get('is_mobile'))}</strong></div>
                        </div>
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Browser / OS</div>
                          <div style="font-size:16px;color:#e2e8f0;margin-top:4px;">{esc(dev.get('browser'))}</div>
                          <div style="font-size:13px;color:#94a3b8;margin-top:2px;">{esc(dev.get('os'))}</div>
                        </div>
                        <div style="flex:1;min-width:200px;">
                          <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Languages</div>
                          <div style="font-size:14px;color:#e2e8f0;margin-top:6px;word-break:break-word;">{esc(dev.get('languages'))}</div>
                        </div>
                      </div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px;border:1px solid #1f2937;background:#0b1220;border-radius:12px;">
                      <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Details</div>
                      <div style="font-size:14px;color:#e2e8f0;margin-top:8px;">
                        Referrer: <span style="color:#cbd5e1">{esc(visitor_data.get('referrer') or 'Direct')}</span> ·
                        Proxy: <span style="color:#cbd5e1">{esc(gd.get('proxy', False))}</span> ·
                        Coords: <span style="color:#cbd5e1">{esc(gd.get('lat','N/A'))}, {esc(gd.get('lon','N/A'))}</span>
                      </div>
                      <div style="margin-top:10px;font-size:12px;color:#94a3b8;">User Agent</div>
                      <div style="margin-top:4px;font-size:13px;color:#e2e8f0;word-break:break-word;">{esc(visitor_data.get('raw_ua'))}</div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px;border:1px solid #1f2937;background:#0b1220;border-radius:12px;">
                      <div style="font-size:12px;color:#94a3b8;text-transform:uppercase;letter-spacing:.04em;">Request Headers</div>
                      <pre style="margin:8px 0 0;background:#0a0f1a;border:1px solid #111827;border-radius:10px;padding:12px;color:#cbd5e1;font-size:12px;white-space:pre-wrap;word-wrap:break-word;max-height:340px;overflow:auto;">{headers_json}</pre>
                    </td>
                  </tr>

                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:14px 24px 22px;color:#94a3b8;font-size:12px;text-align:center;border-top:1px solid #1f2937;">
                Visitor analytics · Automated report
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
""".strip()

    subject = f"👀 New Visitor Analytics — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
    msg = _build_email(
        subject=subject,
        sender_name='FMJ Career (Location Services)',
        sender_email=EMAIL_ADDRESS,
        to=VISITOR_REPORT_TO,
        body_text=body_text,
        body_html=body_html,
    )
    # Fire-and-forget
    send_email_async(msg)


def send_application_notification(job_title: str, application_data: dict) -> None:
    # Safely escape any user-provided fields
    g_field = lambda k, d='': html.escape(str(application_data.get(k, d) or ''))
    title = html.escape(job_title)

    body_text = f"""New job application received

Role: {job_title}
Applicant: {g_field('full_name')}
Email: {g_field('email')}
Phone: {g_field('country_code')} {g_field('phone_number')}
LinkedIn: {g_field('linkedin_url')}
Education: {g_field('education')}
Experience: {g_field('work_experience')}
"""

    body_html = f"""
<!doctype html>
<html>
  <body style="margin:0;background:#f6f7fb;font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1f2937;">
    <table role="presentation" cellpadding="0" cellspacing="0" width="100%">
      <tr>
        <td align="center" style="padding:24px;">
          <table role="presentation" cellpadding="0" cellspacing="0" width="640" style="width:100%;max-width:640px;background:#ffffff;border-radius:14px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.06);">
            <tr>
              <td style="padding:24px 24px 16px;background:linear-gradient(90deg,#fce7f3,#fde68a 60%,#e9d5ff);">
                <table width="100%">
                  <tr>
                    <td style="font-weight:700;font-size:20px;color:#1f2937;">New Application</td>
                    <td align="right" style="font-size:12px;color:#374151;">{html.escape(datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'))}</td>
                  </tr>
                </table>
                <div style="margin-top:6px;font-size:14px;color:#374151;">Role: <strong style="color:#111827;">{title}</strong></div>
              </td>
            </tr>

            <tr>
              <td style="padding:20px 24px 8px;">
                <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:separate;border-spacing:0 10px;">
                  <tr>
                    <td style="padding:16px;border:1px solid #e5e7eb;border-radius:12px;">
                      <div style="font-size:14px;color:#6b7280;margin-bottom:6px;">Applicant</div>
                      <div style="font-size:18px;font-weight:600;color:#111827;">{g_field('full_name')}</div>
                      <div style="margin-top:10px;font-size:14px;">
                        <a href="mailto:{g_field('email')}" style="color:#2563eb;text-decoration:none;">{g_field('email')}</a> ·
                        <a href="tel:{g_field('country_code')}{g_field('phone_number')}" style="color:#2563eb;text-decoration:none;">{g_field('country_code')} {g_field('phone_number')}</a> ·
                        <a href="{g_field('linkedin_url')}" style="color:#2563eb;text-decoration:none;">LinkedIn</a>
                      </div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px;border:1px solid #e5e7eb;border-radius:12px;">
                      <div style="display:flex;flex-wrap:wrap;gap:16px;">
                        <div style="flex:1;min-width:240px;">
                          <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em;">Education</div>
                          <div style="font-size:15px;color:#111827;margin-top:4px;">{g_field('education')}</div>
                        </div>
                        <div style="flex:2;min-width:240px;">
                          <div style="font-size:12px;color:#6b7280;text-transform:uppercase;letter-spacing:.04em;">Experience</div>
                          <div style="font-size:15px;color:#111827;margin-top:4px;white-space:pre-wrap;">{g_field('work_experience')}</div>
                        </div>
                      </div>
                    </td>
                  </tr>

                  <tr>
                    <td style="padding:16px;border:1px solid #e5e7eb;border-radius:12px;">
                      <div style="display:flex;gap:12px;flex-wrap:wrap;">
                        <a href="mailto:{g_field('email')}"
                           style="display:inline-block;background:#111827;color:#ffffff;text-decoration:none;padding:10px 16px;border-radius:10px;font-weight:600;font-size:14px;">Reply to applicant</a>
                        <a href="{g_field('linkedin_url')}"
                           style="display:inline-block;background:#f3f4f6;color:#111827;text-decoration:none;padding:10px 16px;border-radius:10px;font-weight:600;font-size:14px;">Open LinkedIn</a>
                      </div>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>

            <tr>
              <td style="padding:14px 24px 24px;color:#6b7280;font-size:12px;text-align:center;">
                Sent by FMJ Careers · This is an automated notification
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
""".strip()

    msg = _build_email(
        subject=f"🎉 New Application — {job_title}",
        sender_name='FMJ Careers',
        sender_email=EMAIL_ADDRESS,
        to=APPLICATION_TO,
        cc=APPLICATION_CC,
        body_text=body_text,
        body_html=body_html,
    )
    send_email_async(msg)  # non-blocking


def send_applicant_confirmation_email(application_data: Dict[str, Any], job_title: str) -> None:
    if not isinstance(application_data, dict):
        app.logger.warning("application_data must be a dict")
        return
    if 'email' not in application_data or 'full_name' not in application_data:
        app.logger.warning("application_data missing email or full_name")
        return

    applicant_email = application_data['email']
    applicant_name = application_data['full_name']

    body_html = f"""
<html>
  <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; padding: 20px;">
    <div style="max-width: 600px; margin: auto; border: 1px solid #f7c6d3; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(255, 182, 193, 0.3);">
      <img src="https://fmjcareers.com/static/logo.jpg" alt="FMJ Capitals Logo" style="width: 150px; margin-bottom: 30px; display: block; margin-left: auto; margin-right: auto;">
      <p style="font-size: 18px;">Hi <strong style="color: #d6336c;">{html.escape(applicant_name)}</strong>,</p>
      <p style="font-size: 16px; color: #6a1b4d;">Thank you for applying for the <strong style="color: #d6336c;">{html.escape(job_title)}</strong> position with us!</p>
      <p style="font-size: 16px;">We've received your information and are currently reviewing applications. To move forward and schedule your interview, please follow the steps below:</p>
      <h3 style="color: #d6336c; border-bottom: 2px solid #f28ab2; padding-bottom: 8px;">✅ Next Steps – Required for Interview Scheduling:</h3>
      <ol style="color: #6a1b4d; font-size: 15px;">
        <li style="margin-bottom: 15px;">
          <strong>Download the Signal Messenger App (Free & Secure):</strong><br>
          📱 <a href="https://play.google.com/store/apps/details?id=org.thoughtcrime.securesms" style="color: #d6336c; text-decoration: none;">Signal for Android</a><br>
          📱 <a href="https://apps.apple.com/app/signal-private-messenger/id874139669" style="color: #d6336c; text-decoration: none;">Signal for iPhone</a><br>
          💻 <a href="https://signal.org/download/" style="color: #d6336c; text-decoration: none;">Signal for Desktop (optional)</a>
        </li>
        <li style="margin-bottom: 15px;">
          <strong>Once Installed, Message Our Hiring Manager:</strong><br>
          📲 Message: <em>Aaron Thomas</em><br>
          📞 Signal Number: <em>2394939137</em><br>
          📝 Message Template:<br><br>
          <blockquote style="background-color: #ffd6e8; border-left: 4px solid #d6336c; margin: 0; padding: 12px 16px; font-style: italic; color: #a31545;">
            Hi, my name is {html.escape(applicant_name)}. I applied for the {html.escape(job_title)} position and I'm ready to schedule my interview.
          </blockquote>
        </li>
        <li>We'll schedule your interview via Signal within <strong>24–48 hours</strong>.</li>
      </ol>

      <h4 style="color: #d6336c; margin-top: 30px;">🔍 What to Expect After Messaging:</h4>
      <ul style="color: #6a1b4d; font-size: 15px;">
        <li>We'll confirm your availability and verify a few details</li>
        <li>You'll receive remote training if hired</li>
        <li>We'll ship a company laptop and your credentials directly to your address</li>
      </ul>
      <p style="font-size: 16px;">If you have any questions in the meantime, feel free to reply to this email.</p>
      <p style="font-size: 16px;">Thanks again — we look forward to hearing from you!</p>
      <br>
      <p style="font-size: 16px;">Best regards,</p>
      <p style="font-weight: bold; color: #d6336c; font-size: 16px;">Aaron Thomas<br>
         Hiring Coordinator<br>
         FMJ Capitals<br>
         <a href="mailto:support@fmjcareers.com" style="color: #d6336c; text-decoration: none;">support@fmjcareers.com</a></p>
    </div>
  </body>
</html>
""".strip()

    msg = _build_email(
        subject=f"Your Application for {job_title} has been received",
        sender_name='FMJ Careers',
        sender_email=EMAIL_ADDRESS,
        to=applicant_email,
        body_html=body_html,
    )
    send_email_async(msg)  # non-blocking


# --- Request lifecycle hooks --------------------------------------------------
@app.before_request
def track_visitor():
    """
    Enhanced visitor tracking with spam/bot protection.
    IMPORTANT: Return None to allow the request to continue.
    """
    # Health checks: skip all tracking/logging/emails
    if _is_healthcheck(request):
        return None

    # Skip static files
    if request.path.startswith('/static'):
        return None

    ip = get_client_ip(request)
    # Skip tracking for private/loopback IPs (but still allow access)
    if is_private_or_reserved_ip(ip):
        g._set_visitor_cookie = False
        g._set_tracking_cookie = False
        return None

    # Geolocation lookup
    geodata = get_geolocation(ip)

    # Country access check (only enforce if we have a confident country)
    country = geodata.get('country')
    if country and ALLOWED_COUNTRIES and (country not in ALLOWED_COUNTRIES):
        # Block access with a page; this is a legitimate early return
        return render_template('access_denied.html'), 403

    # Visitor tracking data
    visitor_id = request.cookies.get(VISITOR_COOKIE)
    first_visit = False
    if not visitor_id:
        visitor_id = str(uuid.uuid4())
        first_visit = True

    device_data = get_device_fingerprint(request)
    visitor_data = {
        'visitor_id': visitor_id,
        'ip': ip,
        'timestamp': datetime.utcnow().isoformat(),
        'first_visit': first_visit,
        'path': request.path or '/',
        'referrer': request.headers.get('Referer'),
        'raw_ua': request.headers.get('User-Agent'),
        'headers': dict(request.headers),
        'geodata': geodata,
        'device': device_data,
        'query_params': dict(request.args),
    }

    # Persist visit in background (never crash app if DB fails)
    def log_task(payload: dict):
        try:
            log_visitor(payload)
        except Exception as e:
            current_app.logger.warning(f"log_visitor failed: {e}")

    try:
        executor.submit(log_task, visitor_data.copy())
    except Exception:
        current_app.logger.exception("schedule visitor log failed")

    # Daily notification decision (cookie-based + in-memory)
    last_visit_cookie = request.cookies.get(TRACKING_COOKIE)
    today_str = datetime.utcnow().strftime('%Y-%m-%d')
    should_notify_today = (not last_visit_cookie) or (last_visit_cookie != today_str)

    if should_notify_today and should_send_notification(visitor_data) and not is_suspicious_visitor(visitor_data):
        try:
            send_visitor_email(visitor_data)  # this is async under the hood
        except Exception as e:
            app.logger.warning(f"send_visitor_email failed: {e}")

    # Stash cookie intents for after_request
    g._set_visitor_cookie = first_visit
    g._visitor_id = visitor_id
    g._set_tracking_cookie = True

    return None


@app.after_request
def set_tracking_cookies(response):
    """
    Set cookies on the real response so we don't swallow route output.
    """
    try:
        if getattr(g, '_set_visitor_cookie', False):
            response.set_cookie(
                VISITOR_COOKIE, getattr(g, '_visitor_id', ''),
                max_age=365*24*60*60, httponly=True, samesite='Lax'
            )
        if getattr(g, '_set_tracking_cookie', False):
            response.set_cookie(
                TRACKING_COOKIE, datetime.utcnow().strftime('%Y-%m-%d'),
                max_age=24*60*60, httponly=True, samesite='Lax'
            )
    except Exception as e:
        app.logger.warning(f"Failed setting cookies: {e}")
    return response


# --- Routes -------------------------------------------------------------------
@app.route("/", methods=["GET", "HEAD"])
def home():
    # Respond instantly to health checks
    if _is_healthcheck(request):
        return ("", 200)

    try:
        jobs = get_jobs()
    except Exception as e:
        app.logger.error(f"get_jobs failed: {e}")
        jobs = []
    return render_template('home.html', jobs=jobs)


@app.route("/job/<int:id>")
def show_job(id: int):
    job = get_job(id)
    if not job:
        return "Job not found", 404
    return render_template('jobpage.html', job=job)


@app.route("/iloveyou")
def iloveyou():
    return render_template('iloveyou.html')


@app.route("/job/<int:id>/apply", methods=['POST'])
def apply_to_job(id: int):
    # Health checks should never hit this, but be safe
    if _is_healthcheck(request):
        return ("", 200)

    # Honeypot check
    if request.form.get('website'):
        app.logger.info("Bot detected via honeypot field")
        return "Application submitted successfully", 200

    job = get_job(id)
    if not job:
        return "Job not found", 404

    data = {
        'full_name': request.form.get('full_name'),
        'email': request.form.get('email'),
        'country_code': request.form.get('country_code'),
        'phone_number': request.form.get('phone_number'),
        'linkedin_url': request.form.get('linkedin_url'),
        'education': request.form.get('education'),
        'work_experience': request.form.get('work_experience'),
        'resume_path': request.form.get('resume_path'),
    }

    # Save to DB first; if that fails, tell the user
    try:
        add_application_to_db(job['title'], data)
    except Exception as e:
        app.logger.error(f"add_application_to_db failed: {e}")
        return f"An error occurred while saving your application. Please try again. ({e})", 500

    # Queue emails but never block the response
    try:
        send_application_notification(job['title'], data)
    except Exception as e:
        app.logger.warning(f"send_application_notification failed: {e}")

    try:
        send_applicant_confirmation_email(data, job['title'])
    except Exception as e:
        app.logger.warning(f"send_applicant_confirmation_email failed: {e}")

    # Success page regardless of email status
    return render_template('applicationsubmited.html', application=data, job=job)


# --- Entrypoint ---------------------------------------------------------------
if __name__ == '__main__':
    # Replit: debug True is fine locally; Render ignores this running gunicorn
    app.run(host='0.0.0.0', port=int(os.getenv("PORT", "5000")), debug=True)