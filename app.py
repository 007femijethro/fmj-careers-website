from __future__ import annotations

import json
import os
import uuid
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple
from queue import Queue, Empty
from threading import Thread
import re
from collections import deque, defaultdict
from time import time as _now

import requests
from flask import (
    Flask,
    render_template,
    request,
    make_response,
    jsonify,
    g,
    Response,  # for safe error fallbacks
)
from dotenv import load_dotenv
from email.utils import formataddr
from user_agents import parse as parse_ua

try:
    # Python 3.9+
    from zoneinfo import ZoneInfo
except ImportError:  # pragma: no cover
    # For older Python if backports.zoneinfo is installed
    from backports.zoneinfo import ZoneInfo  # type: ignore

# Your own DB helpers
from database import (
    get_jobs,
    get_job,
    add_application_to_db,
    log_visitor,
    schedule_interview_email,
    get_due_interview_emails,
    mark_interview_email_sent,
)


# -----------------------------------------------------------------------------
# Environment / Config
# -----------------------------------------------------------------------------
load_dotenv()

def _get_bool(name: str, default: bool = False) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

def _get_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except Exception:
        return default


# -----------------------------------------------------------------------------
# Bot/scanner detection patterns & in-memory rate limiting (lightweight)
# -----------------------------------------------------------------------------
SUSPICIOUS_PATH_RE = re.compile(
    r"""(?ix)
        ( \.php($|[\?/])                # any .php
        | ^/(wp-|wordpress/)             # wp-*, /wordpress/...
        | ^/(xmlrpc\.php|wp-login\.php|wp-admin|wp-content|wp-includes)
        | ^/(vendor|version|env|\.env)   # common probe paths
        | /id3/license\.txt              # path seen in logs
        )
    """
)

BAD_UA_RE = re.compile(
    r"""(?ix)
        ( ^$ | curl | wget | python-requests | python-urllib | aiohttp | okhttp | go-http-client
        | spider | crawler | bot | scan | scrape )
    """
)

# Very light per-IP rate limiting (best-effort; use Redis for multi-instance)
IP_HITS = defaultdict(lambda: deque(maxlen=40))  # keep last 40 timestamps
RATE_LIMIT_WINDOW = 10.0  # seconds
RATE_LIMIT_MAX = 30       # >30 hits / window => 429


@dataclass(frozen=True)
class AppConfig:
    secret_key: str = os.getenv("SECRET_KEY", "change-this-before-prod")
    flask_env: str = os.getenv("FLASK_ENV", "production")

    # Email (prefer HTTP providers; SMTP only for local/dev)
    email_enabled: bool = _get_bool("EMAIL_ENABLED", True)
    email_provider: str = os.getenv("EMAIL_PROVIDER", "sendgrid").lower()  # sendgrid|mailgun|postmark|smtp
    email_address: str = os.getenv("EMAIL_ADDRESS", "")
    from_name: str = os.getenv("FROM_NAME", "FMJ Capitals Careers")
    reply_to: Optional[str] = os.getenv("REPLY_TO") or None
    admin_to: str = os.getenv("ADMIN_TO", "")
    notify_to: str = os.getenv("NOTIFY_TO", "")

    # SendGrid
    sendgrid_api_key: str = os.getenv("SENDGRID_API_KEY", "")

    # Mailgun
    mailgun_domain: str = os.getenv("MAILGUN_DOMAIN", "")
    mailgun_api_key: str = os.getenv("MAILGUN_API_KEY", "")

    # Postmark
    postmark_server_token: str = os.getenv("POSTMARK_SERVER_TOKEN", "")

    # Optional SMTP (dev fallback; many hosts block SMTP in prod)
    smtp_server: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port: int = _get_int("SMTP_PORT", 587)
    smtp_security: str = os.getenv("SMTP_SECURITY", "starttls").lower()  # starttls|ssl|none
    smtp_user: str = os.getenv("SMTP_USER", os.getenv("EMAIL_ADDRESS", ""))
    smtp_password: str = os.getenv("SMTP_PASSWORD", os.getenv("EMAIL_PASSWORD", ""))  # compat
    debug_smtp: bool = _get_bool("DEBUG_SMTP", False)

    # Test route flag
    enable_email_test_route: bool = _get_bool("ENABLE_EMAIL_TEST_ROUTE", True)  # Enabled for debugging

    # Tracking / Access control
    allowed_countries_csv: str = os.getenv("ALLOWED_COUNTRIES", "United States,Nigeria")
    visitor_cookie: str = os.getenv("VISITOR_COOKIE", "visitor_uid")
    tracking_cookie: str = os.getenv("TRACKING_COOKIE", "last_visit")
    cookie_days: int = _get_int("COOKIE_DAYS", 365)

    # Security
    served_over_https: bool = _get_bool("SERVED_OVER_HTTPS", True)  # Render uses HTTPS

    # Email timeout and retry settings
    email_timeout: int = _get_int("EMAIL_TIMEOUT", 10)
    email_max_retries: int = _get_int("EMAIL_MAX_RETRIES", 2)

    # Inline send switch (core fix): default True on Render
    email_inline_send: bool = _get_bool(
        "EMAIL_INLINE_SEND",
        default=("RENDER" in os.environ)  # default to inline on Render
    )

    @property
    def allowed_countries(self) -> Tuple[str, ...]:
        return tuple(c.strip() for c in self.allowed_countries_csv.split(",") if c.strip())

    @property
    def is_render(self) -> bool:
        return 'RENDER' in os.environ


cfg = AppConfig()

# Time zone for “US time”, used for scheduling next working day at 10am
US_TZ = ZoneInfo(os.getenv("US_BUSINESS_TZ", "America/New_York"))

# Secret token for cron route that sends scheduled interview emails
CRON_SECRET = os.getenv("CRON_SECRET")


# -----------------------------------------------------------------------------
# App / Logging
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = cfg.secret_key

# Enhanced logging configuration
log_level = logging.INFO if cfg.flask_env == "production" else logging.DEBUG
logging.basicConfig(
    level=log_level,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger("fmjcareers")

# Log startup configuration (redacting sensitive info)
safe_config = {k: v for k, v in cfg.__dict__.items() if "key" not in k.lower() and "password" not in k.lower()}
logger.info(f"Application starting with config: {safe_config}")
logger.info(f"Running on Render: {cfg.is_render}")
logger.info(f"Email provider: {cfg.email_provider}, Enabled: {cfg.email_enabled}")


# -----------------------------------------------------------------------------
# Email: async queue + provider clients
# -----------------------------------------------------------------------------
class MailTask:
    def __init__(
        self,
        subject: str,
        to_addr: str,
        body_html: Optional[str] = None,
        body_text: Optional[str] = None,
        from_name: Optional[str] = None,
        reply_to: Optional[str] = None,
    ):
        self.subject = subject
        self.to_addr = to_addr
        self.body_html = body_html
        self.body_text = body_text
        self.from_name = from_name
        self.reply_to = reply_to
        # short correlation id for logs + SendGrid custom args
        self.mail_id = str(uuid.uuid4())[:12]


class AsyncMailer:
    """Tiny in-process queue so web requests never block on email."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.q: "Queue[MailTask]" = Queue(maxsize=1000)
        self.worker = Thread(target=self._run, daemon=True)
        self.worker.start()
        logger.info("AsyncMailer initialized and worker started")

    def enqueue(self, task: MailTask) -> None:
        if not self.cfg.email_enabled:
            logger.info("Email disabled: would send to %s — %s", task.to_addr, task.subject)
            return
        try:
            self.q.put_nowait(task)
            logger.info("mail.enqueue mail_id=%s to=%s subject=%s", task.mail_id, task.to_addr, task.subject)
        except Exception as e:
            logger.error("Email queue full; dropping email to %s: %s", task.to_addr, e)

    def _run(self):
        while True:
            try:
                task = self.q.get(timeout=1.0)
            except Empty:
                continue
            try:
                send_email_with_retry(cfg, task, cfg.email_max_retries)
                logger.info("mail.sent mail_id=%s to=%s subject=%s", task.mail_id, task.to_addr, task.subject)
            except Exception as e:
                logger.error("mail.fail mail_id=%s to=%s err=%s", task.mail_id, task.to_addr, e)
            finally:
                self.q.task_done()


def send_email_with_retry(cfg: AppConfig, task: MailTask, max_retries: int = 2) -> None:
    """Send email with retry logic."""
    for attempt in range(max_retries):
        try:
            send_email_via_provider(cfg, task)
            return
        except Exception as e:
            if attempt == max_retries - 1:  # Last attempt
                raise
            wait_time = (attempt + 1) * 2  # Exponential backoff: 2, 4 seconds
            logger.warning("mail.retry mail_id=%s attempt=%s wait=%ss err=%s", task.mail_id, attempt + 1, wait_time, e)
            time.sleep(wait_time)


def send_email_via_provider(cfg: AppConfig, task: MailTask) -> None:
    """Send via HTTPS provider (preferred) or SMTP (dev fallback)."""
    from_addr = formataddr((task.from_name or cfg.from_name, cfg.email_address))
    reply_to = task.reply_to or cfg.reply_to
    timeout = cfg.email_timeout

    logger.info("mail.sending provider=%s from=%s to=%s subject=%s", cfg.email_provider, cfg.email_address, task.to_addr, task.subject)

    if cfg.email_provider == "sendgrid":
        if not cfg.sendgrid_api_key:
            error_msg = "SENDGRID_API_KEY missing or empty"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        if len(cfg.sendgrid_api_key) < 20:  # Basic validation
            error_msg = f"SENDGRID_API_KEY appears invalid (length: {len(cfg.sendgrid_api_key)})"
            logger.error(error_msg)
            raise RuntimeError(error_msg)

        payload = {
            "personalizations": [{
                "to": [{"email": task.to_addr}],
                "custom_args": {"mail_id": task.mail_id, "env": cfg.flask_env}
            }],
            "from": {"email": cfg.email_address, "name": task.from_name or cfg.from_name},
            "subject": task.subject,
            "content": [],
            "categories": ["fmjcareers"],
        }

        if task.body_text:
            payload["content"].append({"type": "text/plain", "value": task.body_text})
        if task.body_html:
            payload["content"].append({"type": "text/html", "value": task.body_html})
        if not payload["content"]:
            payload["content"].append({"type": "text/plain", "value": " "})

        headers = {
            "Authorization": f"Bearer {cfg.sendgrid_api_key}",
            "Content-Type": "application/json",
            "User-Agent": "FMJCareers/1.0",
        }
        if reply_to:
            payload["reply_to"] = {"email": reply_to}

        logger.info("mail.provider_request provider=sendgrid mail_id=%s", task.mail_id)
        try:
            resp = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers=headers,
                json=payload,
                timeout=timeout,
            )
            sg_msg_id = resp.headers.get("X-Message-Id") or resp.headers.get("X-Message-ID")
            sg_req_id = resp.headers.get("X-Request-Id")
            logger.info(
                "mail.provider_response provider=sendgrid mail_id=%s status=%s sg_message_id=%s sg_request_id=%s body=%s",
                task.mail_id, resp.status_code, sg_msg_id, sg_req_id, (resp.text or "<empty>")[:800]
            )

            if resp.status_code == 202:
                logger.info("mail.accepted provider=sendgrid mail_id=%s", task.mail_id)
                return
            elif resp.status_code >= 400:
                # Helpful errors
                if resp.status_code == 401:
                    raise RuntimeError("SendGrid authentication failed - check your API key")
                elif resp.status_code == 403:
                    raise RuntimeError("SendGrid permission denied - verify API key permissions")
                elif resp.status_code == 422:
                    raise RuntimeError("SendGrid validation failed - check email addresses and content")
                else:
                    resp.raise_for_status()
            else:
                resp.raise_for_status()
        except requests.exceptions.Timeout:
            logger.error("SendGrid API request timed out")
            raise RuntimeError("Email service timeout - please try again")
        except requests.exceptions.ConnectionError:
            logger.error("SendGrid API connection error")
            raise RuntimeError("Cannot connect to email service")
        except Exception as e:
            logger.error("SendGrid unexpected error: %s", e)
            raise

    elif cfg.email_provider == "mailgun":
        if not (cfg.mailgun_domain and cfg.mailgun_api_key):
            raise RuntimeError("MAILGUN_DOMAIN or MAILGUN_API_KEY missing")

        url = f"https://api.mailgun.net/v3/{cfg.mailgun_domain}/messages"
        data = {
            "from": from_addr,
            "to": [task.to_addr],
            "subject": task.subject,
            "text": task.body_text or " ",
        }
        if task.body_html:
            data["html"] = task.body_html
        if reply_to:
            data["h:Reply-To"] = reply_to

        resp = requests.post(url, auth=("api", cfg.mailgun_api_key), data=data, timeout=timeout)
        logger.info("mail.provider_response provider=mailgun status=%s body=%s", resp.status_code, (resp.text or "<empty>")[:800])
        resp.raise_for_status()
        return

    elif cfg.email_provider == "postmark":
        if not cfg.postmark_server_token:
            raise RuntimeError("POSTMARK_SERVER_TOKEN missing")

        payload = {
            "From": from_addr,
            "To": task.to_addr,
            "Subject": task.subject,
            "TextBody": task.body_text or " ",
            "HtmlBody": task.body_html,
            "MessageStream": "outbound",
        }
        if reply_to:
            payload["ReplyTo"] = reply_to

        headers = {
            "X-Postmark-Server-Token": cfg.postmark_server_token,
            "Content-Type": "application/json"
        }
        resp = requests.post("https://api.postmarkapp.com/email", headers=headers, json=payload, timeout=timeout)
        logger.info("mail.provider_response provider=postmark status=%s body=%s", resp.status_code, (resp.text or "<empty>")[:800])
        resp.raise_for_status()
        return

    else:  # SMTP fallback
        logger.warning("Using SMTP fallback - not recommended for production")
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        msg = MIMEMultipart("alternative")
        msg["Subject"] = task.subject
        msg["From"] = from_addr
        msg["To"] = task.to_addr
        if reply_to:
            msg["Reply-To"] = reply_to

        if task.body_text:
            msg.attach(MIMEText(task.body_text, "plain"))
        if task.body_html:
            msg.attach(MIMEText(task.body_html, "html"))
        if not task.body_text and not task.body_html:
            msg.attach(MIMEText(" ", "plain"))

        try:
            if cfg.smtp_security == "ssl":
                server = smtplib.SMTP_SSL(cfg.smtp_server, cfg.smtp_port, timeout=timeout)
            else:
                server = smtplib.SMTP(cfg.smtp_server, cfg.smtp_port, timeout=timeout)
                if cfg.smtp_security in ("starttls", "tls", "true", "1", "yes"):
                    server.ehlo()
                    server.starttls()
                    server.ehlo()

            if cfg.debug_smtp:
                server.set_debuglevel(1)

            if cfg.smtp_user and cfg.smtp_password:
                server.login(cfg.smtp_user, cfg.smtp_password)

            server.send_message(msg)
            server.quit()
            logger.info("SMTP email sent successfully")
        except Exception as e:
            logger.error(f"SMTP error: {e}")
            raise RuntimeError(f"SMTP delivery failed: {e}")


mailer = AsyncMailer(cfg)

def _inline_or_queue(task: MailTask) -> None:
    """Core behavior: inline on Render by default, otherwise enqueue."""
    if cfg.email_inline_send:
        logger.info("mail.inline_send mail_id=%s to=%s", task.mail_id, task.to_addr)
        send_email_with_retry(cfg, task, cfg.email_max_retries)
    else:
        mailer.enqueue(task)

def queue_email(
    subject: str,
    to_addr: str,
    *,
    body_html: Optional[str] = None,
    body_text: Optional[str] = None,
    from_name: Optional[str] = None,
):
    """Queue an email for sending (or send inline depending on config)."""
    if not to_addr or not subject:
        logger.error("Cannot queue email: missing to_addr or subject")
        return

    task = MailTask(
        subject=subject,
        to_addr=to_addr,
        body_html=body_html,
        body_text=body_text,
        from_name=from_name,
    )
    try:
        _inline_or_queue(task)
        logger.info("Email queued/sent successfully for %s", to_addr)
    except Exception as e:
        logger.error("Failed to queue/send email to %s: %s", to_addr, e)
        raise


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def get_geolocation(ip: str) -> Dict[str, Any]:
    """Get geolocation from ip-api.com with a short timeout."""
    if ip in ("127.0.0.1", "::1"):
        return {"status": "localhost"}
    try:
        resp = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=3)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.debug("Geo lookup failed for IP=%s: %s", ip, e)
        return {"error": str(e), "status": "error"}

def get_device_fingerprint(req) -> Dict[str, Any]:
    ua = parse_ua(req.headers.get("User-Agent", ""))
    return {
        "browser": f"{ua.browser.family} {ua.browser.version_string}",
        "os": f"{ua.os.family} {ua.os.version_string}",
        "device": ua.device.family,
        "is_mobile": ua.is_mobile,
        "is_tablet": ua.is_tablet,
        "is_pc": ua.is_pc,
        "is_bot": ua.is_bot,
        "languages": req.headers.get("Accept-Language", ""),
    }

def today_str() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d")

def next_working_day_10am_us() -> datetime:
    """
    Compute the next working day (Mon–Fri) at 10:00 in US_TZ.
    """
    now_local = datetime.now(US_TZ)
    candidate = now_local + timedelta(days=1)

    # 0=Monday ... 6=Sunday; skip Saturday (5) and Sunday (6)
    while candidate.weekday() >= 5:
        candidate += timedelta(days=1)

    return candidate.replace(hour=10, minute=00, second=0, microsecond=0)


# -----------------------------------------------------------------------------
# Error fallback helper (prevents TemplateNotFound loops)
# -----------------------------------------------------------------------------
def _try_render(name: str, status_code: int):
    try:
        return render_template(name), status_code
    except Exception:
        # Minimal safe fallback; avoids recursive 500s if template missing
        return Response(f"{status_code} error at {request.path}", status=status_code, mimetype="text/plain")


# -----------------------------------------------------------------------------
# Real-page detection for notifications
# -----------------------------------------------------------------------------
def _is_notifiable_path(path: str, method: str) -> bool:
    """
    Only treat *real*, user-facing GET pages as notifiable:
      - "/" (home)
      - "/job"
      - "/job/<id>" (any GET under /job/, except explicit /apply actions)
    Excludes non-GETs and "/job/<id>/apply".
    """
    if method != "GET":
        return False
    if path == "/":
        return True
    if path == "/job":
        return True
    if path.startswith("/job/") and not path.endswith("/apply"):
        return True
    return False


# -----------------------------------------------------------------------------
# Before/After Request: Tracking + Access Control
# -----------------------------------------------------------------------------
@app.before_request
def track_visitor() -> Optional[Tuple[str, int]]:
    # Block admin paths
    if request.path.lower().startswith(("/wp-admin", "/wordpress/wp-admin")):
        return "Access denied", 403

    # Skip static and health and hooks
    if (
        request.path.startswith("/static")
        or request.path == "/healthz"
        or request.path.startswith("/hooks/")  # <-- allow SendGrid webhook
    ):
        return None

    # Resolve IP (respect X-Forwarded-For)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()

    geodata = get_geolocation(ip)
    country = geodata.get("country", "Unknown")

    # Access control by country
    if cfg.allowed_countries and country not in cfg.allowed_countries:
        logger.info(f"Access denied for country: {country} from IP: {ip}")
        # Use safe render to avoid TemplateNotFound crash
        return _try_render("access_denied.html", 403)

    # Visitor cookies
    visitor_id = request.cookies.get(cfg.visitor_cookie) or str(uuid.uuid4())
    last_visit = request.cookies.get(cfg.tracking_cookie)
    first_visit = not request.cookies.get(cfg.visitor_cookie)

    # Fingerprint
    device_data = get_device_fingerprint(request)

    # Prepare visitor data
    visitor_data = {
        "visitor_id": visitor_id,
        "ip": ip,
        "timestamp": datetime.utcnow().isoformat(),
        "first_visit": first_visit,
        "path": request.path,
        "referrer": request.headers.get("Referer"),
        "raw_ua": request.headers.get("User-Agent"),
        "geodata": geodata,
        "device": device_data,
        "query_params": dict(request.args),
    }

    # Persist to DB (non-fatal)
    try:
        log_visitor(visitor_data)
    except Exception:
        logger.exception("Failed to log visitor")

    # Notify only for real URLs on first such visit of the day
    notifiable = _is_notifiable_path(request.path, request.method)
    today = today_str()
    g.notify_today = notifiable and ((not last_visit) or (last_visit != today))
    g.visitor_id = visitor_id

    # Only set/update daily cookie on notifiable hits
    g.set_cookies = {}
    if notifiable:
        g.set_cookies = {
            cfg.visitor_cookie: (visitor_id, cfg.cookie_days),
            cfg.tracking_cookie: (today, 1),
        }

    # Queue a small daily alert (never block the request)
    if g.notify_today and cfg.notify_to:
        try:
            send_visitor_notification(visitor_data)
        except Exception:
            logger.exception("Queueing visitor email failed (non-fatal)")

    return None


@app.after_request
def set_tracking_cookies(response):
    for name, (value, days) in getattr(g, "set_cookies", {}).items():
        secure = cfg.served_over_https
        response.set_cookie(
            key=name,
            value=value,
            max_age=days * 24 * 60 * 60,
            httponly=True,
            secure=secure,
            samesite="Lax",
        )
    return response


# -----------------------------------------------------------------------------
# Email Composers (enqueue; non-blocking)
# -----------------------------------------------------------------------------
def send_application_notification(job_title: str, application_data: Dict[str, Any]) -> None:
    """Send beautifully formatted notification to admin about new application."""
    if not cfg.admin_to:
        logger.warning("No ADMIN_TO configured for application notifications")
        return

    applicant_name = application_data.get('full_name', 'Unknown Applicant')
    subject = f"📬 New Application for {job_title} - {applicant_name}"

    linkedin_html = ""
    if application_data.get('linkedin_url'):
        linkedin_url = application_data.get('linkedin_url')
        linkedin_html = f"""
            <div class="info-item" style="grid-column: 1 / -1;">
                <div class="info-label">🔗 LinkedIn Profile</div>
                <div class="info-value">
                    <a href="{linkedin_url}" style="color: #d6336c; text-decoration: none;">{linkedin_url}</a>
                </div>
            </div>
        """

    body_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #d6336c 0%, #a61e4d 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
            font-weight: 600;
        }}
        .content {{
            padding: 30px;
        }}
        .applicant-card {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid #d6336c;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 20px 0;
        }}
        .info-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #e9ecef;
        }}
        .info-label {{
            font-weight: 600;
            color: #495057;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .info-value {{
            color: #212529;
            font-size: 14px;
            margin-top: 5px;
        }}
        .action-btn {{
            display: inline-block;
            background: linear-gradient(135deg, #d6336c 0%, #a61e4d 100%);
            color: white;
            padding: 12px 30px;
            text-decoration: none;
            border-radius: 25px;
            font-weight: 600;
            margin: 10px 5px;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 12px;
        }}
        .badge {{
            background: #d6336c;
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 12px;
            text-align: center;
            margin-bottom: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🎯 New Job Application Received</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">FMJ Capitals Careers Portal</p>
        </div>

        <div class="content">
            <div class="timestamp">📅 {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}</div>

            <div class="applicant-card">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                    <h2 style="margin: 0; color: #d6336c;">{applicant_name}</h2>
                    <span class="badge">New Applicant</span>
                </div>
                <div style="color: #495057; margin-bottom: 15px;">
                    Applied for: <strong>{job_title}</strong>
                </div>
            </div>

            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">📧 Email</div>
                    <div class="info-value">{application_data.get('email', 'Not provided')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">📞 Phone</div>
                    <div class="info-value">{application_data.get('country_code', '')} {application_data.get('phone_number', 'Not provided')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">🎓 Education</div>
                    <div class="info-value">{application_data.get('education', 'Not provided')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">💼 Experience</div>
                    <div class="info-value">{application_data.get('work_experience', 'Not provided')}</div>
                </div>
            </div>

            {linkedin_html}

            <div style="text-align: center; margin: 30px 0;">
                <a href="https://fmjcareers.com/admin/applications" class="action-btn">View All Applications</a>
                <a href="mailto:{application_data.get('email', '')}" class="action-btn" style="background: linear-gradient(135deg, #20c997 0%, #099268 100%);">Contact Applicant</a>
            </div>
        </div>

        <div class="footer">
            <p>This email was sent automatically from FMJ Capitals Careers Portal</p>
            <p>© 2025 FMJ Capitals. All rights reserved.</p>
        </div>
    </div>
</body>
</html>""".strip()

    body_text = f"""
NEW JOB APPLICATION - FMJ CAPITALS CAREERS
{'='*50}

Applicant: {applicant_name}
Position: {job_title}
Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

Contact Information:
📧 Email: {application_data.get('email', 'Not provided')}
📞 Phone: {application_data.get('country_code', '')} {application_data.get('phone_number', 'Not provided')}
🔗 LinkedIn: {application_data.get('linkedin_url', 'Not provided')}

Background:
🎓 Education: {application_data.get('education', 'Not provided')}
💼 Experience: {application_data.get('work_experience', 'Not provided')}

Next Steps:
1. Review the application in admin panel
2. Contact applicant to schedule interview (via Microsoft Teams)
3. Update application status

---
FMJ Capitals Careers Portal - Automated Notification
"""

    logger.info(f"Queueing application notification for {applicant_name}")
    queue_email(subject, cfg.admin_to, body_html=body_html, body_text=body_text, from_name="FMJ Capitals Careers Portal")


def send_visitor_notification(visitor_data: Dict[str, Any]) -> None:
    """Send beautifully formatted visitor analytics notification."""
    if not cfg.notify_to:
        return

    visitor_id = visitor_data.get('visitor_id', 'Unknown')
    country = visitor_data.get('geodata', {}).get('country', 'Unknown')
    city = visitor_data.get('geodata', {}).get('city', 'Unknown')
    is_first_visit = visitor_data.get('first_visit', False)

    subject = f"🌍 {'New' if is_first_visit else 'Returning'} Visitor from {country}"

    if is_first_visit:
        visitor_type = "First-time Visitor"
        visitor_icon = "🆕"
        badge_color = "linear-gradient(135deg, #20c997 0%, #099268 100%)"
    else:
        visitor_type = "Returning Visitor"
        visitor_icon = "🔁"
        badge_color = "linear-gradient(135deg, #339af0 0%, #1c7ed6 100%)"

    body_html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 600px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        .header {{
            background: {badge_color};
            color: white;
            padding: 25px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 22px;
            font-weight: 600;
        }}
        .content {{
            padding: 25px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #e9ecef;
        }}
        .stat-icon {{
            font-size: 24px;
            margin-bottom: 8px;
        }}
        .stat-label {{
            font-weight: 600;
            color: #495057;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .stat-value {{
            color: #212529;
            font-size: 14px;
            font-weight: 600;
            margin-top: 5px;
        }}
        .map-section {{
            background: linear-gradient(135deg, #ffe8cc 0%, #ffa94d 100%);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: center;
        }}
        .device-info {{
            background: #e7f5ff;
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            border-left: 4px solid #339af0;
        }}
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 12px;
        }}
        .badge {{
            background: {badge_color};
            color: white;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 15px;
        }}
        .timestamp {{
            color: #6c757d;
            font-size: 12px;
            text-align: center;
            margin-bottom: 15px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{visitor_icon} {visitor_type}</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">FMJ Capitals Careers Analytics</p>
        </div>

        <div class="content">
            <div class="timestamp">📅 {datetime.utcnow().strftime('%B %d, %Y at %H:%M UTC')}</div>

            <div class="badge">{visitor_type}</div>

            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon">🌎</div>
                    <div class="stat-label">Country</div>
                    <div class="stat-value">{country}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🏙️</div>
                    <div class="stat-label">City</div>
                    <div class="stat-value">{city if city != 'Unknown' else 'Not detected'}</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">🆔</div>
                    <div class="stat-label">Visitor ID</div>
                    <div class="stat-value" style="font-family: monospace; font-size: 10px;">{visitor_id[:8]}...</div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon">📊</div>
                    <div class="stat-label">Visit Type</div>
                    <div class="stat-value">{'First Visit' if is_first_visit else 'Return Visit'}</div>
                </div>
            </div>

            <div class="map-section">
                <div style="font-size: 48px; margin-bottom: 10px;">🗺️</div>
                <div style="font-weight: 600; color: #d6336c; margin-bottom: 5px;">Visitor Location</div>
                <div style="color: #495057;">
                    {f"{city}, {country}" if city != "Unknown" else country}
                </div>
                {f'<div style="font-size: 11px; color: #6c757d; margin-top: 8px;">IP: {visitor_data.get("ip", "Unknown")}</div>' if visitor_data.get("ip") and visitor_data.get("ip") not in ["127.0.0.1", "::1"] else ''}
            </div>

            <div class="device-info">
                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                    <span style="font-size: 20px; margin-right: 10px;">💻</span>
                    <strong>Device Information</strong>
                </div>
                <div style="font-size: 13px;">
                    <strong>Browser:</strong> {visitor_data.get('device', {}).get('browser', 'Unknown')}<br>
                    <strong>OS:</strong> {visitor_data.get('device', {}).get('os', 'Unknown')}<br>
                    <strong>Device:</strong> {visitor_data.get('device', {}).get('device', 'Unknown')}<br>
                    <strong>Type:</strong> {'Mobile' if visitor_data.get('device', {}).get('is_mobile') else 'Tablet' if visitor_data.get('device', {}).get('is_tablet') else 'Desktop'}
                </div>
            </div>

            <div style="background: #fff3cd; padding: 15px; border-radius: 10px; margin: 15px 0; border-left: 4px solid #ffc107;">
                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                    <span style="font-size: 18px; margin-right: 10px;">📈</span>
                    <strong>Engagement Metrics</strong>
                </div>
                <div style="font-size: 13px;">
                    <strong>Page Visited:</strong> {visitor_data.get('path', 'Homepage')}<br>
                    <strong>Referrer:</strong> {visitor_data.get('referrer', 'Direct visit')}<br>
                    <strong>Languages:</strong> {visitor_data.get('device', {}).get('languages', 'Not detected')}
                </div>
            </div>
        </div>

        <div class="footer">
            <p>🌐 Real-time analytics from FMJ Capitals Careers website</p>
            <p>© 2025 FMJ Capitals. All rights reserved.</p>
        </div>
    </div>
</body>
</html>""".strip()

    body_text = f"""
VISITOR ANALYTICS - FMJ CAPITALS CAREERS
{'='*50}

{visitor_icon} {visitor_type}
📅 {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

Location:
🌎 Country: {country}
🏙️ City: {city if city != 'Unknown' else 'Not detected'}
🆔 Visitor ID: {visitor_id}

Device Info:
💻 Browser: {visitor_data.get('device', {}).get('browser', 'Unknown')}
🖥️ OS: {visitor_data.get('device', {}).get('os', 'Unknown')}
📱 Device: {visitor_data.get('device', {}).get('device', 'Unknown')}
🔧 Type: {'Mobile' if visitor_data.get('device', {}).get('is_mobile') else 'Tablet' if visitor_data.get('device', {}).get('is_tablet') else 'Desktop'}

Engagement:
📈 Page: {visitor_data.get('path', 'Homepage')}
🔗 Referrer: {visitor_data.get('referrer', 'Direct visit')}
🌐 Languages: {visitor_data.get('device', {}).get('languages', 'Not detected')}

---
FMJ Capitals Careers Analytics - Automated Report
"""

    queue_email(subject, cfg.notify_to, body_html=body_html, body_text=body_text, from_name="FMJ Capitals Careers Analytics")


def send_applicant_confirmation_email(application_data: Dict[str, Any], job_title: str) -> None:
    """
    Immediate email after application:
    - Thanks them for applying
    - Tells them you'll follow up by email to schedule an interview via Microsoft Teams
    - You also receive a copy of this email.
    """
    if not isinstance(application_data, dict):
        raise ValueError("application_data must be a dictionary")
    if "email" not in application_data or "full_name" not in application_data:
        raise ValueError("application_data missing required fields: email or full_name")

    applicant_email = application_data["email"]
    applicant_name = application_data["full_name"]

    subject = f"FMJ Capitals – Application received for {job_title}"

    body_html = f"""
<html>
  <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; padding: 20px; background-color:#fff5f8;">
    <div style="max-width: 600px; margin: auto; border: 1px solid #f7c6d3; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(255, 182, 193, 0.3); background:#ffffff;">
      <img src="https://fmjcareers.com/static/logo.jpg" alt="FMJ Capitals Logo" style="width: 150px; margin-bottom: 30px; display: block; margin-left: auto; margin-right: auto;">

      <p style="font-size: 18px;">Hi <strong style="color: #d6336c;">{applicant_name}</strong>,</p>

      <p style="font-size: 16px; color: #6a1b4d;">
        Thank you for applying for the <strong style="color: #d6336c;">{job_title}</strong> position at FMJ Capitals.
      </p>

      <p style="font-size: 16px;">
        We’ve received your application and our team will review it shortly.
      </p>

      <p style="font-size: 16px;">
        We’ll follow up with you by email to schedule an interview, which will be held via <strong>Microsoft Teams</strong>.
      </p>

      <p style="font-size: 16px;">
        For now, there’s nothing else you need to do. We’ll be in touch with next steps.
      </p>

      <p style="font-size: 16px; margin-top: 24px;">Best regards,</p>
      <p style="font-weight: bold; color: #d6336c; font-size: 16px;">
        FMJ Capitals Careers Team<br>
        <a href="mailto:support@fmjcareers.com" style="color: #d6336c; text-decoration: none;">support@fmjcareers.com</a>
      </p>
    </div>
  </body>
</html>
""".strip()

    body_text = f"""
Hi {applicant_name},

Thank you for applying for the {job_title} position at FMJ Capitals.

We’ve received your application and our team will review it shortly.
We’ll follow up with you by email to schedule an interview, which will be held via Microsoft Teams.

Best regards,
FMJ Capitals Careers Team
support@fmjcareers.com
""".strip()

    logger.info(f"Queueing confirmation email for {applicant_email}")
    queue_email(subject, applicant_email, body_html=body_html, body_text=body_text, from_name="FMJ Capitals Careers")

    # Send a copy to admin so you are notified of what the applicant received
    admin_copy = cfg.admin_to or cfg.notify_to
    if admin_copy and admin_copy != applicant_email:
        copy_subject = f"[Copy] {subject}"
        logger.info(f"Queueing admin copy of confirmation email to {admin_copy}")
        queue_email(copy_subject, admin_copy, body_html=body_html, body_text=body_text, from_name="FMJ Capitals Careers")


def send_interview_scheduling_email(application_data: Dict[str, Any], job_title: str) -> None:
    """
    Sends an interview scheduling email to qualified applicants.

    This email requests the applicant to propose 2-3 available time slots
    for their preliminary interview. The email is designed to be sent
    the next working day at 10am US time (handled by scheduler/cron).

    Args:
        application_data: Dictionary containing applicant information
        job_title: The specific job role being applied for

    Raises:
        ValueError: If application_data is invalid or missing required fields
    """
    # Input validation
    if not isinstance(application_data, dict):
        raise ValueError("application_data must be a dictionary")

    required_fields = {"email", "full_name"}
    if missing_fields := required_fields - application_data.keys():
        raise ValueError(f"application_data missing required fields: {', '.join(missing_fields)}")

    applicant_email = application_data["email"]
    applicant_name = application_data["full_name"]

    subject = f"Interview Scheduling Request - {job_title} - FMJ Capitals"

    body_html = f"""
<html>
  <head>
    <meta charset="UTF-8">
  </head>
  <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; margin: 0; padding: 20px; background-color: #f8f9fa;">
    <div style="max-width: 600px; margin: auto; background: #ffffff; border: 1px solid #e0e0e0; border-radius: 8px; padding: 40px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">

      <!-- Header -->
      <div style="text-align: center; margin-bottom: 30px;">
        <img src="https://fmjcareers.com/static/logo.jpg" alt="FMJ Capitals Logo" style="width: 180px; height: auto;">
      </div>

      <!-- Salutation -->
      <p style="font-size: 16px; margin-bottom: 20px;">Dear {applicant_name},</p>

      <!-- Main Content -->
      <div style="font-size: 16px;">
        <p style="margin-bottom: 16px;">
          Thank you for your application for the <strong style="color: #d6336c;">{job_title}</strong> position at FMJ Capitals.
        </p>

        <p style="margin-bottom: 16px;">
          We were impressed with your qualifications and would like to invite you to a preliminary interview conducted via <strong>Microsoft Teams</strong>.
        </p>

        <div style="background: #f8f9fa; padding: 20px; border-radius: 6px; margin: 24px 0; border-left: 4px solid #d6336c;">
          <p style="margin: 0 0 12px 0; font-weight: bold;">Next Steps:</p>
          <p style="margin: 8px 0;">Please reply to this email with <strong>2-3 time slots</strong> when you are available for a 30-minute interview.</p>
          <p style="margin: 8px 0;">Please include your <strong>local time zone</strong> with your suggested times.</p>
          <p style="margin: 8px 0;">Our team prefers to schedule interviews within the next 48 hours, but we will accommodate your availability.</p>
        </div>

        <p style="margin-bottom: 16px;">
          Once we confirm a mutually agreeable time, we will send you a Microsoft Teams meeting link and detailed interview information.
        </p>

        <p style="margin-bottom: 16px;">
          We look forward to speaking with you soon.
        </p>
      </div>

      <!-- Closing -->
      <div style="margin-top: 32px; padding-top: 24px; border-top: 1px solid #e0e0e0;">
        <p style="margin-bottom: 8px;">Best regards,</p>
        <p style="font-weight: bold; color: #d6336c; margin: 8px 0;">FMJ Capitals Talent Acquisition Team</p>
        <p style="margin: 4px 0;">
          Email: <a href="mailto:support@fmjcareers.com" style="color: #d6336c; text-decoration: none;">support@fmjcareers.com</a>
        </p>
      </div>
    </div>
  </body>
</html>
""".strip()

    body_text = f"""
Dear {applicant_name},

Thank you for your application for the {job_title} position at FMJ Capitals.

We were impressed with your qualifications and would like to invite you to a preliminary interview conducted via Microsoft Teams.

Please reply to this email with 2-3 time slots when you are available for a 30-minute interview. Please include your local time zone with your suggested times. Our team prefers to schedule interviews within the next 48 hours, but we will accommodate your availability.

Once we confirm a mutually agreeable time, we will send you a Microsoft Teams meeting link and detailed interview information.

We look forward to speaking with you soon.

Best regards,
FMJ Capitals Talent Acquisition Team
Email: support@fmjcareers.com
""".strip()

    # Send primary email to applicant
    logger.info(f"Queueing interview scheduling email for {applicant_email}")
    queue_email(
        subject=subject,
        to_email=applicant_email,
        body_html=body_html,
        body_text=body_text,
        from_name="FMJ Capitals Careers"
    )

    # Send admin copy for tracking
    admin_email = cfg.admin_to or cfg.notify_to
    if admin_email and admin_email != applicant_email:
        copy_subject = f"[INTERVIEW SCHEDULING COPY] {subject}"
        logger.info(f"Queueing admin copy to {admin_email}")
        queue_email(
            subject=copy_subject,
            to_email=admin_email,
            body_html=body_html,
            body_text=body_text,
            from_name="FMJ Capitals Careers"
        )
# -----------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------
@app.route("/healthz")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})

@app.route("/")
def home():
    jobs = get_jobs()
    resp = make_response(render_template("home.html", jobs=jobs))
    return resp

@app.route("/careers")
def careers():
    jobs = get_jobs()
    return render_template("careers.html", jobs=jobs)

@app.route("/job/<int:id>")
def show_job(id: int):
    job = get_job(id)
    if not job:
        return "Job not found", 404
    return render_template("jobpage.html", job=job)

@app.route("/iloveyou")
def iloveyou():
    return render_template("iloveyou.html")

@app.route("/job/<int:id>/apply", methods=["POST"])
def apply_to_job(id: int):
    job = get_job(id)
    if not job:
        return "Job not found", 404

    data = {
        "full_name": request.form.get("full_name"),
        "email": request.form.get("email"),
        "country_code": request.form.get("country_code"),
        "phone_number": request.form.get("phone_number"),
        "linkedin_url": request.form.get("linkedin_url"),
        "education": request.form.get("education"),
        "work_experience": request.form.get("work_experience"),
        "resume_path": request.form.get("resume_path"),
    }

    logger.info(f"Processing application for job {id}: {data.get('full_name')}")

    try:
        # Store application immediately
        add_application_to_db(job["title"], data)

        # Immediate emails
        send_application_notification(job["title"], data)          # to admin
        send_applicant_confirmation_email(data, job["title"])      # to applicant (+ admin copy)

        # Schedule interview email for next working day 10am US time
        scheduled_local = next_working_day_10am_us()
        scheduled_utc = scheduled_local.astimezone(timezone.utc)
        schedule_interview_email(job["title"], data, scheduled_utc)

        logger.info(
            "Interview scheduling email queued in DB for %s at %s (UTC)",
            data.get("email"), scheduled_utc.isoformat()
        )

        logger.info(f"Application processed successfully for {data.get('full_name')}")
        return render_template("applicationsubmited.html", application=data, job=job)

    except Exception as e:
        logger.exception(f"Application handling failed for {data.get('full_name')}")
        return f"An error occurred: {str(e)}", 500


# Cron route to actually send scheduled interview emails
@app.route("/cron/send-interview-emails")
def cron_send_interview_emails():
    """
    This route should be hit by a cron job (e.g. Render cron, GitHub Actions, etc).
    It sends all due interview-scheduling emails whose scheduled_at <= now (UTC).
    Protected with CRON_SECRET so random people can't trigger it.
    """
    if CRON_SECRET:
        token = request.args.get("token")
        if token != CRON_SECRET:
            return "unauthorized", 401

    now_utc = datetime.now(timezone.utc)
    logger.info("cron.send_interview_emails started at %s", now_utc.isoformat())

    try:
        due_items = get_due_interview_emails(now_utc)
        sent_count = 0

        for item in due_items:
            try:
                application_data = {
                    "full_name": item["full_name"],
                    "email": item["email"],
                }
                job_title = item["job_title"]

                send_interview_scheduling_email(application_data, job_title)
                mark_interview_email_sent(item["id"])
                sent_count += 1
            except Exception:
                logger.exception("Failed sending scheduled interview email id=%s", item.get("id"))

        logger.info(
            "cron.send_interview_emails finished: sent=%d at %s",
            sent_count, datetime.now(timezone.utc).isoformat()
        )
        return jsonify({"ok": True, "sent": sent_count, "checked_at": now_utc.isoformat()})
    except Exception as e:
        logger.exception("cron.send_interview_emails failed")
        return jsonify({"ok": False, "error": str(e)}), 500


# SendGrid Event Webhook (delivery, bounce, open, click, etc.)
@app.post("/hooks/sendgrid")
def sendgrid_events():
    token = request.args.get("token")
    if token != os.getenv("SENDGRID_WEBHOOK_TOKEN"):
        return "unauthorized", 401
    try:
        events = request.get_json(force=True, silent=False)
        for ev in events or []:
            logger.info(
                "mail.event provider=sendgrid event=%s sg_message_id=%s email=%s mail_id=%s ts=%s reason=%s",
                ev.get("event"),
                ev.get("sg_message_id"),
                ev.get("email"),
                (ev.get("custom_args") or {}).get("mail_id"),
                ev.get("timestamp"),
                ev.get("reason"),
            )
    except Exception:
        logger.exception("mail.event.parse_error")
        return "bad request", 400
    return "ok", 200


# Debug routes for email testing
@app.route("/debug-email")
def debug_email():
    """Debug email configuration"""
    debug_info = {
        "email_enabled": cfg.email_enabled,
        "email_provider": cfg.email_provider,
        "email_address": cfg.email_address,
        "from_name": cfg.from_name,
        "admin_to": cfg.admin_to,
        "notify_to": cfg.notify_to,
        "has_sendgrid_key": bool(cfg.sendgrid_api_key),
        "sendgrid_key_length": len(cfg.sendgrid_api_key) if cfg.sendgrid_api_key else 0,
        "is_render": cfg.is_render,
        "flask_env": cfg.flask_env,
        "email_inline_send": cfg.email_inline_send,
    }

    # Test sending a simple email (respects inline/queue mode)
    test_sent = False
    test_error = None

    try:
        test_to = cfg.admin_to or cfg.notify_to or cfg.email_address
        if test_to:
            queue_email(
                "FMJ Capitals Careers - Test Email from Production",
                test_to,
                body_text=f"This is a test email from your production server.\n\nTime: {datetime.utcnow().isoformat()}\nEnvironment: {cfg.flask_env}\nProvider: {cfg.email_provider}",
                from_name="FMJ Capitals Careers Debug"
            )
            test_sent = True
        else:
            test_error = "No recipient email address configured"
    except Exception as e:
        test_error = str(e)
        logger.exception("Test email failed")

    debug_info["test_email_sent"] = test_sent
    debug_info["test_email_error"] = test_error

    return jsonify(debug_info)


@app.route("/test-email-apply")
def test_email_apply():
    """Test the application email flow without submitting a real application"""
    test_application = {
        "full_name": "Test Applicant",
        "email": cfg.admin_to or cfg.email_address,  # Send to yourself for testing
        "country_code": "+1",
        "phone_number": "555-123-4567",
        "linkedin_url": "https://linkedin.com/in/test",
        "education": "Test University",
        "work_experience": "5 years in test engineering"
    }

    test_job_title = "Software Engineer"

    try:
        send_application_notification(test_job_title, test_application)
        send_applicant_confirmation_email(test_application, test_job_title)
        # This sends immediately; for the real flow, cron handles timing.
        send_interview_scheduling_email(test_application, test_job_title)

        return jsonify({
            "success": True,
            "message": "Test emails queued/sent successfully",
            "application": test_application
        })
    except Exception as e:
        logger.exception("Test email apply failed")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# Optional test route for email (original)
if cfg.enable_email_test_route:
    @app.route("/__test_email")
    def test_email():
        try:
            queue_email(
                "FMJ Capitals Careers: Email Test",
                cfg.admin_to or cfg.notify_to or cfg.email_address,
                body_text="This is a test email from FMJ Capitals Careers.",
            )
            return jsonify({"queued_or_sent": True, "inline": cfg.email_inline_send})
        except Exception as e:
            logger.exception("Failed to queue test email")
            return jsonify({"queued_or_sent": False, "error": str(e)}), 500


# -----------------------------------------------------------------------------
# Diagnostics for SendGrid (handy but optional)
# -----------------------------------------------------------------------------
@app.get("/__sg_ping")
def __sg_ping():
    try:
        r = requests.get("https://api.sendgrid.com/v3/", timeout=10)
        return {"status": r.status_code, "ok": r.status_code in (200, 401)}
    except Exception as ex:
        return {"status": 0, "error": str(ex)}

@app.get("/__sg_auth_check")
def __sg_auth_check():
    try:
        headers = {"Authorization": f"Bearer {cfg.sendgrid_api_key}"} if cfg.sendgrid_api_key else {}
        r = requests.get("https://api.sendgrid.com/v3/user/account", headers=headers, timeout=10)
        return {"status": r.status_code, "has_key": bool(cfg.sendgrid_api_key)}
    except Exception as ex:
        return {"status": 0, "has_key": bool(cfg.sendgrid_api_key), "error": str(ex)}


# -----------------------------------------------------------------------------
# Error Handlers (safe)
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(error):
    return _try_render('404.html', 404)

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {error}")
    return _try_render('500.html', 500)


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # In production, run behind gunicorn/uwsgi. Flask dev server is not for prod.
    debug = cfg.flask_env != "production"
    logger.info(f"Starting Flask app in {'debug' if debug else 'production'} mode")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=debug)
