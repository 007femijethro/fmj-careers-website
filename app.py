# app.py
from __future__ import annotations

import json
import os
import uuid
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional, Tuple
from queue import Queue, Empty
from threading import Thread

import requests
from flask import (
    Flask,
    render_template,
    request,
    make_response,
    jsonify,
    g,
)
from dotenv import load_dotenv
from email.utils import formataddr
from user_agents import parse as parse_ua

# Your own DB helpers
from database import get_jobs, get_job, add_application_to_db, log_visitor


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


@dataclass(frozen=True)
class AppConfig:
    secret_key: str = os.getenv("SECRET_KEY", "change-this-before-prod")
    flask_env: str = os.getenv("FLASK_ENV", "production")

    # Email (prefer HTTP providers; SMTP only for local/dev)
    email_enabled: bool = _get_bool("EMAIL_ENABLED", True)
    email_provider: str = os.getenv("EMAIL_PROVIDER", "sendgrid").lower()  # sendgrid|mailgun|postmark|smtp
    email_address: str = os.getenv("EMAIL_ADDRESS", "")
    from_name: str = os.getenv("FROM_NAME", "FMJ Careers")
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
    enable_email_test_route: bool = _get_bool("ENABLE_EMAIL_TEST_ROUTE", False)

    # Tracking / Access control
    allowed_countries_csv: str = os.getenv("ALLOWED_COUNTRIES", "United States,Nigeria")
    visitor_cookie: str = os.getenv("VISITOR_COOKIE", "visitor_uid")
    tracking_cookie: str = os.getenv("TRACKING_COOKIE", "last_visit")
    cookie_days: int = _get_int("COOKIE_DAYS", 365)

    # Security
    served_over_https: bool = _get_bool("SERVED_OVER_HTTPS", False)

    @property
    def allowed_countries(self) -> Tuple[str, ...]:
        return tuple(c.strip() for c in self.allowed_countries_csv.split(",") if c.strip())


cfg = AppConfig()

# -----------------------------------------------------------------------------
# App / Logging
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = cfg.secret_key

logging.basicConfig(
    level=logging.INFO if cfg.flask_env == "production" else logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger("fmjcareers")


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


class AsyncMailer:
    """Tiny in-process queue so web requests never block on email."""
    def __init__(self, cfg: AppConfig):
        self.cfg = cfg
        self.q: "Queue[MailTask]" = Queue(maxsize=1000)
        self.worker = Thread(target=self._run, daemon=True)
        self.worker.start()

    def enqueue(self, task: MailTask) -> None:
        if not self.cfg.email_enabled:
            logger.info("Email disabled: would send to %s — %s", task.to_addr, task.subject)
            return
        try:
            self.q.put_nowait(task)
        except Exception:
            logger.warning("Email queue full; dropping email to %s", task.to_addr)

    def _run(self):
        while True:
            try:
                task = self.q.get(timeout=1.0)
            except Empty:
                continue
            try:
                send_email_via_provider(self.cfg, task)
                logger.info("Email sent: to=%s subject=%r", task.to_addr, task.subject)
            except Exception:
                logger.exception("Failed to send email to %s", task.to_addr)
            finally:
                self.q.task_done()


def send_email_via_provider(cfg: AppConfig, task: MailTask) -> None:
    """Send via HTTPS provider (preferred) or SMTP (dev fallback)."""
    from_addr = formataddr((task.from_name or cfg.from_name, cfg.email_address))
    reply_to = task.reply_to or cfg.reply_to
    timeout = 6  # short, non-blocking

    if cfg.email_provider == "sendgrid":
        if not cfg.sendgrid_api_key:
            raise RuntimeError("SENDGRID_API_KEY missing")
        payload = {
            "personalizations": [{"to": [{"email": task.to_addr}]}],
            "from": {"email": cfg.email_address, "name": task.from_name or cfg.from_name},
            "subject": task.subject,
            "content": (
                [{"type": "text/plain", "value": task.body_text or ""}]
                + ([{"type": "text/html", "value": task.body_html}] if task.body_html else [])
            ),
        }
        headers = {"Authorization": f"Bearer {cfg.sendgrid_api_key}", "Content-Type": "application/json"}
        if reply_to:
            payload["reply_to"] = {"email": reply_to}
        resp = requests.post("https://api.sendgrid.com/v3/mail/send", headers=headers, json=payload, timeout=timeout)
        # SendGrid returns 202 Accepted on success with empty body
        if resp.status_code >= 400:
            resp.raise_for_status()
        return

    if cfg.email_provider == "mailgun":
        if not (cfg.mailgun_domain and cfg.mailgun_api_key):
            raise RuntimeError("MAILGUN_DOMAIN or MAILGUN_API_KEY missing")
        url = f"https://api.mailgun.net/v3/{cfg.mailgun_domain}/messages"
        data = {
            "from": from_addr,
            "to": [task.to_addr],
            "subject": task.subject,
            "text": task.body_text or "",
            "html": task.body_html or None,
        }
        if reply_to:
            data["h:Reply-To"] = reply_to
        resp = requests.post(url, auth=("api", cfg.mailgun_api_key), data=data, timeout=timeout)
        resp.raise_for_status()
        return

    if cfg.email_provider == "postmark":
        if not cfg.postmark_server_token:
            raise RuntimeError("POSTMARK_SERVER_TOKEN missing")
        payload = {
            "From": from_addr,
            "To": task.to_addr,
            "Subject": task.subject,
            "TextBody": task.body_text or "",
            "HtmlBody": task.body_html or None,
            "MessageStream": "outbound",
        }
        if reply_to:
            payload["ReplyTo"] = reply_to
        headers = {"X-Postmark-Server-Token": cfg.postmark_server_token, "Content-Type": "application/json"}
        resp = requests.post("https://api.postmarkapp.com/email", headers=headers, json=payload, timeout=timeout)
        resp.raise_for_status()
        return

    # SMTP fallback (useful locally; often blocked in PaaS prod)
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


mailer = AsyncMailer(cfg)

def queue_email(
    subject: str,
    to_addr: str,
    *,
    body_html: Optional[str] = None,
    body_text: Optional[str] = None,
    from_name: Optional[str] = None,
):
    task = MailTask(
        subject=subject,
        to_addr=to_addr,
        body_html=body_html,
        body_text=body_text,
        from_name=from_name,
    )
    try:
        mailer.enqueue(task)
    except Exception:
        logger.exception("Failed to enqueue email")


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


# -----------------------------------------------------------------------------
# Before/After Request: Tracking + Access Control
# -----------------------------------------------------------------------------
@app.before_request
def track_visitor() -> Optional[Tuple[str, int]]:
    # Block admin paths
    if request.path.lower().startswith(("/wp-admin", "/wordpress/wp-admin")):
        return "Access denied", 403

    # Skip static and health
    if request.path.startswith("/static") or request.path == "/healthz":
        return None

    # Resolve IP (respect X-Forwarded-For)
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    if "," in ip:
        ip = ip.split(",")[0].strip()

    geodata = get_geolocation(ip)
    country = geodata.get("country", "Unknown")

    # Access control by country
    if cfg.allowed_countries and country not in cfg.allowed_countries:
        return render_template("access_denied.html"), 403

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

    # Persist to DB
    try:
        log_visitor(visitor_data)
    except Exception:
        logger.exception("Failed to log visitor")

    # Flags for after_request & notification
    g.notify_today = (not last_visit) or (last_visit != today_str())
    g.visitor_id = visitor_id
    g.set_cookies = {
        cfg.visitor_cookie: (visitor_id, cfg.cookie_days),
        cfg.tracking_cookie: (today_str(), 1),
    }

    # Queue a small daily alert (never block the request)
    if g.notify_today and cfg.notify_to:
        subject = f"New Visitor Analytics - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
        body_text = (
            "COMPLETE VISITOR ANALYTICS REPORT\n"
            "=================================\n\n"
            f"- Time: {visitor_data['timestamp']}\n"
            f"- Unique ID: {visitor_data['visitor_id']}\n"
            f"- First Visit: {visitor_data['first_visit']}\n"
            f"- Page: {visitor_data['path']}\n"
            f"- IP: {visitor_data['ip']}\n"
            f"- Country: {visitor_data['geodata'].get('country', 'N/A')}\n"
            f"- City: {visitor_data['geodata'].get('city', 'N/A')}\n"
            f"- Browser: {visitor_data['device']['browser']}\n"
            f"- OS: {visitor_data['device']['os']}\n"
            f"- Referrer: {visitor_data.get('referrer', 'Direct')}\n"
        )
        try:
            queue_email(subject, cfg.notify_to, body_text=body_text, from_name="FMJ Career (Location Services)")
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
    subject = f"New Application for {job_title}"
    body_text = f"""
New job application received:

Position: {job_title}
Applicant: {application_data.get('full_name')}
Email: {application_data.get('email')}
Phone: {application_data.get('country_code')} {application_data.get('phone_number')}
LinkedIn: {application_data.get('linkedin_url')}
Education: {application_data.get('education')}
Work Experience: {application_data.get('work_experience')}
""".strip()

    if cfg.admin_to:
        queue_email(subject, cfg.admin_to, body_text=body_text, from_name="FMJ Careers")


def send_applicant_confirmation_email(application_data: Dict[str, Any], job_title: str) -> None:
    if not isinstance(application_data, dict):
        raise ValueError("application_data must be a dictionary")
    if "email" not in application_data or "full_name" not in application_data:
        raise ValueError("application_data missing required fields: email or full_name")

    applicant_email = application_data["email"]
    applicant_name = application_data["full_name"]

    subject = f"Your Application for {job_title} has been received"
    body_html = f"""
<html>
  <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; padding: 20px;">
    <div style="max-width: 600px; margin: auto; border: 1px solid #f7c6d3; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(255, 182, 193, 0.3);">
      <img src="https://fmjcareers.com/static/logo.jpg" alt="FMJ Capitals Logo" style="width: 150px; margin-bottom: 30px; display: block; margin-left: auto; margin-right: auto;">

      <p style="font-size: 18px;">Hi <strong style="color: #d6336c;">{applicant_name}</strong>,</p>

      <p style="font-size: 16px; color: #6a1b4d;">Thank you for applying for the <strong style="color: #d6336c;">{job_title}</strong> position with us!</p>

      <p style="font-size: 16px;">We’ve received your information and are currently reviewing applications. To move forward and schedule your interview, please follow the steps below:</p>

      <h3 style="color: #d6336c; border-bottom: 2px solid #f28ab2; padding-bottom: 8px;">✅ Next Steps – Required for Interview Scheduling:</h3>
      <ol style="color: #6a1b4d; font-size: 15px;">
        <li style="margin-bottom: 15px;">
          <strong>Download the Signal Messenger App (Free & Secure):</strong><br>
          Signal is our secure communication platform for interviews. Please download it here:<br>
          <a href="https://signal.org/download/" style="color: #d6336c; text-decoration: none;">Signal for Desktop & Mobile</a>
        </li>
        <li style="margin-bottom: 15px;">
          <strong>Once Installed, Message Our Hiring Manager:</strong><br>
          <em>Aaron Thomas</em><br>
          Signal Number: <em>2394939137</em><br>
          Message Template:<br><br>
          <blockquote style="background-color: #ffd6e8; border-left: 4px solid #d6336c; margin: 0; padding: 12px 16px; font-style: italic; color: #a31545;">
            Hi, my name is {applicant_name}. I applied for the {job_title} position and I’m ready to schedule my interview.
          </blockquote>
        </li>
        <li>
          We’ll schedule your interview via Signal within <strong>24–48 hours</strong>.
        </li>
      </ol>

      <h4 style="color: #d6336c; margin-top: 30px;">🔍 What to Expect After Messaging:</h4>
      <ul style="color: #6a1b4d; font-size: 15px;">
        <li>We’ll confirm your availability and verify a few details</li>
        <li>You’ll receive remote training if hired</li>
        <li>We’ll ship a company laptop and your credentials directly to your address</li>
      </ul>

      <p style="font-size: 16px;">If you have any questions in the meantime, feel free to reply to this email.</p>

      <p style="font-size: 16px;">Thanks again — we look forward to hearing from you!</p>

      <br>

      <p style="font-size: 16px;">Best regards,</p>
      <p style="font-weight: bold; color: #d6336c; font-size: 16px;">Aaron Thomas<br>
         Hiring Coordinator<br>
         FMJ Capitals<br>
         <a href="mailto:aaronthomas@fmjcareers.com" style="color: #d6336c; text-decoration: none;">aaronthomas@fmjcareers.com</a></p>
    </div>
  </body>
</html>
""".strip()

    queue_email(subject, applicant_email, body_html=body_html, from_name="FMJ Careers")


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

    try:
        add_application_to_db(job["title"], data)
        # Queue emails (non-blocking)
        send_application_notification(job["title"], data)
        send_applicant_confirmation_email(data, job["title"])

        return render_template("applicationsubmited.html", application=data, job=job)
    except Exception as e:
        logger.exception("Application handling failed")
        return f"An error occurred: {str(e)}", 500


# Optional test route for email
if cfg.enable_email_test_route:
    @app.route("/__test_email")
    def test_email():
        try:
            queue_email(
                "FMJ Careers: Email Test",
                cfg.admin_to or cfg.notify_to or cfg.email_address,
                body_text="This is a test email from FMJ Careers.",
            )
            return jsonify({"queued": True})
        except Exception:
            logger.exception("Failed to queue test email")
            return jsonify({"queued": False}), 500


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # In production, run behind gunicorn/uwsgi. Flask dev server is not for prod.
    debug = cfg.flask_env != "production"
    app.run(host="0.0.0.0", debug=debug)
