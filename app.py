# app.py
from __future__ import annotations

import json
import os
import uuid
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

import requests
import smtplib

from flask import (
    Flask,
    render_template,
    request,
    make_response,
    jsonify,
    g,
)
from dotenv import load_dotenv
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
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

    # Email
    email_enabled: bool = _get_bool("EMAIL_ENABLED", True)
    email_address: str = os.getenv("EMAIL_ADDRESS", "")
    email_password: str = os.getenv("EMAIL_PASSWORD", "")
    smtp_server: str = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port: int = _get_int("SMTP_PORT", 587)
    smtp_security: str = os.getenv("SMTP_SECURITY", "starttls").lower()

    from_name: str = os.getenv("FROM_NAME", "FMJ Careers")
    reply_to: Optional[str] = os.getenv("REPLY_TO") or None
    admin_to: str = os.getenv("ADMIN_TO", "")
    notify_to: str = os.getenv("NOTIFY_TO", "")

    # Feature flags
    debug_smtp: bool = _get_bool("DEBUG_SMTP", False)
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
        return tuple(
            c.strip() for c in self.allowed_countries_csv.split(",") if c.strip()
        )


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
# Email Service
# -----------------------------------------------------------------------------
class EmailService:
    def __init__(self, cfg: AppConfig) -> None:
        self.cfg = cfg
        if not self.cfg.email_enabled:
            logger.warning("EMAIL_ENABLED=false — email sending is disabled.")

    def _connect(self) -> smtplib.SMTP:
        server = smtplib.SMTP(self.cfg.smtp_server, self.cfg.smtp_port, timeout=30)
        if self.cfg.debug_smtp:
            server.set_debuglevel(1)
        server.ehlo()
        if self.cfg.smtp_security in ("starttls", "tls", "true", "1", "yes"):
            server.starttls()
            server.ehlo()
        server.login(self.cfg.email_address, self.cfg.email_password)
        return server

    def _build_message(
        self,
        subject: str,
        to_addr: str,
        body_html: Optional[str] = None,
        body_text: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> MIMEMultipart:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = formataddr((from_name or self.cfg.from_name, self.cfg.email_address))
        msg["To"] = to_addr
        if self.cfg.reply_to:
            msg["Reply-To"] = self.cfg.reply_to

        if body_text:
            msg.attach(MIMEText(body_text, "plain"))
        if body_html:
            msg.attach(MIMEText(body_html, "html"))

        # Always ensure at least plain version
        if not body_text and not body_html:
            msg.attach(MIMEText(" ", "plain"))

        return msg

    def send(
        self,
        subject: str,
        to_addr: str,
        body_html: Optional[str] = None,
        body_text: Optional[str] = None,
        from_name: Optional[str] = None,
    ) -> bool:
        if not self.cfg.email_enabled:
            logger.info(f"Email disabled: would send to {to_addr} — {subject}")
            return False

        try:
            msg = self._build_message(subject, to_addr, body_html, body_text, from_name)
            with self._connect() as server:
                server.send_message(msg)
            logger.info(f"Email sent: to={to_addr} subject={subject!r}")
            return True
        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP auth failed: {e}")
        except Exception as e:
            logger.exception(f"Failed to send email: {e}")
        return False


mailer = EmailService(cfg)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def get_geolocation(ip: str) -> Dict[str, Any]:
    """Get detailed geolocation data from IP using ip-api.com"""
    if ip in ("127.0.0.1", "::1"):
        return {"status": "localhost"}

    try:
        # fields=66846719 requests a wide set of fields in one call
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        logger.warning(f"Geo lookup failed for IP={ip}: {e}")
        return {"error": str(e), "status": "error"}

def get_device_fingerprint(req) -> Dict[str, Any]:
    """Generate basic fingerprint from available headers"""
    user_agent = parse_ua(req.headers.get("User-Agent", ""))
    return {
        "browser": f"{user_agent.browser.family} {user_agent.browser.version_string}",
        "os": f"{user_agent.os.family} {user_agent.os.version_string}",
        "device": user_agent.device.family,
        "is_mobile": user_agent.is_mobile,
        "is_tablet": user_agent.is_tablet,
        "is_pc": user_agent.is_pc,
        "is_bot": user_agent.is_bot,
        "languages": req.headers.get("Accept-Language", ""),
        "accept": req.headers.get("Accept", ""),
        "encoding": req.headers.get("Accept-Encoding", ""),
        "connection": req.headers.get("Connection", ""),
        "dnt": req.headers.get("DNT", ""),
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

    # Resolve IP (respect X-Forwarded-For if behind proxy)
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

    # Enhanced device fingerprint
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
        "headers": dict(request.headers),
        "geodata": geodata,
        "device": device_data,
        "query_params": dict(request.args),
    }

    # Persist to DB
    try:
        log_visitor(visitor_data)
    except Exception as e:
        logger.exception(f"Failed to log visitor: {e}")

    # Decide if we notify (first visit today)
    g.notify_today = (not last_visit) or (last_visit != today_str())
    g.visitor_id = visitor_id

    # Stash for after_request to set cookies
    g.set_cookies = {
        cfg.visitor_cookie: (visitor_id, cfg.cookie_days),
        cfg.tracking_cookie: (today_str(), 1),
    }

    # Send low-volume daily alert (internal)
    if g.notify_today:
        try:
            subject = f"New Visitor Analytics - {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"
            body_text = (
                "COMPLETE VISITOR ANALYTICS REPORT\n"
                "=================================\n\n"
                f"BASIC INFO:\n"
                f"- Time: {visitor_data['timestamp']}\n"
                f"- Unique ID: {visitor_data['visitor_id']}\n"
                f"- First Visit: {visitor_data['first_visit']}\n"
                f"- Page Visited: {visitor_data['path']}\n\n"
                f"NETWORK DATA:\n"
                f"- IP Address: {visitor_data['ip']}\n"
                f"- ISP: {visitor_data['geodata'].get('isp', 'N/A')}\n"
                f"- AS: {visitor_data['geodata'].get('as', 'N/A')}\n"
                f"- Proxy: {visitor_data['geodata'].get('proxy', False)}\n\n"
                f"LOCATION:\n"
                f"- Country: {visitor_data['geodata'].get('country', 'N/A')}\n"
                f"- Region: {visitor_data['geodata'].get('regionName', 'N/A')}\n"
                f"- City: {visitor_data['geodata'].get('city', 'N/A')}\n"
                f"- ZIP: {visitor_data['geodata'].get('zip', 'N/A')}\n"
                f"- Coordinates: {visitor_data['geodata'].get('lat', 'N/A')}, {visitor_data['geodata'].get('lon', 'N/A')}\n\n"
                f"DEVICE INFO:\n"
                f"- Browser: {visitor_data['device']['browser']}\n"
                f"- OS: {visitor_data['device']['os']}\n"
                f"- Device: {visitor_data['device']['device']}\n"
                f"- Mobile: {visitor_data['device']['is_mobile']}\n"
                f"- Languages: {visitor_data['device']['languages']}\n\n"
                f"TECHNICAL DETAILS:\n"
                f"- Referrer: {visitor_data.get('referrer', 'Direct')}\n"
                f"- User Agent: {visitor_data['raw_ua']}\n"
                f"- Headers: {json.dumps(visitor_data['headers'], indent=2)}\n"
            )
            if cfg.notify_to:
                mailer.send(subject, cfg.notify_to, body_text=body_text, from_name="FMJ Career (Location Services)")
        except Exception as e:
            logger.exception(f"Failed to send visitor email: {e}")

    # Continue
    return None


@app.after_request
def set_tracking_cookies(response):
    # Set cookies once per request if requested by before_request
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
# Email Composers
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
        mailer.send(subject, cfg.admin_to, body_text=body_text, from_name="FMJ Careers")

def send_applicant_confirmation_email(application_data: Dict[str, Any], job_title: str) -> None:
    # Validate
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

    mailer.send(subject, applicant_email, body_html=body_html, from_name="FMJ Careers")


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
        send_application_notification(job["title"], data)
        send_applicant_confirmation_email(data, job["title"])

        return render_template("applicationsubmited.html", application=data, job=job)
    except Exception as e:
        logger.exception("Application handling failed")
        return f"An error occurred: {str(e)}", 500


# Optional test route for SMTP
if cfg.enable_email_test_route:
    @app.route("/__test_email")
    def test_email():
        ok = mailer.send(
            "FMJ Careers: SMTP Test",
            cfg.admin_to or cfg.notify_to or cfg.email_address,
            body_text="This is a test email from FMJ Careers.",
        )
        return jsonify({"sent": ok})


# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    # In production, run behind a WSGI server (gunicorn/uwsgi). Flask dev server is not for prod.
    debug = cfg.flask_env != "production"
    app.run(host="0.0.0.0", debug=debug)
