# app.py
import os
import json
import uuid
import ssl
import smtplib
import requests
from datetime import datetime

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
from user_agents import parse as parse_ua

# Your own DB helpers
from database import get_jobs, get_job, add_application_to_db, log_visitor

# Email libs
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr, formatdate, make_msgid


# =========================
# App / Config
# =========================
load_dotenv()

app = Flask(__name__)

# Use the provider's STARTTLS host to avoid certificate hostname mismatch
SMTP_HOST = os.getenv("SMTP_HOST", "us2.smtp.mailhostbox.com")  # your provider shows this for STARTTLS
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))                  # 587 = STARTTLS, 465 = implicit SSL

EMAIL_ADDRESS = os.getenv("EMAIL_ADDRESS")                      # e.g. chaserice@chasericefanpage.com
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")

ADMIN_TO = os.getenv("ADMIN_TO", "devfemijethro@gmail.com")     # analytics recipient
NOTIFY_TO = os.getenv("NOTIFY_TO", "007femijethro@gmail.com")   # internal notifications
NOTIFY_CC = os.getenv("NOTIFY_CC", "Chase.rice.fanpage223@gmail.com,eoni56699@gmail.com")


# =========================
# Helpers
# =========================
def add_required_headers(msg: MIMEMultipart) -> None:
    """
    Ensure RFC 5322 required headers exist and are valid:
    - Message-ID: unique and includes a domain you control
    - Date: set to localtime now
    """
    from_addr = msg.get("From", "")
    domain = "localhost"
    if "@" in from_addr:
        domain = from_addr.split("@", 1)[1].strip("> ")
    elif EMAIL_ADDRESS and "@" in EMAIL_ADDRESS:
        domain = EMAIL_ADDRESS.split("@", 1)[1]

    if not msg.get("Message-ID"):
        msg["Message-ID"] = make_msgid(domain=domain)
    if not msg.get("Date"):
        msg["Date"] = formatdate(localtime=True)


def smtp_send(msg: MIMEMultipart, to_addrs):
    """
    Send a MIME message over SMTP with certificate verification.
    Supports:
      - STARTTLS (587) using SMTP + starttls
      - Implicit SSL (465) using SMTP_SSL
    """
    if isinstance(to_addrs, str):
        to_addrs = [a.strip() for a in to_addrs.split(",") if a.strip()]

    context = ssl.create_default_context()

    def _login_and_send(server):
        server.ehlo()
        # STARTTLS path
        if isinstance(server, smtplib.SMTP):
            server.starttls(context=context)
            server.ehlo()
        if EMAIL_ADDRESS and EMAIL_PASSWORD:
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_addrs, msg.as_string())

    if SMTP_PORT == 465:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=25) as s:
            _login_and_send(s)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as s:
            _login_and_send(s)


def get_client_ip(req) -> str:
    """Best-effort client IP extraction behind proxies/CDNs."""
    for h in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
        if h in req.headers and req.headers[h]:
            return req.headers[h].split(",")[0].strip()
    return req.remote_addr or "127.0.0.1"


def get_geolocation(ip: str) -> dict:
    """Fetch geolocation info (non-fatal if it fails)."""
    if ip in ("127.0.0.1", "::1"):
        return {"status": "localhost"}
    try:
        # ip-api fields bitmask for a rich set
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=5)
        return r.json()
    except Exception as e:
        return {"error": str(e)}


def build_visitor_payload(req) -> dict:
    """
    Structured payload for email/debug. Includes everything we'll map to DB.
    """
    ip = get_client_ip(req)
    ua_str = req.headers.get("User-Agent", "")
    ua = parse_ua(ua_str)

    geodata = get_geolocation(ip)
    cookie_vuid = req.cookies.get("visitor_uid") or ""
    visitor_uid = cookie_vuid or str(uuid.uuid4())

    # Referrer: Flask property, then common header variants
    referrer = req.referrer or req.headers.get("Referer") or req.headers.get("Referrer") or ""

    # Keep a small, non-sensitive header excerpt
    headers_excerpt = {}
    for hk in ["Host", "Accept", "Accept-Language", "Accept-Encoding", "Sec-Fetch-Mode", "Sec-Fetch-Site"]:
        if hk in req.headers:
            headers_excerpt[hk] = req.headers[hk]

    return {
        "visitor_id": visitor_uid,
        "basic": {
            "time": datetime.utcnow().isoformat(),
            "unique_id": visitor_uid,
            "first_visit": not bool(cookie_vuid),
            "page": req.path or "/",
        },
        "network": {"ip": ip},
        "geodata": geodata or {},
        "device": {
            "browser": str(ua.browser),
            "os": str(ua.os),
            "device": ua.device.family or "Other",
            "is_mobile": ua.is_mobile,
            "is_bot": ua.is_bot,
            "user_agent": ua_str,
        },
        "referrer": referrer,
        "headers": headers_excerpt,
    }


def build_db_record(v: dict) -> dict:
    """
    Flatten payload to EXACTLY your DB schema and also include a legacy
    'timestamp' key because log_visitor() is asking for it.
    """
    basic   = v.get("basic")   or {}
    g       = v.get("geodata") or {}
    d       = v.get("device")  or {}
    network = v.get("network") or {}

    when_iso = basic.get("time") or datetime.utcnow().isoformat()
    page     = basic.get("page") or "/"

    record = {
        "visitor_id": v.get("visitor_id"),
        "ip": network.get("ip"),

        # Table column (your schema) …
        "visit_timestamp": when_iso,
        # …and the key your helper is demanding:
        "timestamp": when_iso,                       # <<< added

        "page_path": page,
        "referrer_url": v.get("referrer") or "",
        "user_agent": d.get("user_agent"),
        "browser": d.get("browser"),
        "operating_system": d.get("os"),
        "device_type": d.get("device"),
        "country": g.get("country"),
        "region": g.get("regionName") or g.get("region"),
        "city": g.get("city"),
        "isp": g.get("isp"),
        "is_mobile": bool(d.get("is_mobile")),
        "is_bot": bool(d.get("is_bot")),
        "additional_data": v,                        # jsonb
        "created_at": datetime.utcnow().isoformat(),
    }
    return record


def format_visitor_email_text(v: dict) -> str:
    """Readable analytics email body."""
    parts = []
    parts.append("COMPLETE VISITOR ANALYTICS REPORT")
    parts.append("=================================")
    parts.append("")
    parts.append("BASIC INFO:")
    parts.append(f"- Time: {v['basic'].get('time')}")
    parts.append(f"- Unique ID: {v['basic'].get('unique_id')}")
    parts.append(f"- First Visit: {v['basic'].get('first_visit')}")
    parts.append(f"- Page Visited: {v['basic'].get('page')}")
    parts.append("")
    parts.append("NETWORK DATA:")
    parts.append(f"- IP Address: {v['network'].get('ip')}")
    parts.append("")
    parts.append("LOCATION:")
    g = v.get("geodata", {})
    parts.append(f"- Country: {g.get('country')}")
    parts.append(f"- Region: {g.get('regionName') or g.get('region')}")
    parts.append(f"- City: {g.get('city')}")
    if g.get("lat") and g.get("lon"):
        parts.append(f"- Coordinates: {g.get('lat')}, {g.get('lon')}")
    parts.append("")
    d = v["device"]
    parts.append("DEVICE INFO:")
    parts.append(f"- Browser: {d.get('browser')}")
    parts.append(f"- OS: {d.get('os')}")
    parts.append(f"- Device: {d.get('device')}")
    parts.append(f"- Mobile: {d.get('is_mobile')}")
    parts.append(f"- Bot: {d.get('is_bot')}")
    parts.append("")
    parts.append("REFERRER:")
    parts.append(f"- {v.get('referrer') or '(none)'}")
    parts.append("")
    parts.append("TECHNICAL (headers excerpt):")
    for hk, hv in (v.get("headers") or {}).items():
        parts.append(f"- {hk}: {hv}")
    parts.append("")
    parts.append("Full JSON payload:")
    parts.append(json.dumps(v, indent=2))
    return "\n".join(parts)


# =========================
# Email senders
# =========================
def send_visitor_email(visitor_data: dict):
    msg = MIMEMultipart()
    msg["From"] = formataddr(("FMJ Career (Location Services)", EMAIL_ADDRESS or "no-reply@localhost"))
    msg["To"] = ADMIN_TO
    msg["Subject"] = "COMPLETE VISITOR ANALYTICS REPORT"
    add_required_headers(msg)
    msg.attach(MIMEText(format_visitor_email_text(visitor_data), "plain", "utf-8"))
    smtp_send(msg, ADMIN_TO)


def send_application_notification(job_title: str, application_data: dict):
    to_addr = NOTIFY_TO
    cc_list = [a.strip() for a in NOTIFY_CC.split(",") if a.strip()]
    msg = MIMEMultipart()
    msg["From"] = formataddr(("FMJ Careers", EMAIL_ADDRESS or "no-reply@localhost"))
    msg["To"] = to_addr
    if cc_list:
        msg["Cc"] = ", ".join(cc_list)
    msg["Subject"] = f"New Application for {job_title}"
    add_required_headers(msg)

    body = "A new application was submitted for {}.\n\n{}".format(
        job_title, json.dumps(application_data, indent=2)
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))

    recipients = [to_addr] + cc_list
    smtp_send(msg, recipients)


def send_applicant_confirmation_email(application_data: dict, job_title: str):
    applicant_email = application_data.get("email")
    if not applicant_email:
        return
    msg = MIMEMultipart()
    msg["From"] = formataddr(("FMJ Careers", EMAIL_ADDRESS or "no-reply@localhost"))
    msg["To"] = applicant_email
    msg["Subject"] = f"Your Application for {job_title} has been received"
    add_required_headers(msg)

    body = (
        f"Hello {application_data.get('full_name') or application_data.get('name', 'Applicant')},\n\n"
        f"Thanks for applying for {job_title}. We’ve received your application and our team will review it.\n\n"
        f"Regards,\nFMJ Careers"
    )
    msg.attach(MIMEText(body, "plain", "utf-8"))
    smtp_send(msg, applicant_email)


# =========================
# Routes
# =========================
@app.after_request
def set_visitor_cookie(resp):
    """Persist a visitor cookie for correlation across visits."""
    if not request.cookies.get("visitor_uid"):
        vuid = str(uuid.uuid4())
        # Not HttpOnly so front-end can read if needed; tighten if you prefer
        resp.set_cookie("visitor_uid", vuid, max_age=60 * 60 * 24 * 365, httponly=False, samesite="Lax")
    return resp


@app.route("/")
def home():
    # Jobs
    try:
        jobs = get_jobs()
    except Exception as e:
        jobs = []
        app.logger.exception("get_jobs failed: %s", e)

    # Visitor analytics
    visitor_payload = build_visitor_payload(request)

    # DB logging (matches your exact schema)
    try:
        db_record = build_db_record(visitor_payload)
        log_visitor(db_record)
    except Exception as e:
        app.logger.error("Error logging visitor: %s. Keys present: %s", e, list((db_record or {}).keys()))

    # Email (non-blocking for the page; errors only logged)
    try:
        send_visitor_email(visitor_payload)
    except Exception as e:
        app.logger.error("send_visitor_email failed: %s", e)

    # Your repo uses 'home.html'
    return render_template("home.html", jobs=jobs)


# Give templates the endpoint name they expect: 'show_job'
@app.route("/job/<int:id>", endpoint="show_job")
def jobpage(id: int):
    job = get_job(id)
    if not job:
        return "Job not found", 404
    return render_template("jobpage.html", job=job)


@app.route("/job/<int:id>/apply", methods=["POST"])
def apply_to_job(id: int):
    job = get_job(id)
    if not job:
        return "Job not found", 404

    try:
        data = {
            "job_id": id,
            "full_name": request.form.get("full_name"),
            "email": request.form.get("email"),
            "country_code": request.form.get("country_code"),
            "phone_number": request.form.get("phone_number"),
            "linkedin_url": request.form.get("linkedin_url"),
            "education": request.form.get("education"),
            "work_experience": request.form.get("work_experience"),
            "resume_url": request.form.get("resume_url") or request.form.get("resume_path"),
            "submitted_at": datetime.utcnow().isoformat(),
        }

        # Persist application (support both possible helper signatures)
        try:
            job_title = job.get("title") or job.get("name") or f"Job #{id}"
            try:
                add_application_to_db(job_title, data)  # (title, dict)
            except TypeError:
                add_application_to_db(data)            # (dict)
        except Exception as e:
            app.logger.error("add_application_to_db failed: %s", e)

        # Emails
        try:
            send_application_notification(job.get("title") or job.get("name", "Role"), data)
        except Exception as e:
            app.logger.error("send_application_notification failed: %s", e)

        try:
            send_applicant_confirmation_email(data, job.get("title") or job.get("name", "the role"))
        except Exception as e:
            app.logger.error("send_applicant_confirmation_email failed: %s", e)

        return render_template("applicationsubmited.html", application=data, job=job)
    except Exception as e:
        app.logger.exception("Application processing failed: %s", e)
        return f"An error occurred: {str(e)}", 500


@app.route("/_health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()}), 200


# =========================
# Entry
# =========================
if __name__ == "__main__":
    # Use a real WSGI server (gunicorn/uwsgi) in production
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)
