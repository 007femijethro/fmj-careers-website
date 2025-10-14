# app.py
import os
import json
import logging
import threading
import time
from queue import Queue, Empty

import requests
from flask import Flask, request, jsonify, render_template, Response

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("fmjcareers")

# ------------------------------------------------------------------------------
# Flask
# ------------------------------------------------------------------------------
app = Flask(__name__)

# ------------------------------------------------------------------------------
# Config from environment
# ------------------------------------------------------------------------------
def as_bool(v: str | None, default=False) -> bool:
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")

FLASK_ENV                 = os.getenv("FLASK_ENV", "production")
EMAIL_ENABLED             = as_bool(os.getenv("EMAIL_ENABLED"), True)
EMAIL_PROVIDER            = os.getenv("EMAIL_PROVIDER", "sendgrid").lower()
EMAIL_ADDRESS             = os.getenv("EMAIL_ADDRESS", "no-reply@fmjcareers.com")
FROM_NAME                 = os.getenv("FROM_NAME", "FMJ Careers")
REPLY_TO                  = os.getenv("REPLY_TO")  # optional
ADMIN_TO                  = os.getenv("ADMIN_TO", os.getenv("NOTIFY_TO", "devfemijethro@gmail.com"))
ENABLE_EMAIL_TEST_ROUTE   = as_bool(os.getenv("ENABLE_EMAIL_TEST_ROUTE"), True)
SENDGRID_API_KEY          = os.getenv("SENDGRID_API_KEY", "")
SENDGRID_WEBHOOK_TOKEN    = os.getenv("SENDGRID_WEBHOOK_TOKEN", "")
EMAIL_TIMEOUT             = int(os.getenv("EMAIL_TIMEOUT", "15"))
EMAIL_MAX_RETRIES         = int(os.getenv("EMAIL_MAX_RETRIES", "2"))
# Force inline send on Render (or override explicitly)
EMAIL_INLINE_SEND         = as_bool(os.getenv("EMAIL_INLINE_SEND"),
                                    as_bool(os.getenv("RENDER"), True))

RUNNING_ON_RENDER         = as_bool(os.getenv("RENDER"), True)  # Render sets RENDER=1

app.config["TEMPLATES_AUTO_RELOAD"] = (FLASK_ENV != "production")

logger.info("Application starting with config: %s", {
    "flask_env": FLASK_ENV,
    "email_enabled": EMAIL_ENABLED,
    "email_provider": EMAIL_PROVIDER,
    "email_address": EMAIL_ADDRESS,
    "from_name": FROM_NAME,
    "reply_to": REPLY_TO,
    "admin_to": ADMIN_TO,
    "enable_email_test_route": ENABLE_EMAIL_TEST_ROUTE,
    "served_over_https": True,
    "email_timeout": EMAIL_TIMEOUT,
    "email_max_retries": EMAIL_MAX_RETRIES,
    "inline_send": EMAIL_INLINE_SEND,
    "sg_key_set": bool(SENDGRID_API_KEY),
})
logger.info("Running on Render: %s", RUNNING_ON_RENDER)
logger.info("Email provider: %s, Enabled: %s", EMAIL_PROVIDER, EMAIL_ENABLED)

# ------------------------------------------------------------------------------
# Error handlers with safe fallbacks (no templates required)
# ------------------------------------------------------------------------------
def _try_render(name, **ctx):
    try:
        return render_template(name, **ctx)
    except Exception:
        return Response(
            f"{ctx.get('code', 500)} error at {request.path}",
            status=ctx.get("code", 500),
            mimetype="text/plain",
        )

@app.errorhandler(404)
def not_found(e):
    return _try_render("404.html", code=404), 404

@app.errorhandler(500)
def internal_error(e):
    return _try_render("500.html", code=500), 500

@app.get("/favicon.ico")
def favicon():
    return "", 204

# ------------------------------------------------------------------------------
# SendGrid direct sender with robust logging
# ------------------------------------------------------------------------------
def send_via_sendgrid(to_email: str, subject: str, text: str) -> int:
    url = "https://api.sendgrid.com/v3/mail/send"
    payload = {
        "personalizations": [{"to": [{"email": to_email}]}],
        "from": {"email": EMAIL_ADDRESS, "name": FROM_NAME},
        "subject": subject,
        "content": [{"type": "text/plain", "value": text}],
    }
    if REPLY_TO:
        payload["reply_to"] = {"email": REPLY_TO}

    headers = {
        "Authorization": f"Bearer {SENDGRID_API_KEY}",
        "Content-Type": "application/json",
    }

    logger.info(
        "mail.provider_request provider=sendgrid to=%s subject=%s body_len=%s",
        to_email, subject, len(text),
    )
    try:
        r = requests.post(url, headers=headers, json=payload, timeout=EMAIL_TIMEOUT)
        logger.info(
            "mail.provider_response provider=sendgrid status=%s body=%s",
            r.status_code, (r.text or "<empty>")[:800],
        )
        return r.status_code
    except Exception as ex:
        logger.exception("mail.provider_exception provider=sendgrid error=%s", ex)
        return 0

# ------------------------------------------------------------------------------
# Tiny async mailer (optional). Inline mode bypasses this.
# ------------------------------------------------------------------------------
class AsyncMailer:
    def __init__(self):
        self.q: Queue[tuple[str, str, str, int]] = Queue()
        self._alive = True
        self.thread = threading.Thread(target=self._loop, name="AsyncMailer", daemon=True)
        self.thread.start()
        logger.info("AsyncMailer initialized and worker started")

    def enqueue(self, to_email: str, subject: str, text: str):
        logger.info("mail.enqueue to=%s subject=%s", to_email, subject)
        self.q.put((to_email, subject, text, 0))
        logger.info("Email queued successfully for %s", to_email)

    def _loop(self):
        logger.info("mail.worker_started")
        while self._alive:
            try:
                to_email, subject, text, attempt = self.q.get(timeout=1)
            except Empty:
                continue
            try:
                if not EMAIL_ENABLED:
                    logger.info("mail.disabled skipping send to=%s subject=%s", to_email, subject)
                elif EMAIL_PROVIDER == "sendgrid":
                    code = send_via_sendgrid(to_email, subject, text)
                    if code != 202 and attempt < EMAIL_MAX_RETRIES:
                        logger.warning("mail.retry code=%s attempt=%s to=%s", code, attempt+1, to_email)
                        time.sleep(1.5)
                        self.q.put((to_email, subject, text, attempt + 1))
                else:
                    logger.error("Unsupported EMAIL_PROVIDER=%s", EMAIL_PROVIDER)
            except Exception as ex:
                logger.exception("mail.worker_exception %s", ex)

    def stop(self):
        self._alive = False

async_mailer = AsyncMailer()

def queue_or_send(to_email: str, subject: str, text: str) -> int:
    if EMAIL_INLINE_SEND:
        return send_via_sendgrid(to_email, subject, text)
    else:
        async_mailer.enqueue(to_email, subject, text)
        return 202  # accepted into local queue

# ------------------------------------------------------------------------------
# Basic pages
# ------------------------------------------------------------------------------
@app.get("/")
def index():
    # If you have a template homepage, render it.
    # Using safe fallback here to avoid template errors in minimal setup:
    return Response("FMJ Careers – service is up.", mimetype="text/plain")

# ------------------------------------------------------------------------------
# Diagnostics (remove or protect later)
# ------------------------------------------------------------------------------
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
        headers = {"Authorization": f"Bearer {SENDGRID_API_KEY}"} if SENDGRID_API_KEY else {}
        r = requests.get("https://api.sendgrid.com/v3/user/account", headers=headers, timeout=10)
        return {"status": r.status_code, "has_key": bool(SENDGRID_API_KEY)}
    except Exception as ex:
        return {"status": 0, "has_key": bool(SENDGRID_API_KEY), "error": str(ex)}

@app.get("/__mail_direct")
def __mail_direct():
    if not EMAIL_ENABLED:
        return {"ok": False, "msg": "EMAIL_ENABLED=false"}, 400
    to = request.args.get("to", ADMIN_TO)
    status = send_via_sendgrid(to, "FMJ Careers: Render direct send", "Hello from Render inline-send.")
    return {"status": status, "to": to}

# ------------------------------------------------------------------------------
# Simple test routes that use queue_or_send (respects inline/queue mode)
# ------------------------------------------------------------------------------
@app.get("/__test_email")
def __test_email():
    if not ENABLE_EMAIL_TEST_ROUTE:
        return {"ok": False, "msg": "disabled"}, 403
    to = request.args.get("to", ADMIN_TO)
    status = queue_or_send(to, "FMJ Careers: Email Test", "Hello from app test route.")
    return {"status": status, "to": to}

@app.get("/debug-email")
def debug_email():
    to = request.args.get("to", ADMIN_TO)
    subject = "FMJ Careers - Test Email from Production"
    text = "This is a production test email."
    status = queue_or_send(to, subject, text)
    return {"status": status, "to": to}

# ------------------------------------------------------------------------------
# SendGrid Event Webhook
# ------------------------------------------------------------------------------
@app.post("/hooks/sendgrid")
def sendgrid_webhook():
    token = request.args.get("token", "")
    if not SENDGRID_WEBHOOK_TOKEN or token != SENDGRID_WEBHOOK_TOKEN:
        logger.warning("mail.webhook unauthorized token=%s", token)
        return "unauthorized", 401

    try:
        events = request.get_json(force=True, silent=False)
        if not isinstance(events, list):
            # SendGrid always sends a list of events
            events = [events]
        for ev in events:
            logger.info(
                "mail.event provider=sendgrid event=%s sg_message_id=%s email=%s mail_id=%s ts=%s reason=%s",
                ev.get("event"),
                ev.get("sg_message_id"),
                ev.get("email"),
                (ev.get("custom_args") or {}).get("mail_id"),
                ev.get("timestamp"),
                ev.get("reason"),
            )
        return "ok", 200
    except Exception as ex:
        logger.exception("mail.webhook_exception %s", ex)
        return "bad request", 400

# ------------------------------------------------------------------------------
# Gunicorn entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Local run: python app.py
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port)
