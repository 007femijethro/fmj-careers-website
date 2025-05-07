from flask import Flask, render_template, request, make_response, jsonify
from database import get_jobs, get_job, add_application_to_db, log_visitor
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv
from datetime import datetime
import requests
import json
import uuid
from user_agents import parse

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'fallback-secret-key')

# Configuration
EMAIL_ADDRESS = os.getenv('EMAIL_ADDRESS')
EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD')
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
VISITOR_COOKIE = 'visitor_uid'
TRACKING_COOKIE = 'last_visit'


def get_geolocation(ip):
    """Get detailed geolocation data from IP"""
    if ip in ['127.0.0.1', '::1']:
        return {'status': 'localhost'}

    try:
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=66846719')
        return response.json()
    except Exception as e:
        return {'error': str(e)}


def get_device_fingerprint(request):
    """Generate basic fingerprint from available headers"""
    user_agent = parse(request.headers.get('User-Agent', ''))
    return {
        'browser':
        f"{user_agent.browser.family} {user_agent.browser.version_string}",
        'os': f"{user_agent.os.family} {user_agent.os.version_string}",
        'device': user_agent.device.family,
        'is_mobile': user_agent.is_mobile,
        'is_tablet': user_agent.is_tablet,
        'is_pc': user_agent.is_pc,
        'is_bot': user_agent.is_bot,
        'languages': request.headers.get('Accept-Language', ''),
        'accept': request.headers.get('Accept', ''),
        'encoding': request.headers.get('Accept-Encoding', ''),
        'connection': request.headers.get('Connection', ''),
        'dnt': request.headers.get('DNT', '')
    }


def send_visitor_email(visitor_data):
    """Send detailed visitor report"""
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = EMAIL_ADDRESS
        msg['Cc'] = 'eoni56699@gmail.com'
        msg['Subject'] = f"New Visitor Analytics - {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        # Format the email body
        body = f"""
        COMPLETE VISITOR ANALYTICS REPORT
        =================================

        BASIC INFO:
        - Time: {visitor_data['timestamp']}
        - Unique ID: {visitor_data['visitor_id']}
        - First Visit: {visitor_data['first_visit']}
        - Page Visited: {visitor_data['path']}

        NETWORK DATA:
        - IP Address: {visitor_data['ip']}
        - ISP: {visitor_data['geodata'].get('isp', 'N/A')}
        - AS: {visitor_data['geodata'].get('as', 'N/A')}
        - Proxy: {visitor_data['geodata'].get('proxy', False)}

        LOCATION:
        - Country: {visitor_data['geodata'].get('country', 'N/A')}
        - Region: {visitor_data['geodata'].get('regionName', 'N/A')}
        - City: {visitor_data['geodata'].get('city', 'N/A')}
        - ZIP: {visitor_data['geodata'].get('zip', 'N/A')}
        - Coordinates: {visitor_data['geodata'].get('lat', 'N/A')}, {visitor_data['geodata'].get('lon', 'N/A')}

        DEVICE INFO:
        - Browser: {visitor_data['device']['browser']}
        - OS: {visitor_data['device']['os']}
        - Device: {visitor_data['device']['device']}
        - Mobile: {visitor_data['device']['is_mobile']}
        - Languages: {visitor_data['device']['languages']}

        TECHNICAL DETAILS:
        - Referrer: {visitor_data.get('referrer', 'Direct')}
        - User Agent: {visitor_data['raw_ua']}
        - Headers: {json.dumps(visitor_data['headers'], indent=2)}
        """

        msg.attach(MIMEText(body, 'plain'))
        
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"Visitor's Email sent to: {str(EMAIL_ADDRESS)}")
    except Exception as e:
        print(f"Email sending failed: {str(e)}")


@app.before_request
def track_visitor():
    """Enhanced visitor tracking with detailed device and location info"""
    if request.path.startswith('/static'):
        return None  # Allow static files through

    # Get or create visitor ID
    visitor_id = request.cookies.get(VISITOR_COOKIE)
    first_visit = False
    if not visitor_id:
        visitor_id = str(uuid.uuid4())
        first_visit = True

    # Get visitor IP (handling proxies)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    # Get detailed geolocation
    geodata = get_geolocation(ip)

    # Enhanced device fingerprint
    device_data = get_device_fingerprint(request)

    # Prepare visitor data with all details
    visitor_data = {
        'visitor_id': visitor_id,
        'ip': ip,
        'timestamp': datetime.now().isoformat(),
        'first_visit': first_visit,
        'path': request.path,
        'referrer': request.headers.get('Referer'),
        'raw_ua': request.headers.get('User-Agent'),
        'headers': dict(request.headers),
        'geodata': geodata,
        'device': device_data,
        'query_params': dict(request.args)
    }

    # Store all details in database
    log_visitor(visitor_data)

    # Check if we should send notification (first visit today)
    last_visit = request.cookies.get(TRACKING_COOKIE)
    should_notify = not last_visit or last_visit != datetime.now().strftime('%Y-%m-%d')

    if should_notify:
        send_visitor_email(visitor_data)

    # Don't return anything (equivalent to return None)
    # Flask will continue with the normal request processing

def send_application_notification(job_title, application_data):
    """Send email notification about new job application"""
    try:
        # Create message
        msg = MIMEMultipart()
        msg['From'] = 'devfemijethro@gmail.com'
        msg['To'] = '007femijethro@gmail.com'
        msg['Cc'] = 'Chase.rice.fanpage223@gmail.com'
        msg['Cc'] = 'eoni56699@gmail.com'
        msg['Subject'] = f"New Application for {job_title}"

        # Email body
        body = f"""
        New job application received:

        Position: {job_title}
        Applicant: {application_data['full_name']}
        Email: {application_data['email']}
        Phone: {application_data['country_code']} {application_data['phone_number']}
        LinkedIn: {application_data['linkedin_url']}
        Education: {application_data['education']}
        Work Experience: {application_data['work_experience']}
        """

        msg.attach(MIMEText(body, 'plain'))

        # Connect to SMTP server and send email
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"Application Email sent to: {str(EMAIL_ADDRESS)}")

    except Exception as e:
        print(f"Failed to send email: {e}")


@app.route("/")
def home():
    jobs = get_jobs()
    return render_template('home.html', jobs=jobs)


@app.route("/job/<int:id>")
def show_job(id):
    job = get_job(id)
    if not job:
        return "Job not found", 404
    return render_template('jobpage.html', job=job)


@app.route("/iloveyou")
def iloveyou():
    return render_template('iloveyou.html')


@app.route("/job/<int:id>/apply", methods=['POST'])
def apply_to_job(id):
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
        'resume_path': request.form.get('resume_path')
    }

    try:
        # Insert the application into the database
        add_application_to_db(job['title'], data)

        # Send email notification
        send_application_notification(job['title'], data)

        return render_template('applicationsubmited.html',
                               application=data,
                               job=job)
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
