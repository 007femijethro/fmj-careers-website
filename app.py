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
        """msg['Cc'] = 'eoni56699@gmail.com'"""
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

    # Get visitor IP (handling proxies)
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ',' in ip:
        ip = ip.split(',')[0].strip()

    # Get detailed geolocation
    geodata = get_geolocation(ip)

    # Check country access
    allowed_countries = ['United States', 'Nigeria']
    country = geodata.get('country', 'Unknown')

    if country not in allowed_countries:
        return render_template('access_denied.html'), 403

    # Get or create visitor ID
    visitor_id = request.cookies.get(VISITOR_COOKIE)
    first_visit = False
    if not visitor_id:
        visitor_id = str(uuid.uuid4())
        first_visit = True

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
        msg['From'] = 'support@fmjcareers.com'
        msg['To'] = '007femijethro@gmail.com'
        msg['Cc'] = ', '.join(['Chase.rice.fanpage223@gmail.com', 'eoni56699@gmail.com'])
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

def send_applicant_confirmation_email(application_data, job_title):
    """Send a confirmation email to the applicant"""
    try:
        msg = MIMEMultipart()
        msg['From'] = 'support@fmjcareers.com'
        msg['To'] = application_data['email']
        msg['Subject'] = f"Your Application for {job_title} has been received"

        # Verify application_data is a dictionary
        if not isinstance(application_data, dict):
            raise ValueError("application_data must be a dictionary")

        # Verify required fields exist
        if 'email' not in application_data or 'full_name' not in application_data:
            raise ValueError("application_data is missing required fields (email or full_name)")

        applicant_email = application_data['email']
        applicant_name = application_data['full_name']
        
        body = f"""
        <html>
          <body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6; background-color: #ffe6f0; padding: 20px;">
            <div style="max-width: 600px; margin: auto; background-color: #fff0f6; border: 1px solid #f7c6d3; padding: 30px; border-radius: 12px; box-shadow: 0 4px 10px rgba(255, 182, 193, 0.3);">
              <img src="https://fmjcareers.com/static/logo.jpg" alt="FMJ Capitals Logo" style="width: 150px; margin-bottom: 30px; display: block; margin-left: auto; margin-right: auto;">

              <p style="font-size: 18px;">Hi <strong style="color: #d6336c;">{applicant_name}</strong>,</p>

              <p style="font-size: 16px; color: #6a1b4d;">Thank you for applying for the <strong style="color: #d6336c;">{job_title}</strong> position with us!</p>

              <p style="font-size: 16px;">We’ve received your information and are currently reviewing applications. To move forward and schedule your interview, please follow the steps below:</p>

              <h3 style="color: #d6336c; border-bottom: 2px solid #f28ab2; padding-bottom: 8px;">✅ Next Steps – Required for Interview Scheduling:</h3>
              <ol style="color: #6a1b4d; font-size: 15px;">
                <li style="margin-bottom: 15px;">
                  <strong>Download the Signal Messenger App (Free & Secure):</strong><br>
                  Signal is our secure communication platform for interviews. Please download it here:<br>
                  📱 <a href="https://play.google.com/store/apps/details?id=org.thoughtcrime.securesms" style="color: #d6336c; text-decoration: none;">Signal for Android</a><br>
                  📱 <a href="https://apps.apple.com/app/signal-private-messenger/id874139669" style="color: #d6336c; text-decoration: none;">Signal for iPhone</a><br>
                  💻 <a href="https://signal.org/download/" style="color: #d6336c; text-decoration: none;">Signal for Desktop (optional)</a>
                </li>
                <li style="margin-bottom: 15px;">
                  <strong>Once Installed, Message Our Hiring Manager:</strong><br>
                  📲 Message: <em>Your Hiring Manager’s Name or Title</em><br>
                  📞 Signal Number: <em>2394939137</em><br>
                  📝 Message Template:<br><br>
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
                 <a href="mailto:support@fmjcareers.com" style="color: #d6336c; text-decoration: none;">support@fmjcareers.com</a></p>
            </div>
          </body>
        </html>
        """



        msg.attach(MIMEText(body, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            server.send_message(msg)
            print(f"Confirmation email sent to applicant: {applicant_email}")

    except KeyError as e:
        print(f"Failed to send confirmation email: Missing required field in application data - {e}")
    except ValueError as e:
        print(f"Failed to send confirmation email: {e}")
    except Exception as e:
            print(f"Failed to send confirmation email to applicant: {str(e)}")



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

        # Send confirmation email to applicant
        send_applicant_confirmation_email(data, job['title'])

        return render_template('applicationsubmited.html',
                               application=data,
                               job=job)
    except Exception as e:
        return f"An error occurred: {str(e)}", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
