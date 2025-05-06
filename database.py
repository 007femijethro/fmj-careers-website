from sqlalchemy import create_engine, text
import os
import json
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database configuration
SUPABASE_URL = os.getenv('SUPABASE_URL')
engine = create_engine(SUPABASE_URL, connect_args={"sslmode": "require"})

def get_jobs():
    """Fetch all jobs from the database."""
    with engine.connect() as conn:
        result = conn.execute(text('SELECT * FROM "fmjjobs"'))
        jobs = [dict(row) for row in result.mappings()]
    return jobs

def get_job(id):
    """Fetch a specific job by ID."""
    with engine.connect() as conn:
        result = conn.execute(text('SELECT * FROM "fmjjobs" WHERE id = :val'), {'val': id})
        row = result.mappings().first()
    return dict(row) if row else None

def add_application_to_db(job_title, data):
    """Insert job application into the database."""
    with engine.connect() as conn:
        query = text('''
            INSERT INTO applications (
                job_title, full_name, email, country_code, phone_number, 
                linkedin_url, education, work_experience, resume_url
            ) VALUES (
                :job_title, :full_name, :email, :country_code, :phone_number, 
                :linkedin_url, :education, :work_experience, :resume_url
            )
        ''')
        conn.execute(query, {
            'job_title': job_title,
            'full_name': data['full_name'],
            'email': data['email'],
            'country_code': data['country_code'],
            'phone_number': data['phone_number'],
            'linkedin_url': data['linkedin_url'],
            'education': data['education'],
            'work_experience': data['work_experience'],
            'resume_url': data['resume_path']
        })
        conn.commit()

def log_visitor(visitor_data):
    """Store visitor information in the database with location and device details"""
    with engine.connect() as conn:
        try:
            # Updated query to match typical visitor tracking schema
            conn.execute(
                text('''
                INSERT INTO visitors (
                    visitor_id, 
                    ip, 
                    visit_timestamp, 
                    page_path, 
                    referrer_url,
                    user_agent,
                    browser,
                    operating_system,
                    device_type,
                    country,
                    region,
                    city,
                    isp,
                    is_mobile,
                    is_bot,
                    additional_data
                ) VALUES (
                    :visitor_id, 
                    :ip, 
                    :visit_timestamp, 
                    :page_path, 
                    :referrer_url,
                    :user_agent,
                    :browser,
                    :operating_system,
                    :device_type,
                    :country,
                    :region,
                    :city,
                    :isp,
                    :is_mobile,
                    :is_bot,
                    :additional_data
                )
                '''),
                {
                    'visitor_id': visitor_data['visitor_id'],
                    'ip': visitor_data['ip'],
                    'visit_timestamp': visitor_data['timestamp'],
                    'page_path': visitor_data['path'],
                    'referrer_url': visitor_data['referrer'],
                    'user_agent': visitor_data['raw_ua'],
                    'browser': visitor_data['device']['browser'],
                    'operating_system': visitor_data['device']['os'],
                    'device_type': visitor_data['device']['device'],
                    'country': visitor_data['geodata'].get('country'),
                    'region': visitor_data['geodata'].get('regionName'),
                    'city': visitor_data['geodata'].get('city'),
                    'isp': visitor_data['geodata'].get('isp'),
                    'is_mobile': visitor_data['device']['is_mobile'],
                    'is_bot': visitor_data['device']['is_bot'],
                    'additional_data': json.dumps(visitor_data)
                }
            )
            conn.commit()
        except Exception as e:
            print(f"Error logging visitor: {e}")
            # Consider adding proper error logging here