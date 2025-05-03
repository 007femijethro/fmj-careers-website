from sqlalchemy import create_engine, text
import os
import json
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get database URL from .env file
SUPABASE_URL = os.getenv('SUPABASE_URL')

# Create database engine
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
                job_title, full_name, email, country_code, phone_number, linkedin_url, education, work_experience, resume_url
            ) VALUES (
                :job_title, :full_name, :email, :country_code, :phone_number, :linkedin_url, :education, :work_experience, :resume_url
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
        conn.commit()  # Commit the transaction


def log_visitor(visitor_data):
    """Store visitor analytics in database."""
    with engine.connect() as conn:
        query = text('''
            INSERT INTO visitors (
                visitor_id, ip, timestamp, first_visit, path, referrer,
                user_agent, headers, geodata, device_data, query_params
            ) VALUES (
                :visitor_id, :ip, :timestamp, :first_visit, :path, :referrer,
                :user_agent, :headers, :geodata, :device_data, :query_params
            )
        ''')
        conn.execute(query, {
            'visitor_id': visitor_data['visitor_id'],
            'ip': visitor_data['ip'],
            'timestamp': visitor_data['timestamp'],
            'first_visit': visitor_data['first_visit'],
            'path': visitor_data['path'],
            'referrer': visitor_data['referrer'],
            'user_agent': visitor_data['raw_ua'],
            'headers': json.dumps(visitor_data['headers']),
            'geodata': json.dumps(visitor_data['geodata']),
            'device_data': json.dumps(visitor_data['device']),
            'query_params': json.dumps(visitor_data['query_params'])
        })
        conn.commit()