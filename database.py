from sqlalchemy import create_engine, text
import os
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
        list_of_jobs = [dict(row) for row in result.mappings()]
    return list_of_jobs

def get_job(id):
    """Fetch a specific job by ID and ensure correct data format."""
    with engine.connect() as conn:
       result = conn.execute(text('SELECT * FROM "fmjjobs" WHERE id = :val'), {'val': id})
       row = result.mappings().first()

    if row:
        job = dict(row)

        # Ensure '\n' is properly recognized and split into list items
        job['responsibilities'] = [resp.strip() for resp in job['responsibilities'].replace("\\n", "\n").split("\n") if resp.strip()]
        job['requirements'] = [req.strip() for req in job['requirements'].replace("\\n", "\n").split("\n") if req.strip()]

        return job
    return None



def add_application_to_db(job_id, data):
    """Insert job application into the database."""
    with engine.connect() as conn:
        with conn.begin():  # Start a transaction
            query = text('''
                INSERT INTO applications (
                    job_id, full_name, email, country_code, phone_number, linkedin_url, education, work_experience, resume_url
                ) VALUES (
                    :job_id, :full_name, :email, :country_code, :phone_number, :linkedin_url, :education, :work_experience, :resume_url
                )
            ''')
            conn.execute(query, {
                'job_id': job_id,
                'full_name': data['full_name'],
                'email': data['email'],
                'country_code': data['country_code'],
                'phone_number': data['phone_number'],
                'linkedin_url': data['linkedin_url'],
                'education': data['education'],
                'work_experience': data['work_experience'],
                'resume_url': data['resume_path']
            })
