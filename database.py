from sqlalchemy import create_engine, text
import os

# Corrected connection string format
db_connection_string = os.environ['DB_KEY']

engine = create_engine(
    db_connection_string,
    connect_args={
        "sslmode": "require",  # Ensures SSL is used
        "sslrootcert": "/etc/ssl/cert.pem"  # Path to the SSL certificate
    }
)

def get_jobs():
    with engine.connect() as conn:
        result = conn.execute(text('SELECT * FROM "fmjJobs"'))

        list_of_jobs = []

        for row in result.mappings():
            row_dict = dict(row)  
            list_of_jobs.append(row_dict) 
    return list_of_jobs

def get_job(id):
    with engine.connect() as conn:
        result = conn.execute(text('SELECT * FROM "fmjJobs" WHERE id = :val'), {'val': id})

        row = result.mappings().first()  
    if row is None:
        return None
    else:
        return dict(row) 
  

def add_application_to_db(job_id, data):
    with engine.connect() as conn:
        # Begin a transaction
        with conn.begin():
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
