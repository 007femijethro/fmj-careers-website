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




