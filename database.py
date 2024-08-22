from sqlalchemy import create_engine, text

# Corrected connection string format
db_connection_string = "postgresql+psycopg2://postgres.gqolvrshzzhrarajqgjz:Omodara4wife$@aws-0-eu-west-2.pooler.supabase.com/postgres"

engine = create_engine(
    db_connection_string,
    connect_args={
        "sslmode": "require",  # Ensures SSL is used
        "sslrootcert": "/etc/ssl/cert.pem"  # Path to the SSL certificate
    }
)

# Connect to the database and execute a query
with engine.connect() as conn:
    result = conn.execute(text("SELECT * FROM \"fmjJobs\""))

    # Initialize an empty list to store dictionaries
    list_of_jobs = []

    # Convert each row to a dictionary and append it to the list
    for row in result.mappings():
        row_dict = dict(row)  # Convert row to a dictionary
        list_of_jobs.append(row_dict)  # Add dictionary to the list
