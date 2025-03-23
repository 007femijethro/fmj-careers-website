from flask import Flask, render_template, request
from database import get_jobs, get_job, add_application_to_db

app = Flask(__name__)

@app.route("/")
def home():
    jobs = get_jobs()  # Fetch all jobs from the database
    return render_template('home.html', jobs=jobs)

@app.route("/job/<int:id>")
def show_job(id):
    job = get_job(id)  # Fetch the job by ID
    if not job:
        return "Job not found", 404
    return render_template('jobpage.html', job=job)

@app.route("/job/<int:id>/apply", methods=['POST'])
def apply_to_job(id):
    job = get_job(id)  # Fetch the job by ID
    if not job:
        return "Job not found", 404

    # Get form data
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
        return render_template('applicationsubmited.html', application=data, job=job)
    except Exception as e:
        return f"An error occurred: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)