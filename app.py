from flask import Flask, render_template, jsonify, request
from database import get_jobs, get_job, add_application_to_db

app = Flask(__name__)

@app.route("/")
def home():
    jobs = get_jobs() 
    return render_template('home.html', jobs=jobs)

@app.route("/jobs")
def list_jobs():
    jobs = get_jobs()
    return jsonify(jobs)


@app.route("/job/<id>")
def show_job(id):
    job = get_job(id)  
    
    if not job:
       return "Not Found", 404
    return render_template('jobpage.html', job=job)

@app.route("/job/<id>/apply", methods= ['post'])
def apply_to_job(id):
    data = request.form
    job = get_job(id)
    add_application_to_db(id, data)
    return render_template('applicationsubmited.html', application=data, job=job)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
