from flask import Flask, render_template, jsonify
from database import get_jobs

app = Flask(__name__)

@app.route("/")
def home():
    jobs = get_jobs()  # Fetch fresh data for each request
    return render_template('home.html', jobs=jobs)

@app.route("/jobs")
def list_jobs():
    jobs = get_jobs()  # Fetch fresh data for each request
    return jsonify(jobs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
