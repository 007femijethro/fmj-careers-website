from flask import Flask, render_template, jsonify
from database import list_of_jobs

app = Flask(__name__)


@app.route("/")
def hello_world():
    return render_template('home.html', jobs=list_of_jobs)


@app.route("/jobs")
def list_jobs():
    return jsonify(list_of_jobs)


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
