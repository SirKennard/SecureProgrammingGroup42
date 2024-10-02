from flask import Flask, render_template, url_for, redirect, request, session

app = Flask(__name__)
app.secret_key = 'session_key'


@app.route("/")
def home():
    return render_template("home.html")

if __name__ == "__main__":
    app.run(debug=True, threaded=True)