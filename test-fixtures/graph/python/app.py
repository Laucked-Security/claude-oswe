from flask import Flask, request
from flask_login import login_required

from services.runner import Runner

app = Flask(__name__)
runner = Runner()


def cb():
    return "module-level cb"


def helper(cb):
    return cb()


@app.route('/run', methods=['POST'])
@login_required
def run_cmd():
    return runner.run(request.form['cmd'])


@app.route('/health')
def health():
    check = lambda: helper(cb)
    return check()
