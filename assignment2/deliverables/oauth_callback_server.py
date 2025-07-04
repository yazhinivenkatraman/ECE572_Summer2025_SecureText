from flask import Flask, request

app = Flask(__name__)
auth_code = None

@app.route("/oauth/callback")
def oauth_callback():
    global auth_code
    auth_code = request.args.get("code")
    return "Authentication successful! You can close this tab."

def get_auth_code():
    global auth_code
    return auth_code