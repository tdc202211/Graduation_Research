from flask import Flask, redirect, request, session, url_for
from boxsdk import OAuth2, Client
from dotenv import load_dotenv
import os
from urllib.parse import urlencode

load_dotenv()

app = Flask(__name__)
app.secret_key = "change-this-to-some-random-long-string"

BOX_CLIENT_ID = os.getenv("BOX_CLIENT_ID")
BOX_CLIENT_SECRET = os.getenv("BOX_CLIENT_SECRET")
BOX_REDIRECT_URI = os.getenv("BOX_REDIRECT_URI")


def store_tokens(access_token, refresh_token):
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token


@app.route("/")
def index():
    return '<a href="/login">Login with Box</a>'


@app.route("/login")
def login():
    params = {
        "response_type": "code",
        "client_id": BOX_CLIENT_ID,
        "redirect_uri": BOX_REDIRECT_URI,
    }
    auth_url = "https://account.box.com/api/oauth2/authorize?" + urlencode(params)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    code = request.args.get("code")
    if not code:
        return "No code returned from Box", 400

    oauth = OAuth2(
        client_id=BOX_CLIENT_ID,
        client_secret=BOX_CLIENT_SECRET,
        store_tokens=store_tokens,
    )

    oauth.authenticate(code)

    return redirect(url_for("me"))


@app.route("/me")
def me():
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")

    if not access_token:
        return redirect(url_for("login"))

    oauth = OAuth2(
        client_id=BOX_CLIENT_ID,
        client_secret=BOX_CLIENT_SECRET,
        access_token=access_token,
        refresh_token=refresh_token,
        store_tokens=store_tokens,
    )

    client = Client(oauth)
    user = client.user().get()
    return f"Hello, {user.name} ({user.login})"


if __name__ == "__main__":
    app.run(debug=True)
