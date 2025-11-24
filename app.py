from eth_client import EthereumClient
from box_client import BoxUploader
from flask import Flask, redirect, request, session, url_for, render_template
from boxsdk import OAuth2, Client
from dotenv import load_dotenv
import os
from urllib.parse import urlencode
from boxsdk.exception import BoxAPIException
from io import BytesIO


load_dotenv()

app = Flask(__name__)
app.secret_key = "change-this-to-some-random-long-string"

BOX_CLIENT_ID = os.getenv("BOX_CLIENT_ID")
BOX_CLIENT_SECRET = os.getenv("BOX_CLIENT_SECRET")
BOX_REDIRECT_URI = os.getenv("BOX_REDIRECT_URI")

eth_client = EthereumClient()

def store_tokens(access_token, refresh_token):
    session["access_token"] = access_token
    session["refresh_token"] = refresh_token


def build_client():
    access_token = session.get("access_token")
    refresh_token = session.get("refresh_token")
    if not access_token:
        return None

    oauth = OAuth2(
        client_id=BOX_CLIENT_ID,
        client_secret=BOX_CLIENT_SECRET,
        access_token=access_token,
        refresh_token=refresh_token,
        store_tokens=store_tokens,
    )
    return Client(oauth)


@app.route("/")
def index():
    logged_in = "access_token" in session
    return render_template("index.html", logged_in=logged_in)


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
    client = build_client()
    if client is None:
        return redirect(url_for("login"))

    user = client.user().get()
    return render_template("me.html", user=user)


from boxsdk.exception import BoxAPIException
from io import BytesIO

@app.route("/upload", methods=["GET", "POST"])
def upload():
    client = build_client()
    if client is None:
        return redirect(url_for("login"))

    uploader = BoxUploader(client)

    if request.method == "GET":
        return render_template("upload.html")

    file = request.files.get("file")
    if file is None or file.filename == "":
        return render_template("upload.html", error="ファイルが選択されていません。")

    uploaded_file, conflict_info, file_hash = uploader.upload_file(file)

    # ここで EthereumClient に即送信（設計A）
    tx_hash = eth_client.store_file_record(
        file_hash=file_hash,
        box_file_id=uploaded_file.id,
        box_file_name=uploaded_file.name,
    )

    return render_template(
        "upload_result.html",
        file_name=uploaded_file.name,
        file_id=uploaded_file.id,
        conflict=conflict_info,
        file_hash=file_hash,
        tx_hash=tx_hash,
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
