from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from boxsdk import OAuth2, Client
from dotenv import load_dotenv
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

from box_client import BoxUploader
from eth_client import EthereumClient

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "change-this-to-some-random-long-string")

BOX_CLIENT_ID = os.getenv("BOX_CLIENT_ID")
BOX_CLIENT_SECRET = os.getenv("BOX_CLIENT_SECRET")
BOX_REDIRECT_URI = os.getenv("BOX_REDIRECT_URI")


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


def ensure_env():
    missing = []
    if not BOX_CLIENT_ID:
        missing.append("BOX_CLIENT_ID")
    if not BOX_CLIENT_SECRET:
        missing.append("BOX_CLIENT_SECRET")
    if not BOX_REDIRECT_URI:
        missing.append("BOX_REDIRECT_URI")
    if missing:
        raise RuntimeError(f"Missing env vars: {', '.join(missing)}")


@app.route("/")
def index():
    logged_in = "access_token" in session
    return render_template("index.html", logged_in=logged_in)


@app.route("/login")
def login():
    ensure_env()
    params = {
        "response_type": "code",
        "client_id": BOX_CLIENT_ID,
        "redirect_uri": BOX_REDIRECT_URI,
    }
    auth_url = "https://account.box.com/api/oauth2/authorize?" + urlencode(params)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    ensure_env()
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

    # Boxへアップロード（同名なら上書き＝新バージョン）
    uploaded_file, conflict_info, file_hash = uploader.upload_file(file)

    payload = {
        "fileHash": file_hash,
        "fileId": str(uploaded_file.id),
        "fileName": uploaded_file.name,
        "uploadedAt": datetime.now(timezone.utc).isoformat(),
    }
    
    tx_hash = None
    chain_error = None
    try:
        eth = EthereumClient()  # .env から ETH_RPC_URL / ETH_PRIVATE_KEY / ETH_CONTRACT_ADDRESS を読む
        tx_hash = eth.store_file_record(
            file_hash=payload["fileHash"],
            box_file_id=payload["fileId"],
            box_file_name=payload["fileName"],
        )
    except Exception as ex:
        chain_error = f"{type(ex).__name__}: {ex}"

    # JSON保存
    payload_dir = Path(__file__).resolve().parent / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    payload_path = payload_dir / f"{ts}_{payload['fileId']}.json"
    latest_path = payload_dir / "latest.json"

    save_error = None
    try:
        with payload_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        with latest_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as ex:
        save_error = f"{type(ex).__name__}: {ex}"

    session["last_upload_payload"] = payload

    return render_template(
        "upload_result.html",
        payload=payload,
        saved_path=str(payload_path),
        save_error=save_error,
        conflict=conflict_info,
        tx_hash=tx_hash,
        chain_error=chain_error,
    )


@app.route("/payload/latest")
def latest_payload():
    payload = session.get("last_upload_payload")
    if not payload:
        return jsonify({"error": "no payload"}), 404
    return jsonify(payload)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
