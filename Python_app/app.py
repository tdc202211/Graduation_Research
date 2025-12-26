from flask import Flask, redirect, request, session, url_for, render_template, jsonify
from boxsdk import OAuth2, Client
from dotenv import load_dotenv
import os
import json
from datetime import datetime, timezone, timedelta
import subprocess
import sys
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

    jst = timezone(timedelta(hours=9))
    payload = {
        "fileHash": file_hash,
        "fileId": str(uploaded_file.id),
        "fileName": uploaded_file.name,
        "uploadedAt": datetime.now(jst).isoformat(),
        "txHash": None,
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
        payload["txHash"] = tx_hash
    except Exception as ex:
        chain_error = f"{type(ex).__name__}: {ex}"

    # JSON保存
    payload_dir = Path(__file__).resolve().parent / "payloads"
    payload_dir.mkdir(parents=True, exist_ok=True)

    latest_path = payload_dir / "latest.json"

    save_error = None
    try:
        with latest_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as ex:
        save_error = f"{type(ex).__name__}: {ex}"

    session["last_upload_payload"] = payload

    encode_data = None
    encode_error = None
    try:
        script_path = Path(__file__).resolve().parent / "encode_latest_payload.py"
        result = subprocess.run(
            [sys.executable, str(script_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        encode_data = result.stdout.strip()
    except Exception as ex:
        encode_error = f"{type(ex).__name__}: {ex}"

    storage_view_data = None
    storage_view_error = None
    try:
        script_path = Path(__file__).resolve().parent / "view_storage_format.py"
        result = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "--file-id",
                payload["fileId"],
                "--offline",
                "--payload",
                str(latest_path),
                "--dump-slots",
                "4",
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        storage_view_data = result.stdout.strip()
    except Exception as ex:
        storage_view_error = f"{type(ex).__name__}: {ex}"

    return render_template(
        "upload_result.html",
        payload=payload,
        saved_path=str(latest_path),
        save_error=save_error,
        conflict=conflict_info,
        tx_hash=tx_hash,
        chain_error=chain_error,
        encode_data=encode_data,
        encode_error=encode_error,
        storage_view_data=storage_view_data,
        storage_view_error=storage_view_error,
    )


@app.route("/records")
def records():
    history = []
    chain_error = None
    try:
        eth = EthereumClient()
        history = eth.fetch_all_records()
    except Exception as ex:
        chain_error = f"{type(ex).__name__}: {ex}"

    contract_address = os.getenv("ETH_CONTRACT_ADDRESS")
    return render_template(
        "records.html",
        records=history,
        chain_error=chain_error,
        contract_address=contract_address,
    )


@app.route("/records/<file_id>")
def record_detail(file_id):
    chain_error = None
    record = None
    try:
        eth = EthereumClient()
        res = eth.get_latest(file_id)
        if res.get("exists"):
            record = {"fileId": file_id, **res}
    except Exception as ex:
        chain_error = f"{type(ex).__name__}: {ex}"

    contract_address = os.getenv("ETH_CONTRACT_ADDRESS")
    return render_template(
        "record_detail.html",
        record=record,
        file_id=file_id,
        chain_error=chain_error,
        contract_address=contract_address,
    )


@app.route("/payload/latest")
def latest_payload():
    payload = session.get("last_upload_payload")
    if not payload:
        return jsonify({"error": "no payload"}), 404
    return jsonify(payload)


@app.route("/preview/presign")
def preview_presign():
    latest_path = Path(__file__).resolve().parent / "payloads" / "latest.json"
    script_path = Path(__file__).resolve().parent / "tx_preview_presign.py"
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), str(latest_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as ex:
        return f"{type(ex).__name__}: {ex}", 500, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/preview/signed")
def preview_signed():
    latest_path = Path(__file__).resolve().parent / "payloads" / "latest.json"
    presign_script = Path(__file__).resolve().parent / "tx_preview_presign.py"
    sign_script = Path(__file__).resolve().parent / "tx_preview_signed.py"
    try:
        presign = subprocess.run(
            [sys.executable, str(presign_script), str(latest_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        result = subprocess.run(
            [sys.executable, str(sign_script), str(latest_path), "--from-presign", "-"],
            input=presign.stdout,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as ex:
        return f"{type(ex).__name__}: {ex}", 500, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
