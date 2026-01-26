from flask import Flask, redirect, request, session, url_for, render_template, jsonify
import logging
from boxsdk import OAuth2, Client
from dotenv import load_dotenv
import os
import json
import secrets
import threading
import time
from datetime import datetime, timezone, timedelta
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode

from box_client import BoxUploader
from box_records import fetch_box_files
from eth_client import EthereumClient

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(dotenv_path=BASE_DIR / ".env")

app = Flask(__name__)
logging.getLogger("boxsdk").setLevel(logging.ERROR)
logging.getLogger("boxsdk.network").setLevel(logging.ERROR)
logging.getLogger("boxsdk.network.default_network").setLevel(logging.ERROR)
logging.getLogger("urllib3").setLevel(logging.ERROR)
_flask_secret = os.getenv("FLASK_SECRET_KEY")
if not _flask_secret:
    raise RuntimeError("FLASK_SECRET_KEY is not set")
app.secret_key = _flask_secret

BOX_CLIENT_ID = os.getenv("BOX_CLIENT_ID")
BOX_CLIENT_SECRET = os.getenv("BOX_CLIENT_SECRET")
BOX_REDIRECT_URI = os.getenv("BOX_REDIRECT_URI")
BOX_LIST_FOLDER_ID = os.getenv("BOX_LIST_FOLDER_ID", "0")


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv("FLASK_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=_env_flag(
        "FLASK_SECURE_COOKIE", (BOX_REDIRECT_URI or "").startswith("https://")
    ),
)

TOKEN_STORE: dict[str, dict[str, str]] = {}
TOKEN_STORE_LOCK = threading.Lock()
OAUTH_STATE_TTL = int(os.getenv("OAUTH_STATE_TTL_SECONDS", "600"))
TOKEN_STORE_DIR = BASE_DIR / "token_store"
LAST_TOKEN_FILE = TOKEN_STORE_DIR / "last_token.json"


def _get_token_key() -> str:
    token_key = session.get("token_key")
    if not token_key:
        token_key = secrets.token_urlsafe(32)
        session["token_key"] = token_key
    return token_key


def _token_persist_enabled() -> bool:
    return _env_flag("PERSIST_BOX_TOKENS", True)


def _auto_login_from_saved_token() -> bool:
    return _env_flag("AUTO_LOGIN_FROM_SAVED_TOKEN", False)


def _token_path(token_key: str) -> Path:
    return TOKEN_STORE_DIR / f"{token_key}.json"


def _load_tokens_from_disk(token_key: str) -> dict[str, str] | None:
    if not _token_persist_enabled():
        return None
    path = _token_path(token_key)
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("access_token"):
            return data
    except Exception:
        return None
    return None


def _save_tokens_to_disk(token_key: str, data: dict[str, str]) -> None:
    if not _token_persist_enabled():
        return
    TOKEN_STORE_DIR.mkdir(parents=True, exist_ok=True)
    path = _token_path(token_key)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=True, indent=2)


def _save_last_token_key(token_key: str) -> None:
    if not _token_persist_enabled():
        return
    TOKEN_STORE_DIR.mkdir(parents=True, exist_ok=True)
    with LAST_TOKEN_FILE.open("w", encoding="utf-8") as f:
        json.dump({"token_key": token_key}, f, ensure_ascii=True, indent=2)


def _load_last_token_key() -> str | None:
    if not (_token_persist_enabled() and _auto_login_from_saved_token()):
        return None
    if not LAST_TOKEN_FILE.exists():
        return None
    try:
        with LAST_TOKEN_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        token_key = data.get("token_key") if isinstance(data, dict) else None
        if isinstance(token_key, str) and token_key:
            return token_key
    except Exception:
        return None
    return None


def _clear_last_token_key_if_match(token_key: str) -> None:
    if not _token_persist_enabled():
        return
    if not LAST_TOKEN_FILE.exists():
        return
    try:
        with LAST_TOKEN_FILE.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict) and data.get("token_key") == token_key:
            LAST_TOKEN_FILE.unlink()
    except Exception:
        return


def store_tokens(access_token, refresh_token):
    token_key = _get_token_key()
    with TOKEN_STORE_LOCK:
        tokens = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "updated_at": int(time.time()),
        }
        TOKEN_STORE[token_key] = tokens
    _save_tokens_to_disk(token_key, tokens)
    _save_last_token_key(token_key)


def _get_tokens():
    token_key = session.get("token_key")
    if not token_key:
        token_key = _load_last_token_key()
        if token_key:
            session["token_key"] = token_key
        else:
            return None
    with TOKEN_STORE_LOCK:
        cached = TOKEN_STORE.get(token_key)
    if cached:
        return cached
    tokens = _load_tokens_from_disk(token_key)
    if tokens:
        with TOKEN_STORE_LOCK:
            TOKEN_STORE[token_key] = tokens
    return tokens


def _new_oauth_state() -> str:
    return secrets.token_urlsafe(32)


def _validate_oauth_state(provided: str | None) -> bool:
    expected = session.get("oauth_state")
    issued_at = session.get("oauth_state_ts")
    session.pop("oauth_state", None)
    session.pop("oauth_state_ts", None)
    if not expected or not provided:
        return False
    if issued_at is None:
        return False
    if time.time() - int(issued_at) > OAUTH_STATE_TTL:
        return False
    return secrets.compare_digest(provided, expected)


def _preview_enabled() -> bool:
    return _env_flag("ENABLE_TX_PREVIEW", False)


def _get_payload_path() -> Path | None:
    raw = session.get("payload_path")
    if not raw:
        latest = Path(__file__).resolve().parent / "payloads" / "latest.json"
        return latest if latest.exists() else None
    path = Path(raw)
    if path.exists():
        return path
    latest = Path(__file__).resolve().parent / "payloads" / "latest.json"
    return latest if latest.exists() else None


def build_client():
    tokens = _get_tokens()
    if not tokens:
        return None
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
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
    logged_in = _get_tokens() is not None
    return render_template("index.html", logged_in=logged_in)


@app.route("/login")
def login():
    ensure_env()
    state = _new_oauth_state()
    session["oauth_state"] = state
    session["oauth_state_ts"] = int(time.time())
    params = {
        "response_type": "code",
        "client_id": BOX_CLIENT_ID,
        "redirect_uri": BOX_REDIRECT_URI,
        "state": state,
    }
    auth_url = "https://account.box.com/api/oauth2/authorize?" + urlencode(params)
    return redirect(auth_url)


@app.route("/callback")
def callback():
    ensure_env()
    error = request.args.get("error")
    if error:
        return f"Box auth error: {error}", 400
    state = request.args.get("state")
    if not _validate_oauth_state(state):
        return "Invalid OAuth state", 400
    code = request.args.get("code")
    if not code:
        return "No code returned from Box", 400

    oauth = OAuth2(
        client_id=BOX_CLIENT_ID,
        client_secret=BOX_CLIENT_SECRET,
        store_tokens=store_tokens,
    )

    access_token, refresh_token = oauth.authenticate(code)
    if access_token:
        store_tokens(access_token, refresh_token)
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
    token_key = _get_token_key()

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
    session_payload_path = payload_dir / f"{token_key}.json"

    save_errors = []
    session_payload_error = None
    try:
        with latest_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as ex:
        save_errors.append(f"latest.json: {type(ex).__name__}: {ex}")
    try:
        with session_payload_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception as ex:
        session_payload_error = f"{type(ex).__name__}: {ex}"
        save_errors.append(f"{session_payload_path.name}: {session_payload_error}")

    save_error = "; ".join(save_errors) if save_errors else None
    if session_payload_error is None:
        session["payload_path"] = str(session_payload_path)
    else:
        session.pop("payload_path", None)

    session["last_upload_payload"] = payload
    payload_path_for_scripts = (
        session_payload_path if session_payload_error is None else latest_path
    )

    encode_data = None
    encode_error = None
    try:
        script_path = Path(__file__).resolve().parent / "encode_latest_payload.py"
        result = subprocess.run(
            [sys.executable, str(script_path), str(payload_path_for_scripts)],
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
                str(payload_path_for_scripts),
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
        saved_path=str(payload_path_for_scripts),
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

    box_files = []
    box_error = None
    client = build_client()
    if client is None:
        box_error = "Boxにログインしてください。"
    else:
        try:
            box_files = fetch_box_files(client, BOX_LIST_FOLDER_ID)
        except Exception as ex:
            box_error = f"{type(ex).__name__}: {ex}"

    contract_address = os.getenv("ETH_CONTRACT_ADDRESS")
    return render_template(
        "records.html",
        records=history,
        chain_error=chain_error,
        contract_address=contract_address,
        box_files=box_files,
        box_error=box_error,
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


@app.route("/box/delete/<file_id>", methods=["POST"])
def box_delete(file_id):
    client = build_client()
    if client is None:
        return redirect(url_for("login"))
    try:
        client.file(str(file_id)).delete()
    except Exception:
        pass
    return redirect(url_for("records"))


@app.route("/payload/latest")
def latest_payload():
    payload = session.get("last_upload_payload")
    if not payload:
        return jsonify({"error": "no payload"}), 404
    return jsonify(payload)


@app.route("/preview/presign")
def preview_presign():
    if not _preview_enabled():
        return "preview disabled", 404, {"Content-Type": "text/plain; charset=utf-8"}
    payload_path = _get_payload_path()
    if payload_path is None:
        return "no payload", 404, {"Content-Type": "text/plain; charset=utf-8"}
    script_path = Path(__file__).resolve().parent / "tx_preview_presign.py"
    try:
        result = subprocess.run(
            [sys.executable, str(script_path), str(payload_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout, 200, {"Content-Type": "text/plain; charset=utf-8"}
    except Exception as ex:
        return f"{type(ex).__name__}: {ex}", 500, {"Content-Type": "text/plain; charset=utf-8"}


@app.route("/preview/signed")
def preview_signed():
    if not _preview_enabled():
        return "preview disabled", 404, {"Content-Type": "text/plain; charset=utf-8"}
    payload_path = _get_payload_path()
    if payload_path is None:
        return "no payload", 404, {"Content-Type": "text/plain; charset=utf-8"}
    presign_script = Path(__file__).resolve().parent / "tx_preview_presign.py"
    sign_script = Path(__file__).resolve().parent / "tx_preview_signed.py"
    try:
        presign = subprocess.run(
            [sys.executable, str(presign_script), str(payload_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        result = subprocess.run(
            [sys.executable, str(sign_script), str(payload_path), "--from-presign", "-"],
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
    payload_path = session.get("payload_path")
    token_key = session.get("token_key")
    session.clear()
    if token_key:
        with TOKEN_STORE_LOCK:
            TOKEN_STORE.pop(token_key, None)
        if _token_persist_enabled():
            token_path = _token_path(token_key)
            if token_path.exists():
                try:
                    token_path.unlink()
                except OSError:
                    pass
            _clear_last_token_key_if_match(token_key)
    if payload_path:
        try:
            Path(payload_path).unlink()
        except OSError:
            pass
    return redirect(url_for("index"))


if __name__ == "__main__":
    debug = _env_flag("FLASK_DEBUG", True)
    host = os.getenv("FLASK_HOST", "localhost")
    app.run(debug=debug, host=host, use_reloader=debug)
