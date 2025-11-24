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
    # ログイン済みかチェック
    client = build_client()
    if client is None:
        return redirect(url_for("login"))

    # GET: フォーム表示
    if request.method == "GET":
        return render_template("upload.html")

    # POST: ファイルアップロード処理
    file = request.files.get("file")
    if file is None or file.filename == "":
        return render_template("upload.html", error="ファイルが選択されていません。")

    # 409 でリトライできるように、一度メモリに読み込む
    content = file.read()
    stream = BytesIO(content)

    folder = client.folder("0")  # ルートフォルダ
    conflict_info = None

    try:
        # まずは普通に新規アップロードを試みる
        uploaded_file = folder.upload_stream(stream, file.filename)
    except BoxAPIException as e:
        # 同名ファイルがすでにある場合
        if e.status == 409 and e.code == "item_name_in_use":
            conflict_info = e.context_info.get("conflicts")
            existing_file_id = conflict_info["id"]

            # ストリームを先頭に戻してから「新しいバージョンとして更新」
            stream.seek(0)
            uploaded_file = client.file(existing_file_id).update_contents_with_stream(stream)
        else:
            # それ以外のエラーは一旦そのまま投げる
            raise

    return render_template(
        "upload_result.html",
        file_name=uploaded_file.name,
        file_id=uploaded_file.id,
        conflict=conflict_info,  # None → 新規 / あり → 既存の新バージョン
    )

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
