# box_client.py

import hashlib
from io import BytesIO
from typing import Optional, Dict, Any

from boxsdk import Client
from boxsdk.exception import BoxAPIException
from werkzeug.datastructures import FileStorage


class BoxUploader:
    """
    Box へのファイルアップロード処理をまとめたクラス（Flask用）

    - Flask の request.files['file']（FileStorage）を受け取る
    - デフォルトではルートフォルダ（"0"）にアップロード
    - 同名ファイルがあれば新バージョンとして更新
    - 同時にファイル内容の SHA-256 ハッシュも計算して返す
    """

    def __init__(self, client: Client, default_folder_id: str = "0") -> None:
        self._client = client
        self._default_folder_id = default_folder_id

    def upload_file(
        self,
        file_storage: FileStorage,
        folder_id: Optional[str] = None,
    ):
        """
        Flask の FileStorage を受け取って Box にアップロードし、
        (uploaded_file, conflict_info, file_hash) を返す。

        conflict_info:
          - None              … 新規アップロード
          - dict(conflicts..) … 同名ファイルがすでにあり、新バージョンとして保存した場合

        file_hash:
          - アップロードしたファイル内容の SHA-256 ハッシュ（16進文字列）
        """
        target_folder_id = folder_id or self._default_folder_id

        # 中身を一度メモリに載せておく（409時の再アップロード＆ハッシュ計算に使う）
        content = file_storage.read()
        file_hash = hashlib.sha256(content).hexdigest()
        stream = BytesIO(content)

        folder = self._client.folder(target_folder_id)
        conflict_info: Optional[Dict[str, Any]] = None

        try:
            # 新規アップロードを試す
            uploaded_file = folder.upload_stream(stream, file_storage.filename)
        except BoxAPIException as e:
            # 同名ファイルが存在する場合
            if e.status == 409 and e.code == "item_name_in_use":
                conflict_info = e.context_info.get("conflicts")
                existing_file_id = conflict_info["id"]

                # ストリームを先頭に戻してから、新バージョンとしてアップロード
                stream.seek(0)
                uploaded_file = self._client.file(existing_file_id).update_contents_with_stream(stream)
            else:
                # それ以外は一旦そのまま投げる
                raise

        return uploaded_file, conflict_info, file_hash
