# box_client.py
import hashlib
from pathlib import Path
from typing import Optional

from box_sdk_gen import Client
from models import FileMetadata


class BoxUploader:
    def __init__(self, client: Client, parent_folder_id: str = "0"):
        """
        :param client: 認証済みの boxsdk.Client インスタンス
        :param parent_folder_id: アップロード先フォルダ（デフォルトはルート "0"）
        """
        self._client = client
        self._parent_folder_id = parent_folder_id

    def _calc_sha256(self, path: Path) -> str:
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def upload_file(self, local_path: str) -> FileMetadata:
        """
        ローカルファイルを Box にアップロードし、FileMetadata を返す。
        """
        path = Path(local_path)
        if not path.is_file():
            raise FileNotFoundError(f"File not found: {local_path}")

        file_hash = self._calc_sha256(path)

        folder = self._client.folder(self._parent_folder_id)
        uploaded = folder.upload(str(path), file_name=path.name)

        # 共有リンク作成（読み取り専用）
        uploaded = uploaded.update_info({
            "shared_link": {
                "access": "open",  # 必要に応じて company / collaborators に変更
            }
        })

        shared_link = uploaded.shared_link["url"] if uploaded.shared_link else ""

        return FileMetadata(
            local_path=str(path),
            box_file_id=uploaded.id,
            box_file_name=uploaded.name,
            box_file_url=shared_link,
            file_hash=file_hash,
        )
