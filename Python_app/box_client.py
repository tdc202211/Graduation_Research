import hashlib
from boxsdk.exception import BoxAPIException


class BoxUploader:
    def __init__(self, client, default_folder_id="0"):
        self._client = client
        self._default_folder_id = str(default_folder_id)

    @staticmethod
    def _sha256_bytes(data: bytes) -> str:
        h = hashlib.sha256()
        h.update(data)
        return h.hexdigest()

    def upload_file(self, file_storage):
        """
        Args:
            file_storage: Flaskの request.files["file"] の FileStorage

        Returns:
            (uploaded_file, conflict_info, file_hash)
            - uploaded_file: BoxのFileオブジェクト（id/nameが確実に取れるようget()済み）
            - conflict_info: 409時のconflict情報（なければNone）
            - file_hash: アップロード内容のSHA-256(hex)
        """
        filename = file_storage.filename

        # FileStorageはstreamを持つ。内容をbytesとして読み切ってhash計算し、
        # そのbytesでBoxへアップロードする（確実に同じ内容をhashとアップロードに使う）
        data = file_storage.read()
        file_hash = self._sha256_bytes(data)

        # BoxSDKはストリームが必要なので、bytesをmemoryview/bytesで渡せる stream を作る
        # ここはシンプルに bytes を使ってアップロード（boxsdkが内部で扱う）
        # ただし update_contents_with_stream は stream を要求するので io.BytesIO を使う
        import io
        stream = io.BytesIO(data)

        conflict_info = None

        try:
            # 新規アップロード
            uploaded = (
                self._client.folder(self._default_folder_id)
                .upload_stream(stream, filename)
            )
            # name等が薄いケースがあるので確実に取得
            uploaded_file = self._client.file(uploaded.id).get()
            return uploaded_file, conflict_info, file_hash

        except BoxAPIException as e:
            # 同名衝突 → 上書き（新バージョン）
            if e.status == 409 and getattr(e, "code", None) == "item_name_in_use":
                conflict_info = None

                # boxsdkの例外に含まれる conflict 情報を拾う
                ctx = getattr(e, "context_info", None)
                if isinstance(ctx, dict):
                    conflicts = ctx.get("conflicts")
                    if isinstance(conflicts, list) and conflicts:
                        conflict_info = conflicts[0]
                    elif isinstance(conflicts, dict):
                        conflict_info = conflicts

                if not conflict_info or "id" not in conflict_info:
                    # 409だけどIDが取れないのは想定外なので投げる
                    raise

                existing_file_id = conflict_info["id"]

                # 先頭に戻して新バージョンをアップロード
                stream.seek(0)
                self._client.file(existing_file_id).update_contents_with_stream(stream)

                # update系は戻り値が薄いことがあるので get() で確実に
                uploaded_file = self._client.file(existing_file_id).get()
                return uploaded_file, conflict_info, file_hash

            # それ以外は再raise
            raise
