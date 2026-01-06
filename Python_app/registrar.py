# registrar.py
from box_client import BoxUploader
from eth_client import EthereumClient
from models import FileMetadata


class FileRegistrar:
    """
    1. Boxにファイルをアップロード
    2. その情報をEthereumに記録

    という “ユースケース” を表現するクラス。
    """

    def __init__(self, box_uploader: BoxUploader, eth_client: EthereumClient):
        self._box_uploader = box_uploader
        self._eth_client = eth_client

    def register(self, local_path: str) -> tuple[FileMetadata, str]:
        """
        :return: (FileMetadata, tx_hash)
        """
        # 1. Boxにアップロード
        uploaded_file, _conflict_info, file_hash = self._box_uploader.upload_file(local_path)
        shared_link = getattr(uploaded_file, "shared_link", None)
        file_url = ""
        if isinstance(shared_link, dict):
            file_url = str(shared_link.get("url") or "")

        meta = FileMetadata(
            local_path=local_path,
            box_file_id=str(uploaded_file.id),
            box_file_name=uploaded_file.name,
            box_file_url=file_url,
            file_hash=file_hash,
        )

        # 2. Ethereumに保存
        tx_hash = self._eth_client.store_file_record(
            file_hash=meta.file_hash,
            box_file_id=meta.box_file_id,
            box_file_name=meta.box_file_name,
        )

        return meta, tx_hash
