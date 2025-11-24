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
        meta = self._box_uploader.upload_file(local_path)

        # 2. Ethereumに保存
        tx_hash = self._eth_client.register_file(meta)

        return meta, tx_hash
