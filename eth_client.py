# eth_client.py

class EthereumClient:
    """
    Ethereum への書き込み処理をまとめるクラス。

    今はまだ「ダミー実装」で、実際のブロックチェーンには送らず、
    コンソールにログを出してダミーのトランザクションハッシュを返す。

    後で web3.py を使って本物のトランザクション送信に差し替える。
    """

    def __init__(self) -> None:
        # 将来ここで RPC URL や コントラクトアドレスを読み込む予定
        pass

    def store_file_record(self, file_hash: str, box_file_id: str, box_file_name: str) -> str:
        """
        ファイルのハッシュ値と Box の情報を「ブロックチェーンに送ったつもり」で処理する。

        :return: ダミーのトランザクションハッシュ文字列
        """
        print("[EthereumClient] store_file_record called")
        print(f"  file_hash   = {file_hash}")
        print(f"  box_file_id = {box_file_id}")
        print(f"  box_file_name = {box_file_name}")

        # 本物実装では実際の tx_hash を返す
        dummy_tx_hash = "0xDUMMY_TX_HASH"
        return dummy_tx_hash
