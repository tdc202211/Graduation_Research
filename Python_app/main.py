# main.py
import os

from boxsdk import OAuth2, Client
from dotenv import load_dotenv

from box_client import BoxUploader
from eth_client import EthereumClient
from registrar import FileRegistrar

load_dotenv()

def create_box_client() -> Client:
    # ここでは Developer Token を想定した簡易例
    dev_token = os.getenv("BOX_DEVELOPER_TOKEN")
    if not dev_token:
        raise RuntimeError("BOX_DEVELOPER_TOKEN is not set")

    oauth = OAuth2(
        client_id=None,
        client_secret=None,
        access_token=dev_token,
    )
    return Client(oauth)


def main():
    box_client = create_box_client()
    box_uploader = BoxUploader(box_client, parent_folder_id="0")

    eth_client = EthereumClient(
        rpc_url=os.getenv("ETH_RPC_URL"),
        private_key=os.getenv("ETH_PRIVATE_KEY"),
        contract_address=os.getenv("ETH_CONTRACT_ADDRESS"),
        abi_path=os.getenv("ETH_CONTRACT_ABI_PATH"),
    )

    registrar = FileRegistrar(box_uploader, eth_client)

    # ここをお好みで：CLI引数やWebから受け取ってもOK
    target_path = "sample.txt"

    meta, tx_hash = registrar.register(target_path)

    print("=== Box ===")
    print("  File ID  :", meta.box_file_id)
    print("  Name     :", meta.box_file_name)
    print("  URL      :", meta.box_file_url)
    print("  Hash     :", meta.file_hash)
    print("=== Ethereum ===")
    print("  Tx Hash  :", tx_hash)


if __name__ == "__main__":
    main()
