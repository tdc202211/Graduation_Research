# models.py
from dataclasses import dataclass

@dataclass
class FileMetadata:
    local_path: str
    box_file_id: str
    box_file_name: str
    box_file_url: str
    file_hash: str
