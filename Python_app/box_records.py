def fetch_box_files(client, folder_id: str, limit: int = 200) -> list[dict]:
    items = client.folder(folder_id).get_items(
        limit=limit,
        fields=["id", "name", "modified_at", "created_at", "size", "type"],
    )
    files = []
    for item in items:
        if getattr(item, "type", "") != "file":
            continue
        files.append(
            {
                "fileId": str(getattr(item, "id", "")),
                "fileName": getattr(item, "name", "") or "-",
                "updatedAt": getattr(item, "modified_at", None)
                or getattr(item, "created_at", None),
                "createdAt": getattr(item, "created_at", None),
                "size": getattr(item, "size", None),
            }
        )
    return files
