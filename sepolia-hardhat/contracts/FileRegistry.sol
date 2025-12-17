// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileRegistry {
    struct FileRecord {
        bytes32 fileHash;   // SHA-256ならbytes32にぴったり
        string boxUrl;      // 共有リンク or 何か識別子
        string fileName;    // 任意（なくてもいい）
        uint256 uploadedAt; // ブロック時刻
        address uploader;   // 誰が登録したか
    }

    mapping(bytes32 => FileRecord) public records;

    event FileRecorded(bytes32 indexed fileHash, string boxUrl, string fileName, address indexed uploader);

    function recordFile(bytes32 fileHash, string calldata boxUrl, string calldata fileName) external {
        // 二重登録を嫌うならチェック
        require(records[fileHash].uploadedAt == 0, "already recorded");

        records[fileHash] = FileRecord({
            fileHash: fileHash,
            boxUrl: boxUrl,
            fileName: fileName,
            uploadedAt: block.timestamp,
            uploader: msg.sender
        });

        emit FileRecorded(fileHash, boxUrl, fileName, msg.sender);
    }
}
