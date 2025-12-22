// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileRegistry {
    struct Latest {
        bytes32 fileHash;
        string fileName;
        uint256 updatedAt;
        bool exists;
    }

    // fileId（string）を keccak256 して固定長キーにする
    mapping(bytes32 => Latest) private latestByFileKey;

    event FileRecordedOrUpdated(
        bytes32 indexed fileKey,
        string fileId,
        bytes32 fileHash,
        string fileName,
        uint256 updatedAt
    );

    function _key(string memory fileId) internal pure returns (bytes32) {
        return keccak256(bytes(fileId));
    }

    // ★ 上書きOK：同じ fileId なら常に最新状態に更新される
    function recordOrUpdate(bytes32 fileHash, string calldata fileId, string calldata fileName) external {
        bytes32 k = _key(fileId);
        latestByFileKey[k] = Latest({
            fileHash: fileHash,
            fileName: fileName,
            updatedAt: block.timestamp,
            exists: true
        });

        emit FileRecordedOrUpdated(k, fileId, fileHash, fileName, block.timestamp);
    }

    // ★ 読み取り（検証用）：最新状態を返す
    function getLatest(string calldata fileId)
        external
        view
        returns (bytes32 fileHash, string memory fileName, uint256 updatedAt, bool exists)
    {
        Latest memory r = latestByFileKey[_key(fileId)];
        return (r.fileHash, r.fileName, r.updatedAt, r.exists);
    }
}
