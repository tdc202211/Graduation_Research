// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileRegistry {
    event FileRegistered(
        string fileHash,
        string boxFileId,
        string boxFileName,
        uint256 timestamp,
        address uploader
    );

    function registerFile(
        string memory fileHash,
        string memory boxFileId,
        string memory boxFileName
    ) external {
        emit FileRegistered(fileHash, boxFileId, boxFileName, block.timestamp, msg.sender);
    }
}
