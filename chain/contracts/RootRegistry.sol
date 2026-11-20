// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title Root-Defense Root Registry
/// @notice Append-only public notary for Merkle roots of security-log batches.
///         Only hashes are stored here: never raw log text.
///         There is deliberately no function to edit or delete an anchor.
contract RootRegistry {
    /// Why an anchor was written.
    uint8 public constant REASON_SCHEDULED = 0; // regular interval
    uint8 public constant REASON_CRITICAL = 1;  // critical log event (root login, sudo, ...)
    uint8 public constant REASON_ALARM = 2;     // witness alarm (agent silent, tamper report)

    struct Anchor {
        bytes32 streamId;   // which monitored server / agent
        bytes32 root;       // Merkle root of the batch
        uint64 firstSeq;    // first entry sequence number in the batch
        uint64 lastSeq;     // last entry sequence number in the batch
        uint32 count;       // number of entries in the batch
        uint8 reason;       // REASON_*
        uint64 timestamp;   // block timestamp
        uint64 blockNumber; // block number
    }

    address public immutable owner;
    mapping(address => bool) public isWriter;
    Anchor[] private anchors;
    mapping(bytes32 => uint256[]) private streamAnchors;

    event Anchored(
        uint256 indexed index,
        bytes32 indexed streamId,
        bytes32 root,
        uint64 firstSeq,
        uint64 lastSeq,
        uint32 count,
        uint8 reason,
        uint64 timestamp
    );
    event WriterSet(address indexed writer, bool allowed);

    error NotOwner();
    error NotWriter();
    error EmptyBatch();
    error BadRange();

    constructor() {
        owner = msg.sender;
        isWriter[msg.sender] = true;
        emit WriterSet(msg.sender, true);
    }

    function setWriter(address writer, bool allowed) external {
        if (msg.sender != owner) revert NotOwner();
        isWriter[writer] = allowed;
        emit WriterSet(writer, allowed);
    }

    /// @notice Record a Merkle root. Returns the global anchor index.
    function anchor(
        bytes32 streamId,
        bytes32 root,
        uint64 firstSeq,
        uint64 lastSeq,
        uint32 count,
        uint8 reason
    ) external returns (uint256 index) {
        if (!isWriter[msg.sender]) revert NotWriter();
        if (count == 0) revert EmptyBatch();
        if (lastSeq < firstSeq) revert BadRange();

        index = anchors.length;
        anchors.push(
            Anchor({
                streamId: streamId,
                root: root,
                firstSeq: firstSeq,
                lastSeq: lastSeq,
                count: count,
                reason: reason,
                timestamp: uint64(block.timestamp),
                blockNumber: uint64(block.number)
            })
        );
        streamAnchors[streamId].push(index);
        emit Anchored(index, streamId, root, firstSeq, lastSeq, count, reason, uint64(block.timestamp));
    }

    function anchorCount() external view returns (uint256) {
        return anchors.length;
    }

    function getAnchor(uint256 index) external view returns (Anchor memory) {
        return anchors[index];
    }

    function streamAnchorCount(bytes32 streamId) external view returns (uint256) {
        return streamAnchors[streamId].length;
    }

    function streamAnchorAt(bytes32 streamId, uint256 i) external view returns (uint256) {
        return streamAnchors[streamId][i];
    }
}
