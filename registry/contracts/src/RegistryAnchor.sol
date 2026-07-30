// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title RegistryAnchor — on-chain anchor for the BlindAge trust registry.
/// @notice Stores ONLY public registry metadata: the keccak256 of the signed
/// registry document's canonical JSON, its generated_at, and a version.
/// Never any user identity, token, redemption, domain, or fingerprint data —
/// not even hashed (BlindAge constitution rule 3). Updates flow exclusively
/// through a TimelockController (audited governance; rule 4 spirit).
contract RegistryAnchor {
    address public immutable timelock;

    bytes32 public registryHash;
    string public generatedAt; // ISO-8601 UTC: lexicographic order = chronological
    uint64 public version;
    uint64 public updatedAt;

    event AnchorUpdated(bytes32 registryHash, string generatedAt, uint64 version);

    error NotTimelock();
    error VersionNotIncreasing();
    error GeneratedAtNotIncreasing();

    constructor(address timelock_) {
        timelock = timelock_;
    }

    /// On-chain rollback protection: version and generatedAt must strictly
    /// increase, independent of any client cache.
    function setAnchor(
        bytes32 newHash,
        string calldata newGeneratedAt,
        uint64 newVersion
    ) external {
        if (msg.sender != timelock) revert NotTimelock();
        if (newVersion <= version) revert VersionNotIncreasing();
        if (!_lexGt(bytes(newGeneratedAt), bytes(generatedAt))) {
            revert GeneratedAtNotIncreasing();
        }
        registryHash = newHash;
        generatedAt = newGeneratedAt;
        version = newVersion;
        updatedAt = uint64(block.timestamp);
        emit AnchorUpdated(newHash, newGeneratedAt, newVersion);
    }

    function current() external view returns (bytes32, string memory, uint64, uint64) {
        return (registryHash, generatedAt, version, updatedAt);
    }

    /// Strict lexicographic greater-than over UTF-8 bytes.
    function _lexGt(bytes memory a, bytes memory b) internal pure returns (bool) {
        uint256 n = a.length < b.length ? a.length : b.length;
        for (uint256 i = 0; i < n; i++) {
            if (a[i] != b[i]) return a[i] > b[i];
        }
        return a.length > b.length;
    }
}
