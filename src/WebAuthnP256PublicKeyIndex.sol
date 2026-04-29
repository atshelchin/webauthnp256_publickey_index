// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WebAuthnP256PublicKeyIndex
/// @notice Stores WebAuthn P256 passkey public keys on Ethereum mainnet.
///         Single source of truth for all chains. Records are append-only.
///         (rpId, credentialId) is globally unique — first come, first served.
contract WebAuthnP256PublicKeyIndex {
    uint8 public constant VERSION = 1;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant MAX_CREDENTIAL_ID_LENGTH = 1024;
    uint256 public constant MAX_NAME_LENGTH = 256;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)

    struct PublicKeyRecord {
        string rpId;
        string credentialId;
        bytes publicKey;
        string name;
        string initialCredentialId;
        bytes metadata;
        uint256 createdAt;
    }

    mapping(bytes32 => PublicKeyRecord) private _records;
    mapping(string => uint256) private _rpCount;

    event RecordCreated(bytes32 indexed key, string rpId, string credentialId, bytes publicKey, string initialCredentialId, bytes metadata);

    error EmptyRpId();
    error EmptyCredentialId();
    error InvalidPublicKeyLength(uint256 length);
    error RpIdTooLong(uint256 length);
    error CredentialIdTooLong(uint256 length);
    error NameTooLong(uint256 length);
    error RecordAlreadyExists(string rpId, string credentialId);
    error RecordNotFound(string rpId, string credentialId);
    error InitialRecordNotFound(string rpId, string initialCredentialId);

    function _recordKey(string calldata rpId, string calldata credentialId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(rpId, "\x00", credentialId));
    }

    // ── Write ──

    /// @notice Store a new passkey public key record.
    /// @param initialCredentialId Must equal credentialId (initial key) or reference an existing record (rotated key).
    function createRecord(
        string calldata rpId,
        string calldata credentialId,
        bytes calldata publicKey,
        string calldata name,
        string calldata initialCredentialId,
        bytes calldata metadata
    ) external {
        if (bytes(rpId).length == 0) revert EmptyRpId();
        if (bytes(rpId).length > MAX_RPID_LENGTH) revert RpIdTooLong(bytes(rpId).length);
        if (bytes(credentialId).length == 0) revert EmptyCredentialId();
        if (bytes(credentialId).length > MAX_CREDENTIAL_ID_LENGTH) revert CredentialIdTooLong(bytes(credentialId).length);
        if (publicKey.length != UNCOMPRESSED_P256_KEY_LENGTH) revert InvalidPublicKeyLength(publicKey.length);
        if (bytes(name).length > MAX_NAME_LENGTH) revert NameTooLong(bytes(name).length);

        bytes32 k = _recordKey(rpId, credentialId);
        if (_records[k].createdAt != 0) revert RecordAlreadyExists(rpId, credentialId);

        // initialCredentialId must equal credentialId (initial key) or reference an existing record
        if (keccak256(bytes(initialCredentialId)) != keccak256(bytes(credentialId))) {
            bytes32 initKey = _recordKey(rpId, initialCredentialId);
            if (_records[initKey].createdAt == 0) revert InitialRecordNotFound(rpId, initialCredentialId);
        }

        _records[k] = PublicKeyRecord({
            rpId: rpId,
            credentialId: credentialId,
            publicKey: publicKey,
            name: name,
            initialCredentialId: initialCredentialId,
            metadata: metadata,
            createdAt: block.timestamp
        });
        _rpCount[rpId]++;

        emit RecordCreated(k, rpId, credentialId, publicKey, initialCredentialId, metadata);
    }

    // ── Read ──

    /// @notice Query a record by rpId and credentialId.
    function getRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (PublicKeyRecord memory)
    {
        bytes32 k = _recordKey(rpId, credentialId);
        if (_records[k].createdAt == 0) revert RecordNotFound(rpId, credentialId);
        return _records[k];
    }

    /// @notice Check if a record exists.
    function hasRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (bool)
    {
        return _records[_recordKey(rpId, credentialId)].createdAt != 0;
    }

    /// @notice Get the number of credentials registered under an rpId.
    function getRpCount(string calldata rpId) external view returns (uint256) {
        return _rpCount[rpId];
    }
}
