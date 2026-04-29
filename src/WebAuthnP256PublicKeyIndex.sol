// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WebAuthnP256PublicKeyIndex
/// @notice Stores WebAuthn P256 passkey public keys on Ethereum mainnet.
///         Single source of truth for all chains. Records are append-only.
///         (rpId, credentialId) is globally unique — first come, first served.
///         createRecord requires a valid WebAuthn P256 signature to prove key ownership.
contract WebAuthnP256PublicKeyIndex {
    uint8 public constant VERSION = 1;

    uint256 public constant MAX_RPID_LENGTH = 253;
    uint256 public constant MAX_CREDENTIAL_ID_LENGTH = 1024;
    uint256 public constant MAX_NAME_LENGTH = 256;
    uint256 public constant UNCOMPRESSED_P256_KEY_LENGTH = 65; // 04 || x(32) || y(32)

    /// @dev P256VERIFY precompile (RIP-7212, Ethereum mainnet Pectra+)
    address private constant P256_VERIFIER = address(0x0100);

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
    mapping(bytes32 => bool) private _exists;
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
    error InvalidSignature();
    error InvalidClientDataJSON();
    error InvalidAuthenticatorData();

    function _recordKey(string calldata rpId, string calldata credentialId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(rpId, "\x00", credentialId));
    }

    // ── Write ──

    /// @notice Store a new passkey public key record with WebAuthn signature proof.
    /// @dev Client flow:
    ///      1. Call getChallenge(rpId, credentialId) to get the challenge bytes.
    ///      2. Pass challenge to navigator.credentials.get() as the challenge parameter.
    ///      3. Extract authenticatorData, clientDataJSON, and signature (r, s) from the response.
    ///      4. Call createRecord with all parameters.
    function createRecord(
        string calldata rpId,
        string calldata credentialId,
        bytes calldata publicKey,
        string calldata name,
        string calldata initialCredentialId,
        bytes calldata metadata,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        uint256 r,
        uint256 s
    ) external {
        if (bytes(rpId).length == 0) revert EmptyRpId();
        if (bytes(rpId).length > MAX_RPID_LENGTH) revert RpIdTooLong(bytes(rpId).length);
        if (bytes(credentialId).length == 0) revert EmptyCredentialId();
        if (bytes(credentialId).length > MAX_CREDENTIAL_ID_LENGTH) revert CredentialIdTooLong(bytes(credentialId).length);
        if (publicKey.length != UNCOMPRESSED_P256_KEY_LENGTH) revert InvalidPublicKeyLength(publicKey.length);
        if (bytes(name).length > MAX_NAME_LENGTH) revert NameTooLong(bytes(name).length);

        bytes32 k = _recordKey(rpId, credentialId);
        if (_exists[k]) revert RecordAlreadyExists(rpId, credentialId);

        _verifySignature(rpId, credentialId, publicKey, authenticatorData, clientDataJSON, r, s);

        _records[k] = PublicKeyRecord({
            rpId: rpId,
            credentialId: credentialId,
            publicKey: publicKey,
            name: name,
            initialCredentialId: initialCredentialId,
            metadata: metadata,
            createdAt: block.timestamp
        });
        _exists[k] = true;
        _rpCount[rpId]++;

        emit RecordCreated(k, rpId, credentialId, publicKey, initialCredentialId, metadata);
    }

    // ── Read ──

    /// @notice Compute the challenge bytes for navigator.credentials.get().
    function getChallenge(string calldata rpId, string calldata credentialId)
        external
        view
        returns (bytes32)
    {
        return _computeChallenge(rpId, credentialId);
    }

    /// @notice Query a record by rpId and credentialId.
    function getRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (PublicKeyRecord memory)
    {
        bytes32 k = _recordKey(rpId, credentialId);
        if (!_exists[k]) revert RecordNotFound(rpId, credentialId);
        return _records[k];
    }

    /// @notice Batch query multiple records.
    function getRecordsBatch(string[] calldata rpIds, string[] calldata credentialIds)
        external
        view
        returns (PublicKeyRecord[] memory records, bool[] memory exists)
    {
        require(rpIds.length == credentialIds.length, "length mismatch");
        uint256 len = rpIds.length;
        records = new PublicKeyRecord[](len);
        exists = new bool[](len);
        for (uint256 i = 0; i < len; i++) {
            bytes32 k = keccak256(abi.encodePacked(rpIds[i], "\x00", credentialIds[i]));
            exists[i] = _exists[k];
            if (exists[i]) {
                records[i] = _records[k];
            }
        }
    }

    /// @notice Check if a record exists.
    function hasRecord(string calldata rpId, string calldata credentialId)
        external
        view
        returns (bool)
    {
        return _exists[_recordKey(rpId, credentialId)];
    }

    /// @notice Get the number of credentials registered under an rpId.
    function getRpCount(string calldata rpId) external view returns (uint256) {
        return _rpCount[rpId];
    }

    // ── WebAuthn Verification (internal) ──

    function _computeChallenge(string calldata rpId, string calldata credentialId)
        internal
        view
        returns (bytes32)
    {
        return sha256(abi.encodePacked(address(this), block.chainid, rpId, "\x00", credentialId));
    }

    function _verifySignature(
        string calldata rpId,
        string calldata credentialId,
        bytes calldata publicKey,
        bytes calldata authenticatorData,
        bytes calldata clientDataJSON,
        uint256 r,
        uint256 s
    ) internal view {
        // 1. Validate authenticatorData: minimum 37 bytes (rpIdHash 32 + flags 1 + signCount 4)
        if (authenticatorData.length < 37) revert InvalidAuthenticatorData();
        // Verify rpIdHash matches
        if (bytes32(authenticatorData[:32]) != sha256(bytes(rpId))) revert InvalidAuthenticatorData();
        // Require UP (user present) flag (bit 0)
        if (uint8(authenticatorData[32]) & 0x01 == 0) revert InvalidAuthenticatorData();

        // 2. Verify clientDataJSON contains correct type and challenge
        bytes32 challenge = _computeChallenge(rpId, credentialId);
        bytes memory challengeBase64 = _base64UrlEncode(abi.encodePacked(challenge));
        _verifyClientDataJSON(bytes(clientDataJSON), challengeBase64);

        // 3. Compute WebAuthn message hash: SHA256(authenticatorData || SHA256(clientDataJSON))
        bytes32 messageHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));

        // 4. Extract x, y from uncompressed P256 public key (skip 0x04 prefix)
        uint256 x = uint256(bytes32(publicKey[1:33]));
        uint256 y = uint256(bytes32(publicKey[33:65]));

        // 5. Verify P256 signature via precompile
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encode(messageHash, r, s, x, y)
        );
        if (!success || result.length < 32 || abi.decode(result, (uint256)) != 1) {
            revert InvalidSignature();
        }
    }

    /// @dev Verify clientDataJSON contains "type":"webauthn.get" and the expected challenge.
    function _verifyClientDataJSON(bytes memory json, bytes memory expectedChallenge) internal pure {
        // Must contain type field
        if (!_containsBytes(json, bytes('"type":"webauthn.get"'))) {
            revert InvalidClientDataJSON();
        }

        // Find challenge field and verify value
        bytes memory prefix = bytes('"challenge":"');
        int256 idx = _indexOfBytes(json, prefix);
        if (idx < 0) revert InvalidClientDataJSON();

        uint256 start = uint256(idx) + prefix.length;
        uint256 end = start + expectedChallenge.length;
        if (end >= json.length) revert InvalidClientDataJSON();

        for (uint256 i = 0; i < expectedChallenge.length; i++) {
            if (json[start + i] != expectedChallenge[i]) {
                revert InvalidClientDataJSON();
            }
        }

        // Challenge must be followed by closing quote
        if (json[end] != '"') revert InvalidClientDataJSON();
    }

    function _indexOfBytes(bytes memory haystack, bytes memory needle) internal pure returns (int256) {
        if (needle.length == 0 || needle.length > haystack.length) return -1;
        uint256 limit = haystack.length - needle.length + 1;
        for (uint256 i = 0; i < limit; i++) {
            bool found = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return int256(i);
        }
        return -1;
    }

    function _containsBytes(bytes memory haystack, bytes memory needle) internal pure returns (bool) {
        return _indexOfBytes(haystack, needle) >= 0;
    }

    /// @dev Base64url encode without padding (RFC 4648 §5).
    function _base64UrlEncode(bytes memory data) internal pure returns (bytes memory) {
        bytes memory table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        uint256 len = data.length;
        uint256 encodedLen = (len * 4 + 2) / 3;

        bytes memory result = new bytes(encodedLen);
        uint256 j = 0;

        for (uint256 i = 0; i < len; i += 3) {
            uint256 a = uint8(data[i]);
            uint256 b = (i + 1 < len) ? uint8(data[i + 1]) : 0;
            uint256 c = (i + 2 < len) ? uint8(data[i + 2]) : 0;
            uint256 triple = (a << 16) | (b << 8) | c;

            result[j++] = table[(triple >> 18) & 0x3F];
            if (j < encodedLen) result[j++] = table[(triple >> 12) & 0x3F];
            if (j < encodedLen) result[j++] = table[(triple >> 6) & 0x3F];
            if (j < encodedLen) result[j++] = table[triple & 0x3F];
        }

        return result;
    }
}
