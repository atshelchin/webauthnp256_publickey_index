// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";

contract WebAuthnP256PublicKeyIndexTest is Test {
    WebAuthnP256PublicKeyIndex public index;

    bytes constant PK1 = hex"045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
    bytes constant PK2 = hex"04aaa257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";

    address constant P256_VERIFIER = address(0x0100);

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndex();
        // Mock P256 precompile to return success for all calls
        vm.mockCall(P256_VERIFIER, bytes(hex""), abi.encode(uint256(1)));
    }

    // ── Helpers ──

    function _buildAuthenticatorData(string memory rpId) internal pure returns (bytes memory) {
        bytes32 rpIdHash = sha256(bytes(rpId));
        // flags: 0x05 = UP (bit 0) + UV (bit 2)
        // signCount: 1
        return abi.encodePacked(rpIdHash, uint8(0x05), uint32(1));
    }

    function _buildClientDataJSON(string memory rpId, string memory credentialId) internal view returns (bytes memory) {
        bytes32 challenge = index.getChallenge(rpId, credentialId);
        bytes memory challengeBase64 = _base64UrlEncode(abi.encodePacked(challenge));
        return abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            challengeBase64,
            '","origin":"https://example.com","crossOrigin":false}'
        );
    }

    /// @dev Minimal base64url encoder (no padding) for test helper.
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

    function _createRecord(string memory rpId, string memory credentialId, bytes memory pk, string memory name) internal {
        bytes memory authData = _buildAuthenticatorData(rpId);
        bytes memory clientJSON = _buildClientDataJSON(rpId, credentialId);
        index.createRecord(rpId, credentialId, pk, name, "", "", authData, clientJSON, 1, 2);
    }

    // ── Version ──

    function test_version() public view {
        assertEq(index.VERSION(), 1);
    }

    // ── Create & Query ──

    function test_createAndQuery() public {
        _createRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc", PK1, "My Passkey");

        WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r =
            index.getRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc");

        assertEq(r.rpId, "btc5m.crazydoge.dev");
        assertEq(r.credentialId, "paRIU_PWELwa1kf8R2-2yw54mIc");
        assertEq(r.publicKey, PK1);
        assertEq(r.name, "My Passkey");
        assertGt(r.createdAt, 0);
    }

    function test_createdAt_usesBlockTimestamp() public {
        vm.warp(1700000000);
        _createRecord("rp1", "cred-1", PK1, "Key 1");
        assertEq(index.getRecord("rp1", "cred-1").createdAt, 1700000000);
    }

    function test_sameCredentialId_differentRpId() public {
        _createRecord("rp1", "cred-1", PK1, "Key on rp1");
        _createRecord("rp2", "cred-1", PK2, "Key on rp2");

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
        assertEq(index.getRecord("rp2", "cred-1").publicKey, PK2);
    }

    function test_appendOnly_cannotOverwrite() public {
        _createRecord("rp1", "cred-1", PK1, "Key 1");

        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");

        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.RecordAlreadyExists.selector, "rp1", "cred-1"
        ));
        index.createRecord("rp1", "cred-1", PK2, "Key 2", "", "", authData, clientJSON, 1, 2);

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
    }

    function test_emptyName_allowed() public {
        _createRecord("rp1", "cred-1", PK1, "");
        assertEq(bytes(index.getRecord("rp1", "cred-1").name).length, 0);
    }

    function test_unicodeName() public {
        _createRecord("rp1", "cred-1", PK1, unicode"我的密钥🔑");
        assertEq(index.getRecord("rp1", "cred-1").name, unicode"我的密钥🔑");
    }

    // ── hasRecord ──

    function test_hasRecord() public {
        assertFalse(index.hasRecord("rp1", "cred-1"));
        _createRecord("rp1", "cred-1", PK1, "Key 1");
        assertTrue(index.hasRecord("rp1", "cred-1"));
        assertFalse(index.hasRecord("rp1", "cred-2"));
        assertFalse(index.hasRecord("rp2", "cred-1"));
    }

    // ── getChallenge ──

    function test_getChallenge_deterministic() public view {
        bytes32 c1 = index.getChallenge("rp1", "cred-1");
        bytes32 c2 = index.getChallenge("rp1", "cred-1");
        assertEq(c1, c2);
    }

    function test_getChallenge_differentInputs() public view {
        bytes32 c1 = index.getChallenge("rp1", "cred-1");
        bytes32 c2 = index.getChallenge("rp1", "cred-2");
        bytes32 c3 = index.getChallenge("rp2", "cred-1");
        assertTrue(c1 != c2);
        assertTrue(c1 != c3);
    }

    // ── rpCount ──

    function test_rpCount() public {
        assertEq(index.getRpCount("rp1"), 0);
        _createRecord("rp1", "cred-1", PK1, "Key 1");
        _createRecord("rp1", "cred-2", PK2, "Key 2");
        _createRecord("rp2", "cred-3", PK1, "Key 3");
        assertEq(index.getRpCount("rp1"), 2);
        assertEq(index.getRpCount("rp2"), 1);
        assertEq(index.getRpCount("rp-none"), 0);
    }

    // ── Batch Query ──

    function test_getRecordsBatch() public {
        _createRecord("rp1", "cred-1", PK1, "Key 1");
        _createRecord("rp2", "cred-2", PK2, "Key 2");

        string[] memory rpIds = new string[](3);
        string[] memory credIds = new string[](3);
        rpIds[0] = "rp1"; credIds[0] = "cred-1";
        rpIds[1] = "rp2"; credIds[1] = "cred-2";
        rpIds[2] = "rp1"; credIds[2] = "no-such";

        (WebAuthnP256PublicKeyIndex.PublicKeyRecord[] memory records, bool[] memory exists) =
            index.getRecordsBatch(rpIds, credIds);

        assertTrue(exists[0]);
        assertEq(records[0].publicKey, PK1);
        assertTrue(exists[1]);
        assertEq(records[1].publicKey, PK2);
        assertFalse(exists[2]);
    }

    function test_getRecordsBatch_empty() public view {
        string[] memory rpIds = new string[](0);
        string[] memory credIds = new string[](0);
        (WebAuthnP256PublicKeyIndex.PublicKeyRecord[] memory records, bool[] memory exists) =
            index.getRecordsBatch(rpIds, credIds);
        assertEq(records.length, 0);
        assertEq(exists.length, 0);
    }

    function test_getRecordsBatch_lengthMismatch() public {
        string[] memory rpIds = new string[](2);
        string[] memory credIds = new string[](1);
        rpIds[0] = "rp1"; rpIds[1] = "rp2";
        credIds[0] = "cred-1";
        vm.expectRevert("length mismatch");
        index.getRecordsBatch(rpIds, credIds);
    }

    // ── Input Validation ──

    function test_revert_emptyRpId() public {
        bytes memory authData = _buildAuthenticatorData("");
        bytes memory clientJSON = _buildClientDataJSON("", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.EmptyRpId.selector);
        index.createRecord("", "cred-1", PK1, "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_emptyCredentialId() public {
        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.EmptyCredentialId.selector);
        index.createRecord("rp1", "", PK1, "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_publicKeyTooShort() public {
        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 32
        ));
        index.createRecord("rp1", "cred-1", new bytes(32), "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_publicKeyTooLong() public {
        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 66
        ));
        index.createRecord("rp1", "cred-1", new bytes(66), "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_publicKeyEmpty() public {
        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 0
        ));
        index.createRecord("rp1", "cred-1", "", "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_rpIdTooLong() public {
        bytes memory longRpId = new bytes(254);
        for (uint256 i = 0; i < 254; i++) longRpId[i] = "a";
        bytes memory authData = _buildAuthenticatorData(string(longRpId));
        // Can't easily build clientDataJSON for this, just test the length check
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.RpIdTooLong.selector, 254
        ));
        index.createRecord(string(longRpId), "cred-1", PK1, "bad", "", "", authData, "", 1, 2);
    }

    function test_revert_credentialIdTooLong() public {
        bytes memory longCredId = new bytes(1025);
        for (uint256 i = 0; i < 1025; i++) longCredId[i] = "a";
        bytes memory authData = _buildAuthenticatorData("rp1");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.CredentialIdTooLong.selector, 1025
        ));
        index.createRecord("rp1", string(longCredId), PK1, "bad", "", "", authData, "", 1, 2);
    }

    function test_revert_nameTooLong() public {
        bytes memory longName = new bytes(257);
        for (uint256 i = 0; i < 257; i++) longName[i] = "a";
        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.NameTooLong.selector, 257
        ));
        index.createRecord("rp1", "cred-1", PK1, string(longName), "", "", authData, clientJSON, 1, 2);
    }

    function test_maxLengthValues_succeed() public {
        bytes memory maxRpId = new bytes(253);
        for (uint256 i = 0; i < 253; i++) maxRpId[i] = "a";
        bytes memory maxCredId = new bytes(1024);
        for (uint256 i = 0; i < 1024; i++) maxCredId[i] = "b";
        bytes memory maxName = new bytes(256);
        for (uint256 i = 0; i < 256; i++) maxName[i] = "c";

        bytes memory authData = _buildAuthenticatorData(string(maxRpId));
        bytes memory clientJSON = _buildClientDataJSON(string(maxRpId), string(maxCredId));

        index.createRecord(string(maxRpId), string(maxCredId), PK1, string(maxName), "", "", authData, clientJSON, 1, 2);
        assertTrue(index.hasRecord(string(maxRpId), string(maxCredId)));
    }

    // ── WebAuthn Signature Verification ──

    function test_revert_authenticatorDataTooShort() public {
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidAuthenticatorData.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", new bytes(36), clientJSON, 1, 2);
    }

    function test_revert_authenticatorData_wrongRpIdHash() public {
        // Build authenticatorData with wrong rpId
        bytes memory wrongAuthData = _buildAuthenticatorData("wrong-rp");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidAuthenticatorData.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", wrongAuthData, clientJSON, 1, 2);
    }

    function test_revert_authenticatorData_noUserPresent() public {
        // Build authenticatorData with UP flag cleared
        bytes32 rpIdHash = sha256(bytes("rp1"));
        bytes memory authData = abi.encodePacked(rpIdHash, uint8(0x00), uint32(1)); // flags=0, no UP
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidAuthenticatorData.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_clientDataJSON_wrongType() public {
        bytes32 challenge = index.getChallenge("rp1", "cred-1");
        bytes memory challengeBase64 = _base64UrlEncode(abi.encodePacked(challenge));
        // Use "webauthn.create" instead of "webauthn.get"
        bytes memory badJSON = abi.encodePacked(
            '{"type":"webauthn.create","challenge":"', challengeBase64, '","origin":"https://example.com"}'
        );
        bytes memory authData = _buildAuthenticatorData("rp1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidClientDataJSON.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, badJSON, 1, 2);
    }

    function test_revert_clientDataJSON_wrongChallenge() public {
        // Use a random challenge instead of the expected one
        bytes memory wrongChallengeBase64 = _base64UrlEncode(abi.encodePacked(sha256("wrong")));
        bytes memory badJSON = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', wrongChallengeBase64, '","origin":"https://example.com"}'
        );
        bytes memory authData = _buildAuthenticatorData("rp1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidClientDataJSON.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, badJSON, 1, 2);
    }

    function test_revert_clientDataJSON_noChallenge() public {
        bytes memory badJSON = bytes('{"type":"webauthn.get","origin":"https://example.com"}');
        bytes memory authData = _buildAuthenticatorData("rp1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidClientDataJSON.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, badJSON, 1, 2);
    }

    function test_revert_invalidP256Signature() public {
        // Mock P256 precompile to return failure
        vm.mockCall(P256_VERIFIER, bytes(hex""), abi.encode(uint256(0)));

        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidSignature.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, clientJSON, 1, 2);
    }

    function test_revert_p256PrecompileReverts() public {
        // Mock P256 precompile to revert (return empty)
        vm.mockCallRevert(P256_VERIFIER, bytes(hex""), bytes(hex""));

        bytes memory authData = _buildAuthenticatorData("rp1");
        bytes memory clientJSON = _buildClientDataJSON("rp1", "cred-1");
        vm.expectRevert(WebAuthnP256PublicKeyIndex.InvalidSignature.selector);
        index.createRecord("rp1", "cred-1", PK1, "bad", "", "", authData, clientJSON, 1, 2);
    }

    // ── Real P256 Signature (end-to-end, no mock) ──

    function _deployP256Verifier() internal {
        // Read the pre-compiled P256Verifier bytecode artifact
        string memory artifact = vm.readFile("test/P256Verifier.bytecode");
        bytes memory code = vm.parseBytes(artifact);
        vm.etch(P256_VERIFIER, code);
    }

    function test_realP256Signature() public {
        // Clear all mocks and deploy a real Solidity P256 verifier at the precompile address
        vm.clearMockedCalls();
        _deployP256Verifier();

        // Real P256 key pair (generated offline)
        bytes memory realPK = abi.encodePacked(
            uint8(0x04),
            uint256(0xe39c8ea58602fced67d26bd548b6ac1de8fa0def770788718353af079cbcde91),
            uint256(0x2b75751f634824b03e1b78444af0376d6ff1d6c78f24fbd096c485bdfbb5ab0a)
        );
        uint256 sigR = 0x34737743c2542c7d5057a94325e93e20fbbaaf199b1c094d02da139c9c4e0fc3;
        uint256 sigS = 0x29f63f01be2670b57dea87947cc400a469db1065c80583b596bc16139b3887f3;

        // authenticatorData: SHA256("rp1") || flags=0x05 || signCount=1
        bytes memory authData = hex"bc02d6e4b40820b0e8b5ec5204b1ab99e4e71b2f7c0d6ecb76334254e711b79a0500000001";

        // clientDataJSON with the correct challenge for this contract address + chainId
        bytes memory clientJSON = bytes(
            '{"type":"webauthn.get","challenge":"qQA3flp9MM4AEE5G1Hj_tlK5aJd5Zua35sc55rQpsKs","origin":"https://example.com","crossOrigin":false}'
        );

        // This should pass with real P256 verification (Prague EVM)
        index.createRecord("rp1", "cred-1", realPK, "Real Sig Test", "", "", authData, clientJSON, sigR, sigS);

        WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r = index.getRecord("rp1", "cred-1");
        assertEq(r.publicKey, realPK);
        assertEq(r.name, "Real Sig Test");
    }

    // ── Event ──

    function test_emitsRecordCreated() public {
        bytes32 expectedKey = keccak256(abi.encodePacked("rp1", "\x00", "cred-1"));
        vm.expectEmit(true, false, false, true);
        emit WebAuthnP256PublicKeyIndex.RecordCreated(expectedKey, "rp1", "cred-1", PK1, "", "");
        _createRecord("rp1", "cred-1", PK1, "Key 1");
    }

    // ── Multiple callers ──

    function test_differentCallersCanCreate() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        vm.prank(alice);
        _createRecord("rp1", "cred-a", PK1, "Alice Key");

        vm.prank(bob);
        _createRecord("rp1", "cred-b", PK2, "Bob Key");

        assertEq(index.getRecord("rp1", "cred-a").publicKey, PK1);
        assertEq(index.getRecord("rp1", "cred-b").publicKey, PK2);
        assertEq(index.getRpCount("rp1"), 2);
    }
}
