// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {WebAuthnP256PublicKeyIndex} from "../src/WebAuthnP256PublicKeyIndex.sol";

contract WebAuthnP256PublicKeyIndexTest is Test {
    WebAuthnP256PublicKeyIndex public index;

    bytes constant PK1 = hex"045ff257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";
    bytes constant PK2 = hex"04aaa257819a8927dc548d62eeb90a7a61a8e90afd70c9f774e7ed78d0c5bbbc0e8ed0f6a55f675f162b2e8450f79cd0e6766e56f10f762430ec15d2a4388f19fb";

    function setUp() public {
        index = new WebAuthnP256PublicKeyIndex();
    }

    // ── Helpers ──

    function _commitFull(
        string memory rpId, string memory credentialId, bytes memory pk,
        string memory name, string memory initialCredentialId, bytes memory metadata
    ) internal {
        bytes32 commitment = keccak256(abi.encode(rpId, credentialId, pk, name, initialCredentialId, metadata));
        index.commit(commitment);
        vm.roll(block.number + 2);
    }

    function _createInitialRecord(string memory rpId, string memory credentialId, bytes memory pk, string memory name) internal {
        _commitFull(rpId, credentialId, pk, name, credentialId, "");
        index.createRecord(rpId, credentialId, pk, name, credentialId, "");
    }

    // ── Version ──

    function test_version() public view {
        assertEq(index.VERSION(), 1);
    }

    // ── Create & Query ──

    function test_createAndQuery() public {
        _createInitialRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc", PK1, "My Passkey");

        WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r =
            index.getRecord("btc5m.crazydoge.dev", "paRIU_PWELwa1kf8R2-2yw54mIc");

        assertEq(r.rpId, "btc5m.crazydoge.dev");
        assertEq(r.credentialId, "paRIU_PWELwa1kf8R2-2yw54mIc");
        assertEq(r.publicKey, PK1);
        assertEq(r.name, "My Passkey");
        assertEq(r.initialCredentialId, "paRIU_PWELwa1kf8R2-2yw54mIc");
        assertGt(r.createdAt, 0);
    }

    function test_createdAt_usesBlockTimestamp() public {
        vm.warp(1700000000);
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        assertEq(index.getRecord("rp1", "cred-1").createdAt, 1700000000);
    }

    function test_sameCredentialId_differentRpId() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Key on rp1");
        _createInitialRecord("rp2", "cred-1", PK2, "Key on rp2");

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
        assertEq(index.getRecord("rp2", "cred-1").publicKey, PK2);
    }

    function test_appendOnly_cannotOverwrite() public {
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");

        _commitFull("rp1", "cred-1", PK2, "Key 2", "cred-1", "");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.RecordAlreadyExists.selector, "rp1", "cred-1"
        ));
        index.createRecord("rp1", "cred-1", PK2, "Key 2", "cred-1", "");

        assertEq(index.getRecord("rp1", "cred-1").publicKey, PK1);
    }

    function test_emptyName_allowed() public {
        _createInitialRecord("rp1", "cred-1", PK1, "");
        assertEq(bytes(index.getRecord("rp1", "cred-1").name).length, 0);
    }

    function test_unicodeName() public {
        _createInitialRecord("rp1", "cred-1", PK1, unicode"我的密钥🔑");
        assertEq(index.getRecord("rp1", "cred-1").name, unicode"我的密钥🔑");
    }

    // ── initialCredentialId validation ──

    function test_initialKey_selfReference() public {
        // initialCredentialId == credentialId → initial key, always valid
        _commitFull("rp1", "cred-1", PK1, "Initial", "cred-1", "");
        index.createRecord("rp1", "cred-1", PK1, "Initial", "cred-1", "");
        assertEq(index.getRecord("rp1", "cred-1").initialCredentialId, "cred-1");
    }

    function test_rotatedKey_referencesExisting() public {
        // Register initial key first
        _createInitialRecord("rp1", "cred-1", PK1, "Initial");

        // Rotated key references the initial
        _commitFull("rp1", "cred-2", PK2, "Rotated", "cred-1", "");
        index.createRecord("rp1", "cred-2", PK2, "Rotated", "cred-1", "");

        WebAuthnP256PublicKeyIndex.PublicKeyRecord memory r = index.getRecord("rp1", "cred-2");
        assertEq(r.initialCredentialId, "cred-1");
    }

    function test_revert_initialCredentialId_notFound() public {
        _commitFull("rp1", "cred-2", PK1, "Bad", "nonexistent", "");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InitialRecordNotFound.selector, "rp1", "nonexistent"
        ));
        index.createRecord("rp1", "cred-2", PK1, "Bad", "nonexistent", "");
    }

    function test_rotatedKey_initialMustBeOnSameRpId() public {
        // cred-1 exists on rp1, but not on rp2
        _createInitialRecord("rp1", "cred-1", PK1, "Initial on rp1");

        _commitFull("rp2", "cred-2", PK2, "Bad rotation", "cred-1", "");
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InitialRecordNotFound.selector, "rp2", "cred-1"
        ));
        index.createRecord("rp2", "cred-2", PK2, "Bad rotation", "cred-1", "");
    }

    // ── metadata ──

    function test_metadata_stored() public {
        bytes memory meta = abi.encode(address(0xdead), uint256(42));
        _commitFull("rp1", "cred-1", PK1, "With meta", "cred-1", meta);
        index.createRecord("rp1", "cred-1", PK1, "With meta", "cred-1", meta);
        assertEq(index.getRecord("rp1", "cred-1").metadata, meta);
    }

    function test_metadata_empty() public {
        _createInitialRecord("rp1", "cred-1", PK1, "No meta");
        assertEq(index.getRecord("rp1", "cred-1").metadata.length, 0);
    }

    // ── hasRecord ──

    function test_hasRecord() public {
        assertFalse(index.hasRecord("rp1", "cred-1"));
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        assertTrue(index.hasRecord("rp1", "cred-1"));
        assertFalse(index.hasRecord("rp1", "cred-2"));
        assertFalse(index.hasRecord("rp2", "cred-1"));
    }

    // ── rpCount ──

    function test_rpCount() public {
        assertEq(index.getRpCount("rp1"), 0);
        _createInitialRecord("rp1", "cred-1", PK1, "Key 1");
        _createInitialRecord("rp1", "cred-2", PK2, "Key 2");
        _createInitialRecord("rp2", "cred-3", PK1, "Key 3");
        assertEq(index.getRpCount("rp1"), 2);
        assertEq(index.getRpCount("rp2"), 1);
        assertEq(index.getRpCount("rp-none"), 0);
    }

    // ── Input Validation ──

    function test_revert_emptyRpId() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndex.EmptyRpId.selector);
        index.createRecord("", "cred-1", PK1, "bad", "cred-1", "");
    }

    function test_revert_emptyCredentialId() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndex.EmptyCredentialId.selector);
        index.createRecord("rp1", "", PK1, "bad", "", "");
    }

    function test_revert_publicKeyTooShort() public {
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 32
        ));
        index.createRecord("rp1", "cred-1", new bytes(32), "bad", "cred-1", "");
    }

    function test_revert_publicKeyTooLong() public {
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 66
        ));
        index.createRecord("rp1", "cred-1", new bytes(66), "bad", "cred-1", "");
    }

    function test_revert_publicKeyEmpty() public {
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyLength.selector, 0
        ));
        index.createRecord("rp1", "cred-1", "", "bad", "cred-1", "");
    }

    function test_revert_rpIdTooLong() public {
        bytes memory longRpId = new bytes(254);
        for (uint256 i = 0; i < 254; i++) longRpId[i] = "a";
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.RpIdTooLong.selector, 254
        ));
        index.createRecord(string(longRpId), "cred-1", PK1, "bad", "cred-1", "");
    }

    function test_revert_credentialIdTooLong() public {
        bytes memory longCredId = new bytes(1025);
        for (uint256 i = 0; i < 1025; i++) longCredId[i] = "a";
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.CredentialIdTooLong.selector, 1025
        ));
        index.createRecord("rp1", string(longCredId), PK1, "bad", string(longCredId), "");
    }

    function test_revert_nameTooLong() public {
        bytes memory longName = new bytes(257);
        for (uint256 i = 0; i < 257; i++) longName[i] = "a";
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.NameTooLong.selector, 257
        ));
        index.createRecord("rp1", "cred-1", PK1, string(longName), "cred-1", "");
    }

    function test_revert_publicKeyBadPrefix() public {
        bytes memory badPK = new bytes(65);
        badPK[0] = 0x03; // should be 0x04
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InvalidPublicKeyPrefix.selector, bytes1(0x03)
        ));
        index.createRecord("rp1", "cred-1", badPK, "bad", "cred-1", "");
    }

    function test_revert_initialCredentialIdTooLong() public {
        bytes memory longInitCredId = new bytes(1025);
        for (uint256 i = 0; i < 1025; i++) longInitCredId[i] = "a";
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.InitialCredentialIdTooLong.selector, 1025
        ));
        index.createRecord("rp1", "cred-1", PK1, "bad", string(longInitCredId), "");
    }

    function test_revert_metadataTooLong() public {
        bytes memory longMeta = new bytes(1025);
        vm.expectRevert(abi.encodeWithSelector(
            WebAuthnP256PublicKeyIndex.MetadataTooLong.selector, 1025
        ));
        index.createRecord("rp1", "cred-1", PK1, "bad", "cred-1", longMeta);
    }

    function test_maxLengthValues_succeed() public {
        bytes memory maxRpId = new bytes(253);
        for (uint256 i = 0; i < 253; i++) maxRpId[i] = "a";
        bytes memory maxCredId = new bytes(1024);
        for (uint256 i = 0; i < 1024; i++) maxCredId[i] = "b";
        bytes memory maxName = new bytes(256);
        for (uint256 i = 0; i < 256; i++) maxName[i] = "c";

        _commitFull(string(maxRpId), string(maxCredId), PK1, string(maxName), string(maxCredId), new bytes(1024));
        index.createRecord(string(maxRpId), string(maxCredId), PK1, string(maxName), string(maxCredId), new bytes(1024));
        assertTrue(index.hasRecord(string(maxRpId), string(maxCredId)));
    }

    // ── Event ──

    function test_emitsRecordCreated() public {
        _commitFull("rp1", "cred-1", PK1, "Key 1", "cred-1", "");
        bytes32 expectedKey = keccak256(abi.encode("rp1", "cred-1"));
        vm.expectEmit(true, false, false, true);
        emit WebAuthnP256PublicKeyIndex.RecordCreated(expectedKey, "rp1", "cred-1", PK1, "cred-1", "");
        index.createRecord("rp1", "cred-1", PK1, "Key 1", "cred-1", "");
    }

    // ── Multiple callers ──

    function test_differentCallersCanCreate() public {
        address alice = makeAddr("alice");
        address bob = makeAddr("bob");

        // Both commit
        bytes32 cAlice = keccak256(abi.encode("rp1", "cred-a", PK1, "Alice Key", "cred-a", bytes("")));
        bytes32 cBob = keccak256(abi.encode("rp1", "cred-b", PK2, "Bob Key", "cred-b", bytes("")));
        vm.prank(alice);
        index.commit(cAlice);
        vm.prank(bob);
        index.commit(cBob);

        vm.roll(block.number + 2);

        vm.prank(alice);
        index.createRecord("rp1", "cred-a", PK1, "Alice Key", "cred-a", "");
        vm.prank(bob);
        index.createRecord("rp1", "cred-b", PK2, "Bob Key", "cred-b", "");

        assertEq(index.getRecord("rp1", "cred-a").publicKey, PK1);
        assertEq(index.getRecord("rp1", "cred-b").publicKey, PK2);
        assertEq(index.getRpCount("rp1"), 2);
    }

    // ── Commit-Reveal ──

    function test_revert_notCommitted() public {
        vm.expectRevert(WebAuthnP256PublicKeyIndex.NotCommitted.selector);
        index.createRecord("rp1", "cred-1", PK1, "No commit", "cred-1", "");
    }

    function test_revert_revealTooEarly() public {
        bytes32 commitment = keccak256(abi.encode("rp1", "cred-1", PK1, "Early", "cred-1", bytes("")));
        index.commit(commitment);
        // Don't roll forward — still same block
        vm.expectRevert(WebAuthnP256PublicKeyIndex.RevealTooEarly.selector);
        index.createRecord("rp1", "cred-1", PK1, "Early", "cred-1", "");
    }

    function test_commitOnlyStoredOnce() public {
        bytes32 commitment = keccak256(abi.encode("rp1", "cred-1", PK1, "Test", "cred-1", bytes("")));
        index.commit(commitment);
        vm.roll(block.number + 5);
        index.commit(commitment); // should not overwrite
        vm.roll(block.number + 2);
        // reveal should succeed (delay measured from first commit)
        index.createRecord("rp1", "cred-1", PK1, "Test", "cred-1", "");
        assertTrue(index.hasRecord("rp1", "cred-1"));
    }
}
