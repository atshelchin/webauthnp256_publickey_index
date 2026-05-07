# WebAuthnP256PublicKeyIndex

On-chain registry for WebAuthn P256 passkey public keys. Append-only, first come first served.

## Quick start

```shell
forge build   # compile
forge test    # run tests
```

## How it works

Two-step commit-reveal to prevent front-running:

1. `commit(keccak256(abi.encode(rpId, credentialId, publicKey, name, initialCredentialId, metadata)))`
2. Wait 1 block
3. `createRecord(rpId, credentialId, publicKey, name, initialCredentialId, metadata)`

No signature verification — pure storage index. Pass normalized `rpId` (lowercase, punycode) to avoid duplicates.

## Key rotation

- **Initial key**: `initialCredentialId = credentialId`
- **Rotated key**: `initialCredentialId` = an existing root credential under the same `rpId`

Every key traces directly back to the origin credential.

## Contract interface

### Write

| Function | Description |
|---|---|
| `commit(bytes32)` | Submit commitment hash |
| `createRecord(rpId, credentialId, publicKey, name, initialCredentialId, metadata)` | Register a passkey (requires prior commit) |

### Read — single record

| Function | Description |
|---|---|
| `getRecord(rpId, credentialId)` → `PublicKeyRecord` | Get a record (reverts if not found) |
| `hasRecord(rpId, credentialId)` → `bool` | Check existence |

### Read — enumeration (paginated, sortable)

| Function | Description |
|---|---|
| `getTotalRpIds()` → `uint256` | Total distinct sites |
| `getRpCount(rpId)` → `uint256` | Credential count under an rpId |
| `getRpIds(offset, limit, desc)` → `(total, rpIds[], counts[], createdAts[])` | List all sites with pagination |
| `getKeysByRpId(rpId, offset, limit, desc)` → `(total, PublicKeyRecord[])` | List all keys under a site |

Pagination: `offset` = items to skip, `limit` = max items. `desc = true` for newest first.

> All read functions are `view` — free to call (no gas cost).

## PublicKeyRecord

| Field | Type | Description |
|---|---|---|
| `rpId` | `string` | Relying Party domain |
| `credentialId` | `string` | WebAuthn credential ID |
| `publicKey` | `bytes` | Uncompressed P256 key (65 bytes: `04 \|\| x \|\| y`) |
| `name` | `string` | Human-readable label (max 256 bytes) |
| `initialCredentialId` | `string` | Root credential this key traces to |
| `metadata` | `bytes` | Caller-defined data (max 1024 bytes) |
| `createdAt` | `uint256` | `block.timestamp` (seconds) |

## Deployment

| Network | Address |
|---|---|
| Gnosis | `0xc1f7Ef155a0ee1B48edbbB5195608e336ae6542b` |

Deployed via CREATE2 ([Deterministic Deployment Proxy](https://github.com/Arachnid/deterministic-deployment-proxy)) for consistent address across chains.

```shell
forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast --private-key <KEY>
```

## License

MIT
