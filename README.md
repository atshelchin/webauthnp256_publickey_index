# WebAuthnP256PublicKeyIndex

On-chain registry for WebAuthn P256 (secp256r1) passkey public keys. Single source of truth — records are append-only, first come first served.

## How it works

1. Client calls `createRecord(rpId, credentialId, publicKey, name, initialCredentialId, metadata)`.
2. The contract validates inputs and stores the public key record permanently under `keccak256(rpId, "\x00", credentialId)`.

No signature verification is required — the contract is a pure storage index. Credential IDs are random (128-bit+) and unpredictable, making front-running impractical.

## Key rotation

- **Initial key**: set `initialCredentialId = credentialId` (self-reference).
- **Rotated key**: set `initialCredentialId` to an existing credential under the same `rpId`. The contract verifies the referenced record exists.

This allows tracing any key back to its original credential.

## Contract interface

| Function | Description |
|---|---|
| `createRecord(rpId, credentialId, publicKey, name, initialCredentialId, metadata)` | Register a new passkey public key |
| `getRecord(rpId, credentialId)` | Query a single record |
| `hasRecord(rpId, credentialId)` | Check if a record exists |
| `getRpCount(rpId)` | Count of credentials under an rpId |

## PublicKeyRecord struct

| Field | Type | Description |
|---|---|---|
| `rpId` | `string` | Relying Party ID (domain) |
| `credentialId` | `string` | WebAuthn credential identifier |
| `publicKey` | `bytes` | Uncompressed P256 public key (65 bytes: `0x04 \|\| x \|\| y`) |
| `name` | `string` | Human-readable label (max 256 bytes) |
| `initialCredentialId` | `string` | The original credential this key traces back to |
| `metadata` | `bytes` | Caller-defined data (e.g. EOA address, signer index, tags), max 1024 bytes |
| `createdAt` | `uint256` | Block timestamp at creation |

## Build

```shell
forge build
```

## Test

```shell
forge test
```

## Deploy (CREATE2)

Deploy to a deterministic address via the [Deterministic Deployment Proxy](https://github.com/Arachnid/deterministic-deployment-proxy):

```shell
forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast --private-key <KEY>
```

Custom salt:

```shell
DEPLOY_SALT=0x0000...0001 forge script script/Deploy.s.sol --rpc-url <RPC_URL> --broadcast --private-key <KEY>
```

## License

MIT
