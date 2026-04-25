# WebAuthnP256PublicKeyIndex

On-chain registry for WebAuthn P256 (secp256r1) passkey public keys. Single source of truth — records are append-only, first come first served.

## How it works

1. Client calls `getChallenge(rpId, credentialId)` to get a deterministic challenge bound to `address(this)`, `chainId`, `rpId`, and `credentialId`.
2. Client signs the challenge with `navigator.credentials.get()` using the passkey.
3. Client calls `createRecord(...)` with the authenticator response. The contract verifies the WebAuthn P256 signature on-chain via the `P256VERIFY` precompile (RIP-7212, available on Ethereum mainnet since Pectra).
4. The public key record is stored permanently under `keccak256(rpId, "\x00", credentialId)`.

## Contract interface

| Function | Description |
|---|---|
| `createRecord(rpId, credentialId, publicKey, name, authenticatorData, clientDataJSON, r, s)` | Register a new passkey with signature proof |
| `getChallenge(rpId, credentialId)` | Get the challenge to pass to `navigator.credentials.get()` |
| `getRecord(rpId, credentialId)` | Query a single record |
| `getRecordsBatch(rpIds[], credentialIds[])` | Batch query multiple records |
| `hasRecord(rpId, credentialId)` | Check if a record exists |
| `getRpCount(rpId)` | Count of credentials under an rpId |

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
