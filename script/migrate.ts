import {
  createWalletClient,
  createPublicClient,
  http,
  encodeAbiParameters,
  parseAbiParameters,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";

declare const process: {
  env: Record<string, string | undefined>;
  exit(code?: number): never;
};

// ── Config ──

const PRIVATE_KEY = process.env.PRIVATE_KEY as Hex;
if (!PRIVATE_KEY) throw new Error("PRIVATE_KEY env required");
if (!/^0x[0-9a-fA-F]{64}$/.test(PRIVATE_KEY)) {
  throw new Error("PRIVATE_KEY must be a 32-byte hex string with 0x prefix");
}

const RPC_URL = process.env.RPC_URL || "https://rpc.gnosischain.com";
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
if (!CONTRACT_ADDRESS) throw new Error("CONTRACT_ADDRESS env required");
if (!/^0x[0-9a-fA-F]{40}$/.test(CONTRACT_ADDRESS)) {
  throw new Error("CONTRACT_ADDRESS must be an EVM address");
}
const CONTRACT = CONTRACT_ADDRESS as Address;
const API_BASE = process.env.API_BASE || "https://webauthnp256-publickey-index.biubiu.tools";

// ── ABI (only what we need) ──

const abi = [
  {
    type: "function",
    name: "commit",
    inputs: [{ name: "commitment", type: "bytes32" }],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "createRecord",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "credentialId", type: "string" },
      { name: "walletRef", type: "bytes32" },
      { name: "publicKey", type: "bytes" },
      { name: "name", type: "string" },
      { name: "initialCredentialId", type: "string" },
      { name: "metadata", type: "bytes" },
    ],
    outputs: [],
    stateMutability: "nonpayable",
  },
  {
    type: "function",
    name: "hasRecord",
    inputs: [
      { name: "rpId", type: "string" },
      { name: "credentialId", type: "string" },
    ],
    outputs: [{ type: "bool" }],
    stateMutability: "view",
  },
] as const;

// ── Types ──

interface ApiRecord {
  rpId: string;
  credentialId: string;
  walletRef?: string;
  walletAddress?: string;
  address?: string;
  publicKey: string;
  name: string;
}

// ── Fetch all records from API ──

async function fetchAllRecords(): Promise<ApiRecord[]> {
  const sitesRes = await fetch(`${API_BASE}/api/stats/sites?pageSize=100`);
  const sites = (await sitesRes.json()) as {
    items: { rpId: string }[];
  };

  const records: ApiRecord[] = [];
  for (const site of sites.items) {
    const keysRes = await fetch(
      `${API_BASE}/api/stats/keys?rpId=${encodeURIComponent(site.rpId)}&pageSize=1000`
    );
    const keys = (await keysRes.json()) as { items: ApiRecord[] };
    // oldest first for on-chain insertion order
    records.push(...keys.items.reverse());
  }

  console.log(`Fetched ${records.length} records from ${sites.items.length} sites`);
  return records;
}

// ── Build metadata: abi.encode("VelaWalletV1", publicKey) ──

function buildMetadata(publicKey: Hex): Hex {
  return encodeAbiParameters(
    parseAbiParameters("string, bytes"),
    ["VelaWalletV1", publicKey]
  );
}

function normalizeHex(value: string): Hex {
  return (value.startsWith("0x") ? value : `0x${value}`) as Hex;
}

function buildWalletRef(r: ApiRecord): Hex {
  const source = r.walletRef ?? r.walletAddress ?? r.address;
  if (!source) {
    throw new Error(`Missing walletRef for ${r.rpId} / ${r.credentialId}`);
  }

  const hex = normalizeHex(source);
  if (!/^0x[0-9a-fA-F]+$/.test(hex)) {
    throw new Error(`walletRef must be hex for ${r.rpId} / ${r.credentialId}: ${source}`);
  }
  if (hex.length <= 66) {
    const walletRef = `0x${hex.slice(2).padStart(64, "0")}` as Hex;
    if (/^0x0{64}$/.test(walletRef)) {
      throw new Error(`walletRef cannot be zero for ${r.rpId} / ${r.credentialId}`);
    }
    return walletRef;
  }
  if (hex.length % 2 !== 0) {
    throw new Error(`walletRef hex must have an even number of digits for ${r.rpId} / ${r.credentialId}`);
  }
  return keccak256(hex);
}

// ── Build commitment ──

function buildCommitment(r: ApiRecord, walletRef: Hex, metadata: Hex): Hex {
  const publicKey = r.publicKey.startsWith("0x")
    ? (r.publicKey as Hex)
    : (`0x${r.publicKey}` as Hex);
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("string, string, bytes32, bytes, string, string, bytes"),
      [r.rpId, r.credentialId, walletRef, publicKey, r.name, r.credentialId, metadata]
    )
  );
}

// ── Main ──

async function main() {
  const phase = process.env.PHASE || "commit";
  const account = privateKeyToAccount(PRIVATE_KEY);

  console.log(`Wallet: ${account.address}`);
  console.log(`Contract: ${CONTRACT}`);
  console.log(`Phase: ${phase}`);

  const publicClient = createPublicClient({
    chain: gnosis,
    transport: http(RPC_URL),
  });

  const walletClient = createWalletClient({
    account,
    chain: gnosis,
    transport: http(RPC_URL),
  });

  const balance = await publicClient.getBalance({ address: account.address });
  console.log(`Balance: ${Number(balance) / 1e18} ETH`);

  const records = await fetchAllRecords();

  if (phase === "commit") {
    console.log("\n── Phase 1: Commit ──\n");

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      const publicKey = r.publicKey.startsWith("0x")
        ? (r.publicKey as Hex)
        : (`0x${r.publicKey}` as Hex);
      const metadata = buildMetadata(publicKey);
      const walletRef = buildWalletRef(r);
      const commitment = buildCommitment(r, walletRef, metadata);

      // Check if already exists on-chain
      const exists = await publicClient.readContract({
        address: CONTRACT,
        abi,
        functionName: "hasRecord",
        args: [r.rpId, r.credentialId],
      });

      if (exists) {
        console.log(`[${i + 1}/${records.length}] SKIP (exists): ${r.rpId} / ${r.credentialId}`);
        continue;
      }

      const hash = await walletClient.writeContract({
        address: CONTRACT,
        abi,
        functionName: "commit",
        args: [commitment],
      });
      await publicClient.waitForTransactionReceipt({ hash });

      console.log(`[${i + 1}/${records.length}] Committed: ${r.rpId} / ${r.credentialId} → ${hash}`);
    }

    console.log("\nDone. Wait 1+ block, then run with PHASE=reveal");
  } else if (phase === "reveal") {
    console.log("\n── Phase 2: Reveal ──\n");

    for (let i = 0; i < records.length; i++) {
      const r = records[i];
      const publicKey = r.publicKey.startsWith("0x")
        ? (r.publicKey as Hex)
        : (`0x${r.publicKey}` as Hex);
      const metadata = buildMetadata(publicKey);
      const walletRef = buildWalletRef(r);

      // Check if already exists on-chain
      const exists = await publicClient.readContract({
        address: CONTRACT,
        abi,
        functionName: "hasRecord",
        args: [r.rpId, r.credentialId],
      });

      if (exists) {
        console.log(`[${i + 1}/${records.length}] SKIP (exists): ${r.rpId} / ${r.credentialId}`);
        continue;
      }

      const hash = await walletClient.writeContract({
        address: CONTRACT,
        abi,
        functionName: "createRecord",
        args: [r.rpId, r.credentialId, walletRef, publicKey, r.name, r.credentialId, metadata],
      });
      await publicClient.waitForTransactionReceipt({ hash });

      console.log(`[${i + 1}/${records.length}] Created: ${r.rpId} / ${r.credentialId} → ${hash}`);
    }

    console.log("\nMigration complete!");
  } else {
    console.error("Unknown PHASE. Use PHASE=commit or PHASE=reveal");
    process.exit(1);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
