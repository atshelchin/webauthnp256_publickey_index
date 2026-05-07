import {
  createWalletClient,
  createPublicClient,
  http,
  encodeAbiParameters,
  parseAbiParameters,
  keccak256,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { gnosis } from "viem/chains";

// ── Config ──

const PRIVATE_KEY = process.env.PRIVATE_KEY as Hex;
if (!PRIVATE_KEY) throw new Error("PRIVATE_KEY env required");

const RPC_URL = process.env.RPC_URL || "https://rpc.gnosischain.com";
const CONTRACT = "0xc1f7Ef155a0ee1B48edbbB5195608e336ae6542b" as const;
const API_BASE = "https://webauthnp256-publickey-index.biubiu.tools";

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

// ── Build commitment ──

function buildCommitment(r: ApiRecord, metadata: Hex): Hex {
  const publicKey = r.publicKey.startsWith("0x")
    ? (r.publicKey as Hex)
    : (`0x${r.publicKey}` as Hex);
  return keccak256(
    encodeAbiParameters(
      parseAbiParameters("string, string, bytes, string, string, bytes"),
      [r.rpId, r.credentialId, publicKey, r.name, r.credentialId, metadata]
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
      const commitment = buildCommitment(r, metadata);

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
        args: [r.rpId, r.credentialId, publicKey, r.name, r.credentialId, metadata],
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
