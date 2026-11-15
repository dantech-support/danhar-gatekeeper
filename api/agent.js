/**
 * danhar's Proof Gatekeeper agent — Vercel serverless deployment.
 *
 * Protocol (https://agentgames.zkverify.io/build, /events/proof-gatekeeper):
 *  - Platform POSTs signed envelopes to this endpoint (/agent).
 *  - x-agent-games-signature = HMAC-SHA256 hex of the RAW body under
 *    AGENT_GAMES_HMAC_SECRET. Verified BEFORE parsing JSON.
 *  - Preflight -> signed { ok: true, protocolVersion: "v1" }.
 *  - Task -> deterministic checks, local Groth16 proof of the decision
 *    (gatekeeper circuit via snarkjs), optional Kurier submission, signed
 *    JSON response. Fail closed: any doubt means REJECT.
 * Secrets come from environment variables only. Nothing secret is logged.
 */
"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");

const SECRET = process.env.AGENT_GAMES_HMAC_SECRET || "";
const KURIER_API_KEY = process.env.KURIER_API_KEY || "";
const KURIER_API_URL = process.env.KURIER_API_URL || "https://api.kurier.xyz/api/v1";
const VK_HASH =
  process.env.GATEKEEPER_VK_HASH ||
  "0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0";
const CIRCUITS_DIR = path.join(process.cwd(), "circuits");
const WASM = path.join(CIRCUITS_DIR, "gatekeeper.wasm");
const ZKEY = path.join(CIRCUITS_DIR, "gatekeeper_final.zkey");
const STORE_PATH = path.join(os.tmpdir(), "gatekeeper-seen.json");
const KURIER_BUDGET_MS = Number(process.env.KURIER_BUDGET_MS || 8000);

const TASK_TYPE = "agent-games.proof-gatekeeper.v1";
const PREFLIGHT_TYPE = "agent-games.preflight.v1";
const SIG_HEADER = "x-agent-games-signature";
const BN128_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// ------------------------------------------------------------ seen store
const store = { seen: new Set(), responses: new Map() };
try {
  const saved = JSON.parse(fs.readFileSync(STORE_PATH, "utf8"));
  for (const tx of saved.seen || []) store.seen.add(tx);
  for (const [k, v] of Object.entries(saved.responses || {})) store.responses.set(k, v);
} catch { /* cold start */ }
function persist() {
  try {
    fs.writeFileSync(
      STORE_PATH,
      JSON.stringify({ seen: [...store.seen], responses: Object.fromEntries(store.responses) }),
    );
  } catch (e) {
    console.error("[store] persist failed:", e.message);
  }
}

// ------------------------------------------------------------ hmac
function signBody(raw) {
  return crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
}
function verifySignature(raw, header) {
  if (!SECRET || !header) return false;
  let v = String(header).trim();
  if (v.toLowerCase().startsWith("sha256=")) v = v.slice(7).trim();
  let candidate = null;
  if (/^[0-9a-fA-F]{64}$/.test(v)) candidate = Buffer.from(v, "hex");
  else {
    try {
      const b = Buffer.from(v, "base64");
      if (b.length === 32) candidate = b;
    } catch { /* fall through */ }
  }
  if (!candidate) return false;
  const expected = crypto.createHmac("sha256", SECRET).update(raw).digest();
  return crypto.timingSafeEqual(candidate, expected);
}
function deriveSalt(taskId) {
  const digest = crypto
    .createHmac("sha256", SECRET || "gatekeeper-local-dev")
    .update(`gatekeeper-salt:${taskId}`)
    .digest();
  return BigInt("0x" + digest.toString("hex")) % BN128_PRIME;
}

// ------------------------------------------------------------ fields
function parseUint(v) {
  if (typeof v === "number") return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
  if (typeof v !== "string") return null;
  const s = v.trim();
  if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
  if (/^[0-9]+$/.test(s)) return BigInt(s);
  return null;
}
function toField(v) {
  let n;
  if (typeof v === "bigint") n = v;
  else {
    const s = String(v).trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) n = BigInt(s);
    else if (/^[0-9]+$/.test(s)) n = BigInt(s);
    else n = BigInt("0x" + crypto.createHash("sha256").update(s).digest("hex"));
  }
  return (((n % BN128_PRIME) + BN128_PRIME) % BN128_PRIME).toString(10);
}
const normHex = (v) => String(v ?? "").trim().toLowerCase();

// ------------------------------------------------------------ policy
function parseInput(input) {
  if (!input || typeof input !== "object") return null;
  const p = {
    registeredVk: input.registered_vk,
    proofVk: input.proof_vk,
    minimum: parseUint(input.minimum),
    publicBalance: parseUint(input.public_balance),
    expiryBlock: parseUint(input.expiry_block),
    currentBlock: parseUint(input.current_block),
    recipient: input.recipient,
    conditionRecipient: input.condition_recipient,
    amount: parseUint(input.amount),
    maxTransfer: parseUint(input.max_transfer),
    proofTx: input.proof_tx,
  };
  if (
    p.minimum === null || p.publicBalance === null || p.amount === null ||
    p.maxTransfer === null || p.expiryBlock === null || p.currentBlock === null
  ) return null;
  for (const k of ["registeredVk", "proofVk", "recipient", "conditionRecipient", "proofTx"]) {
    if (typeof p[k] !== "string" || !p[k]) return null;
  }
  return p;
}
function evaluate(p) {
  if (normHex(p.proofVk) !== normHex(p.registeredVk))
    return { decision: "REJECT", reason_code: "VK_SUBSTITUTION", provable: true };
  if (store.seen.has(normHex(p.proofTx)))
    return { decision: "REJECT", reason_code: "PROOF_REUSED", provable: false };
  if (p.publicBalance < p.minimum)
    return { decision: "REJECT", reason_code: "THRESHOLD_MISMATCH", provable: true };
  if (p.currentBlock >= p.expiryBlock)
    return { decision: "REJECT", reason_code: "EXPIRED_CONDITION", provable: true };
  if (normHex(p.recipient) !== normHex(p.conditionRecipient))
    return { decision: "REJECT", reason_code: "RECIPIENT_MISMATCH", provable: true };
  if (p.amount > p.maxTransfer)
    return { decision: "REJECT", reason_code: "AMOUNT_OVERFLOW", provable: true };
  return { decision: "APPROVE", reason_code: "VALID_CONDITION", provable: true };
}
function buildCircuitInputs(task, p, decision) {
  return {
    taskId: toField(task.task_id),
    registeredVkHash: toField(p.registeredVk),
    proofVkHash: toField(p.proofVk),
    minimum: p.minimum.toString(10),
    publicBalance: p.publicBalance.toString(10),
    expiryBlock: p.expiryBlock.toString(10),
    currentBlock: p.currentBlock.toString(10),
    recipient: toField(p.recipient),
    conditionRecipient: toField(p.conditionRecipient),
    amount: p.amount.toString(10),
    maxTransfer: p.maxTransfer.toString(10),
    decision: decision === "APPROVE" ? "1" : "0",
    salt: deriveSalt(task.task_id).toString(10),
  };
}

// ------------------------------------------------------------ kurier
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function submitToKurier(proof, publicSignals, budgetMs) {
  if (!KURIER_API_KEY) return null;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const res = await fetch(`${KURIER_API_URL}/submit-proof/${KURIER_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: VK_HASH },
      }),
    });
    if (!res.ok) {
      console.error("[kurier] submit HTTP", res.status);
      return null;
    }
    const job = await res.json();
    if (!job.jobId) return null;
    while (Date.now() < deadline) {
      await sleep(Math.min(2500, Math.max(0, deadline - Date.now())));
      const sres = await fetch(`${KURIER_API_URL}/job-status/${KURIER_API_KEY}/${job.jobId}`);
      if (!sres.ok) continue;
      const s = await sres.json();
      const txHash = s.txHash ?? s.transactionInfo?.txHash;
      if (s.status === "Failed") return null;
      if (txHash) return txHash;
    }
    return null;
  } catch (e) {
    console.error("[kurier] error:", e.message);
    return null;
  }
}

// ------------------------------------------------------------ handler
function sendJson(res, status, body, signature) {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  if (signature) res.setHeader(SIG_HEADER, signature);
  res.end(body);
}
const signedSend = (res, status, obj) => {
  const body = JSON.stringify(obj);
  sendJson(res, status, body, signBody(body));
};

async function handleTask(task, res) {
  if (task.task_id && store.responses.has(task.task_id)) {
    const body = store.responses.get(task.task_id);
    return sendJson(res, 200, body, signBody(body));
  }
  const p = parseInput(task.input);
  if (!p || !task.task_id) return signedSend(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });

  const ev = evaluate(p);
  const response = { decision: ev.decision, reason_code: ev.reason_code };

  if (ev.provable) {
    try {
      const inputs = buildCircuitInputs(task, p, ev.decision);
      const { proof, publicSignals } = await snarkjs.groth16.fullProve(inputs, WASM, ZKEY);
      response.proof = proof;
      response.public_signals = publicSignals;
      const txHash = await submitToKurier(proof, publicSignals, KURIER_BUDGET_MS);
      response.proof_tx = txHash || p.proofTx;
    } catch (e) {
      console.error("[agent] proving failed:", e.message);
      return signedSend(res, 200, {
        decision: "REJECT",
        reason_code: ev.decision === "APPROVE" ? "INVALID_TASK" : ev.reason_code,
        proof_tx: p.proofTx,
      });
    }
  } else {
    response.proof_tx = p.proofTx;
  }

  const body = JSON.stringify(response);
  store.seen.add(normHex(p.proofTx));
  store.responses.set(task.task_id, body);
  persist();
  sendJson(res, 200, body, signBody(body));
}

async function handler(req, res) {
  if (req.method === "GET") {
    return sendJson(res, 200, JSON.stringify({ ok: true, protocolVersion: "v1", agent: "danhar-gatekeeper" }), null);
  }
  if (req.method !== "POST") return sendJson(res, 405, JSON.stringify({ error: "method_not_allowed" }), null);

  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks);

  if (!SECRET) return sendJson(res, 500, JSON.stringify({ error: "server_misconfigured" }), null);
  if (!verifySignature(raw, req.headers[SIG_HEADER])) {
    return sendJson(res, 401, JSON.stringify({ error: "invalid_signature" }), null);
  }
  let envelope;
  try {
    envelope = JSON.parse(raw.toString("utf8"));
  } catch {
    return signedSend(res, 400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  if (envelope.type === PREFLIGHT_TYPE) {
    return signedSend(res, 200, { ok: true, protocolVersion: "v1" });
  }
  if (envelope.type !== TASK_TYPE) {
    return signedSend(res, 400, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
  try {
    await handleTask(envelope, res);
  } catch (e) {
    console.error("[agent] task error:", e.message);
    signedSend(res, 200, { decision: "REJECT", reason_code: "INVALID_TASK" });
  }
}

module.exports = handler;

// Standalone mode for local smoke tests: `node api/agent.js`
if (require.main === module) {
  const http = require("http");
  const port = Number(process.env.PORT || 8792);
  http.createServer((req, res) => { handler(req, res); }).listen(port, () => {
    console.log(`[agent] standalone on :${port}`);
  });
}
