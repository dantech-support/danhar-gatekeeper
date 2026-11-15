# danhar-gatekeeper

A **Proof Gatekeeper** agent for the [zkVerify Agent Games](https://agentgames.zkverify.io)
(Season 01, Proof Gatekeeper track).

The agent is a public HTTPS endpoint. The platform POSTs HMAC-signed task
envelopes describing proof-backed payment conditions; the agent answers
**APPROVE** or **REJECT** within the deadline, together with a Groth16 proof
of its decision generated locally with the official gatekeeper circuit.

**Live endpoint:** `https://danhar-gatekeeper.vercel.app/api/agent`

## How it works

1. **Authenticate** — every request is verified against
   `x-agent-games-signature` (HMAC-SHA256 over the *raw* body) before any
   JSON parsing. Bad signature → `401`.
2. **Preflight** — `agent-games.preflight.v1` envelopes get a signed
   `{ ok: true, protocolVersion: "v1" }`.
3. **Decide** — deterministic checks only (no language model near the
   decision), in the published trap-taxonomy order:
   `VK_SUBSTITUTION` → `PROOF_REUSED` → `THRESHOLD_MISMATCH` →
   `EXPIRED_CONDITION` → `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` →
   otherwise `APPROVE / VALID_CONDITION`. Fail closed on any error.
4. **Prove** — the decision is proven with snarkjs against the official
   `gatekeeper.wasm` / `gatekeeper_final.zkey` circuit; the proof and its
   13 public signals ride in the signed response. A reused-proof rejection
   carries no proof, per the event rules.
5. **(Optional)** — with a `KURIER_API_KEY`, proofs are also submitted to
   zkVerify mainnet via Kurier and the finalized transaction hash is
   returned as `proof_tx`.

## Layout

- `api/agent.js` — the whole agent (Vercel serverless function; also runs
  standalone with `node api/agent.js`).
- `circuits/` — the verification key, plus a README explaining where the
  proving artifacts come from (they are distributed by the platform, not
  stored in git).
- `vercel.json` — function config (60 s max duration, circuit files
  bundled with the function).

## Deploy

1. Import this repo in Vercel (or `vercel deploy --prod` from a checkout).
2. Download the circuit artifacts into `circuits/` first if deploying from
   a fresh clone — see `circuits/README.md`.
3. Set the environment variable `AGENT_GAMES_HMAC_SECRET` to the secret
   from the Agent Games dashboard (**Rotate Secret** on your agent), then
   redeploy.
4. Register the deployed `/api/agent` URL as the agent endpoint on the
   Agent Games dashboard and run preflight.

## Environment variables

| Name | Required | Notes |
| --- | --- | --- |
| `AGENT_GAMES_HMAC_SECRET` | Yes | Issued once by the platform dashboard. Never commit it. |
| `KURIER_API_KEY` | No | Enables on-chain proof submission via Kurier. |

MIT licensed. Built for the Agent Games; the circuit stays the referee.
