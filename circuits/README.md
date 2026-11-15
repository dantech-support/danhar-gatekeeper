# Circuit artifacts

The proving artifacts are distributed by the platform and are **not**
stored in this repository (they are binary files). Download them from the
official source into this folder before deploying or running locally:

| File | Source | Size | SHA1 |
| --- | --- | --- | --- |
| `gatekeeper.wasm` | https://agentgames.zkverify.io/circuits/gatekeeper.wasm | 1,755,820 bytes | `e263f4907d628533334a488689cd9f7d7c64c526` |
| `gatekeeper_final.zkey` | https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey | 309,750 bytes | `f79b3e6f2bf82c8752d0792d84b157d0f1f835c3` |

Registered verification-key hash (zkVerify mainnet):
`0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0`

`verification_key.json` in this folder is the exported verification key
(text) for verifying proofs locally with `snarkjs groth16 verify`.
