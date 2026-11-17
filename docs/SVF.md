# SVF — the Munex verification layer

SVF is the part of Munex that lets a contract ask the chain a
question: *"has this token's evidence been certified, and does it
satisfy my profile?"* It is always on (`SVF_ACTIVATION_HEIGHT =
0`). It cannot be turned off, and no contract on the chain can
avoid it: the guard is a precompile that every contract call
passes through when it calls `requirePass()`.

This document describes the design as implemented in
`launch/v10/node.py` (v10, sha256 `6398eb39…`). The consensus
rules SVF depends on (epochs, certificates, prune floor, state
root) are stated in `consensus.md`.

Status: TESTNET CANDIDATE (2026-11-16). SVF has run with the
**test key only**. No real committee key ceremony has happened,
no independent audit has taken place, and certificate generation
refuses to run with a non-test key. Do not present SVF as
production-grade.

## 1. Why SVF exists

A maze lottery picks block producers, and every block carries
attestation evidence — which mazes were attested, at what size,
with what weight, and whether they grew. SVF turns that evidence
into something contracts can rely on: an epoch's evidence is
hashed into a root, the committee signs a certificate over that
root, and a contract's `requirePass()` checks a registered
profile against the certified epoch. The point is to make "this
token's backing was verified by the chain" a checkable on-chain
fact, rather than an off-chain claim.

## 2. Committee key and templates

- The committee is a BLS threshold group: `SVF_COMMITTEE_N =
  4` members, threshold `t` (from the key file's DKG config).
  Partial signatures from `t` members combine into one
  threshold signature verifiable against the group public key.
- The committee key and the approved template hashes are **not
  in the source**. They are loaded from a key file named by
  config `svf.key_file` (`_svf_load_key_file`). A missing,
  unreadable, or invalid file exits 1 naming the file. The key
  file must be mode 0600 — group/other readable is refused.
- **Test key.** `test = true`, `chain_id = 6621`, `test_seed`
  present (64 hex chars), and the group public key must match
  the key derived from the seed by `_svf_committee_dkg`. The
  test key is the only key that exists today. The seed lives
  only in the operator-controlled key file and is never logged;
  logs carry only the chain id, test flag, group public key,
  and template names and hashes.
- **Real key.** `test = false`, `chain_id` not 6621, **no**
  `test_seed`, and a non-empty `ceremony_record`. A real key
  file with `chain_id` 6621, or with `test_seed` present, is
  refused. The ceremony record is supposed to document a real
  multi-party ceremony. No such ceremony has happened, so no
  real key exists.
- **Templates.** `template_hashes` is a list of `{name,
  sha256}`. The only approved template in this pack is
  `direct_erc20`, sha256
  `42ef31de0b91480beda1431b9e447a39c086d343ef6d69d206d94bb71e450437`.
  A contract whose runtime code hash is not an approved
  template cannot register a profile.
- **The group public key is 96 bytes** (a valid BLS G1 point).
  Testnet group public key (unchanged across runs):
  `07a0dd8e0a14536cc01b7ddb305217bfe7eb308a9158c0d3dede401802cfaecdd68a77fca4305cf6fab3057db33483b31763aef5b1c9e90ef19c9a2f1106f5491846390c259aaf87493d644a0e32418e71b48b20612a919981131a13f1a86755`
- **Public parameters travel in the genesis.** The genesis body
  carries `svf_public` (group public key + template hashes),
  covered by the genesis identity hash. A joining node reads
  them from the genesis it receives over P2P; the producer
  (which holds the key file) writes them when it creates a new
  genesis. The test key stays on the producer only — never in
  `genesis.json`, never in any log, never on a follower. A
  follower with no key file waits for the genesis instead of
  exiting at process start; a malformed `svf_public` exits 1
  naming the field.

## 3. Profiles

A profile is a token's statement of what evidence it requires,
registered on-chain before the token can pass the guard.

- **Format.** A canonical 42-byte blob (`svf_profile_bytes`):
  magic `"MCXS"` (4 bytes) | `schema_version` uint16 (= 1) |
  `family_id` uint8 (= 1) | `sample_blocks` uint8 (1–100) |
  `min_distinct_winners` uint8 | `min_growth_blocks` uint8 |
  `min_total_attestation_weight` uint256 (32 bytes, big-endian).
- **Fields.** `sample_blocks`: how many evidence records are
  sampled. `min_distinct_winners`: how many different winners
  the sample must contain. `min_growth_blocks`: how many
  sampled blocks must show growth.
  `min_total_attestation_weight`: the minimum total attestation
  weight of the sample.
- **Registration.** `registerProfile(bytes)`, selector
  `0xb58f53b2`. The call data is the standard ABI encoding of
  a `bytes` argument: selector, offset word (32), length word,
  profile bytes, zero-padded to a 32-byte boundary.
  Registration stores the profile in `svf_profiles` with its
  hash (`svf_profile_hash(chain_id, token_address,
  profile_bytes)`), the registrant, the registration
  transaction hash and block height, an `effective_epoch`, and
  status `ACTIVE`.
- **Effective epoch.** A profile becomes effective at the epoch
  after registration. The guard refuses (`target_epoch <
  effective_epoch`) until the profile's epoch is certifiable.
- **Idempotent re-register.** Registering the *identical*
  profile for the same token succeeds (returns `0x01`) — this
  is what makes a register transaction replayable across a fork.
  Registering a *different* profile for the same token is still
  refused.
- **Example profiles.** Satisfiable (used by test token A):
  `sample_blocks=10, min_distinct_winners=2,
  min_growth_blocks=0, min_total_attestation_weight=1000`.
  Unsatisfiable (test token B, used by case (c)): the same,
  with `min_weight=10**9`.

## 4. Evidence and epoch roots

- Every sealed block contributes **one evidence record** to
  its epoch: height, block hash, winner public key, attested
  size, attestation weight, growth present, record hash
  (`SVFBlockEvidence`; stored in `svf_evidence`, keyed by
  `(epoch_id, height)`).
- An epoch is **100 blocks**. Epoch `e` covers blocks
  `e*100 … e*100+99`.
- Epoch 0 has only **99** evidence records (genesis gets
  none), so it **can never certify**. The first certifiable
  epoch is epoch 1 (blocks 100–199).
- When an epoch's 100 records are complete, its evidence root
  is computed (exactly 100 records required — 99 or 101 will
  not do) and stored in `svf_epoch_roots` with the record count
  and a `complete` flag. Evidence and roots are **never
  pruned**.

## 5. Certificates

- **Preparation.** A certificate for epoch `e` is prepared
  only when the chain is past `end + PRUNE_BLOCKS`, where
  `end` is the epoch's last block (`e*100+99`). With prune
  100, the epoch-1 certificate is first prepared at block 300.
  Preparation also requires the test key: if the key is not a
  test key, or the DKG config is absent, preparation returns
  without doing anything. There is no production certificate
  generation in this code — a real committee-signing
  arrangement would have to be built.
- **Anchor.** The certificate's anchor is the hash of the
  epoch's last block. The anchor lookup searches only the
  node's in-memory block list; if the anchor is not there, the
  certificate is skipped. Known open item: there is no
  database fallback, so it bites past 10,000 blocks
  (`BLOCK_CACHE_MAX`) or after a restart with an old anchor.
- **Signed message.** The threshold-BLS signature is over the
  canonical message `MCX-SVF-EPOCH-BEACON-V1` + version
  (uint16, 1) + chain id (uint64) + committee epoch (uint64) +
  evidence epoch (uint64) + window start (uint64) + window end
  (uint64) + anchor hash (32 bytes) + evidence root (32
  bytes). `PRUNE_BLOCKS` is deliberately not in the message:
  it is a local config value, and including it made a
  certificate signed by a prune-100 node unverifiable on a
  prune-200 node.
- **Contents.** A stored certificate (`svf_certificates`) has:
  `evidence_epoch, chain_id, committee_epoch,
  window_start_height, window_end_height, anchor_block_hash,
  evidence_root, group_public_key_id, threshold_signature,
  inclusion_block, usable_from`. A certificate carried in block
  N is usable from block N+1.
- **Verification.** A follower checks the anchor against the
  canonical block hash at the epoch-end height, the evidence
  root against the committed epoch root (never taken from the
  certificate itself), and the threshold signature against the
  group public key. Any failure rejects the block ("invalid SVF
  certificate"). The certificate is verified but **not stored**
  during verification; it is applied to the in-memory dict and
  the database only after the root check (see `consensus.md`
  section 6).
- **Proven in Run 17.** `svf_certificates = [(1, 307)]` on all
  three nodes; the epoch-1 certificate was sealed in block 307
  and its state root matched on all three nodes. A live reorg
  at height 306 succeeded with the certificate in flight.

## 6. The requirePass guard

The guard is precompile
`0x0000000000000000000000000000000000000800`
(`SVF_GUARD_ADDRESS`). Its interface, by selector (all
first-4-bytes of keccak256 of the signature, `_svf_selector`):

| Function | Selector | Returns |
|----------|----------|---------|
| `requirePass()` | `0x4514a8d5` | `0x01` pass, `0x` refuse |
| `registerProfile(bytes)` | `0xb58f53b2` | `0x01` on success |
| `profileOf(address)` | `0x2f8eb9cb` | 32-byte profile hash, or 32 zero bytes |
| `epochStatus(address,uint64)` | `0xfadbd0d3` | single `0x00` byte (stub — do not rely on it) |
| `protocolInfo()` | `0x93420cf4` | 18 bytes: version uint16 (1), activation height uint64 (0), epoch blocks uint64 (100) |

**Guard order** (`_execute_svf_guard`, requirePass branch).
This order is the whole design:

1. **Profiles first.** The guard reads `svf_profiles` for the
   calling token.
2. **No profile → approved.** If no profile row exists, the
   guard returns `(True, 0x01)` **without touching**
   `svf_evidence` or `svf_certificates`. An unregistered token
   is not gated by SVF at all.
3. **Profile exists.** The profile is parsed (unparsable →
   refuse). The target epoch is computed from a chain-global
   maturity lag: `target_epoch = (block_h - 100 - 100) // 100`.
   If the target epoch is before the profile's
   `effective_epoch`, refuse.
4. **Evidence.** Exactly 100 evidence records for the target
   epoch are required. Fewer, or a database failure, → refuse
   (fail-closed).
5. **Certificate.** The certificate row for the target epoch
   is read. A database failure → refuse. A missing certificate
   makes the profile **UNAVAILABLE**, not failed — the guard
   refuses, and `evaluate_profile` reports UNAVAILABLE.
6. **Evaluation.** `evaluate_profile` selects `sample_blocks`
   records by HMAC-SHA256 Fisher-Yates sampling and passes only
   if sampled weight ≥ `min_total_attestation_weight` **and**
   distinct winners ≥ `min_distinct_winners` **and** sampled
   growth ≥ `min_growth_blocks`. A corrupt root or an invalid
   certificate is FAIL. PASS returns `(True, 0x01)`; any other
   outcome returns `(False, b'')`.

**Return convention.** On success the guard returns one byte,
`0x01`. On refusal it returns empty (`b''`), which surfaces
through `eth_call` as `0x`. It is not a JSON-RPC error. Note
the return is a single byte, not a 32-byte ABI-encoded bool —
callers must use a low-level call and check the raw bytes (see
`SampleSVFToken.sol`).

## 7. SVF fees

SVF token operations are priced by the node, not by the sender.
The fees are hardcoded constants, enforced at mempool
admission, execution, and block verification alike — a block
whose `_fee_charged` does not match the recomputation is
rejected.

| Operation | Fee |
|-----------|-----|
| `token_create` | 500000 flat |
| `token_transfer` | 1000 + 1 per canonical byte |
| `token_burn` | 1000 + 1 per canonical byte |

The fee is charged on top of the normal gas fee
(`gas_used x gasPrice`). The schedule was live-tested in the
v9.3 red-team: a `token_create` sealed at block 24, a
`token_transfer` at block 37, and a `token_burn` at block 55,
each with the fee above.

## 8. The four guard cases

Run as T-SVF-RPC through verified `eth_*` RPC on a running
node. All four passed in Run 17; the guard code is unchanged
in v10.

| Case | Setup | `eth_call` result |
|------|-------|-------------------|
| (a) | Registered, satisfiable profile, **no certificate yet** | `0x` (refused) |
| (b) | Same token, **certificate present** — `eth_call` | `0x01` (approved) |
| (b) transfer | Same token, certificate present — a real `contract_call` transaction, sealed on-chain | Sealed: nonce 5, receipt block 318, status `0x1`, on both nodes |
| (c) | Registered, **unsatisfiable** profile (`min_weight=10**9`), certificate present | `0x` (refused) |
| (d) | **Unregistered** token, with `svf_evidence` and `svf_certificates` dropped | `0x01` (approved), with **zero** traced reads of `svf_evidence`/`svf_certificates` |

Case (d) is the proof of the guard order: because no profile
exists, the guard approves without reading the evidence or
certificate tables — proven by dropping both tables and by a
SQLite trace of the call window.

## 9. The test token

The deployed test token is a **minimal forwarder**, not a token
with logic. Its 56-byte runtime copies all calldata and
`CALL`s the guard precompile with all gas, returning the
guard's returndata on success and reverting on failure. Its
12-byte init (`6038600c60003960386000f3`) copies those 56 bytes
from offset 12 and returns them as the runtime. Deploying
requires sending init + runtime together; sending the init
alone produces a 56-zero-byte runtime. Template:
`direct_erc20`. See `SampleSVFToken.sol` for the guarded-token
pattern developers should follow.

## 10. Honest limits

- **Test key only.** Everything certified so far was signed by
  the test key. No multi-party ceremony has happened, so no
  real committee key exists, and certificate generation refuses
  to run without a test key.
- **No audit.** The consensus, wallet, and RPC code have not
  been independently audited. Every round exposed a new latent
  bug; passing the tests proves the bugs tested for are absent,
  not that the code is sound.
- **Known open items:** certificate anchor lookup with no
  database fallback (bites past 10,000 blocks);
  `minermazes.size` not restored by the reorg fix;
  balance-cleanup pruning caveat. The deploy-branch fee
  non-atomicity is fixed (v9.3); the register-idempotency fix
  is proven only by unit test.
- **External miners have sealed blocks.** The v10 tests sealed
  blocks with an unchanged external miner (block 1 at draw
  weight 91, 24 blocks in sync across two nodes). The embedded
  miner is removed in v10.
- **The v3 intent/reservation layer is unconnected by design.**
  The intent, batch-reservation, and release functions exist in
  the file but have no callers in execution, sealing, reorg,
  RPC, or P2P. Do not build on them.
- **Epoch 0 never certifies.** It has 99 evidence records, not
  100. Any design that assumes the first epoch certifies is
  wrong.
- **`epochStatus` is a stub.** It returns a single `0x00`
  byte. Do not use it to decide anything.
