# Munex consensus rules

This document states the consensus rules of the Munex testnet
(chain 6621) as implemented in `launch/v10/node.py` (v10, sha256
`6398eb39…`, genesis pin `4aa436a1…`). v10 is a consensus change:
it needs a FRESH genesis; a v9.3 chain does not carry over.

Status: TESTNET CANDIDATE (2026-11-16). These rules are the rules
of a testnet. They have not been independently audited.

Where a rule is a *fixed* rule — one that must not change without
a new genesis and a new test round — it is marked **FIXED**.
Function and constant names are given so every rule can be found
in the node file by search; line numbers are deliberately not
used, because they move.

## 1. Chain identity

- Chain id **6621** (testnet). `CHAIN_ID = 6621`.
- SVF is always on: `SVF_ACTIVATION_HEIGHT = 0`. **FIXED.**
- Genesis is identified by its identity hash over
  `GENESIS_IDENTITY_FIELDS`, which includes `svf_public` (the
  SVF group public key and the approved template hashes). A
  joining node with no expected-genesis pin refuses to join
  (exit 1).
- Blocks are numbered from genesis (height 0). A block is
  identified by its hash.

## 2. Proof of Spatial Work — the lottery

PoSW is the block-producer selection rule. A miner proves work by
playing a maze: it moves through a 3D maze, catches the goal to
grow the maze, and the maze slowly shrinks back over time
(ghost shrink). The bigger the maze, the more weight it carries
in the lottery. Mining is open: anyone can join, and there is no
maximum maze size.

### 2.1 Candidates and weight — FIXED

- **Candidates.** Every attested maze over size 5 the producer
  knows about is a candidate. A maze at or under 5x5x5 is never
  a candidate: 5x5x5 is the default starting size, and it is
  subtracted from the weight, so a size-5 maze has weight 0. A
  maze can shrink back to 5x5x5 and become ineligible.
- **Weight.** Each candidate's weight is `size^3 - 125`
  (`_maze_att_weight`): size 5 has weight 0, size 6 has weight
  91, size 7 has weight 218. The lottery is **global**: the
  winner is picked across all miners' candidates, not per miner.

### 2.2 The draw — FIXED

- The winner is drawn with probability `P = weight / total
  weight`, using a deterministic weighted ordering (repeated
  draws reusing `_maze_ticket` with a per-rank domain
  separator, integer arithmetic only).
- The ticket is `T = int(keccak256(previous_block_hash ||
  height || timestamp || maze_id))` (`_maze_ticket`). The ticket
  binds the block's own proposed timestamp, so every retry is a
  fresh draw while remaining fully deterministic: every verifier
  recomputes it from the sealed block.
- One eligible miner wins 100% of the time. Two miners at sizes
  6 and 7 win with probability 91/309 (~29%) and 218/309
  (~71%).
- **Verification.** A follower recomputes the draw from the
  block's sealed `lottery_draw` (candidates, rank, winner
  index, takeover flag) and rejects the block if the draw does
  not reproduce. The draw is not taken on trust.

### 2.3 Rank and takeover

- The winner is normally the first draw (rank 0). If the rank-0
  winner's host is absent or behind, the rank climbs with
  elapsed time: `rank = min((elapsed - BLOCK_TIME) //
  SLOT_TIMEOUT, len(passing) - 1)`, with `BLOCK_TIME = 50` and
  `SLOT_TIMEOUT = 30` (default), so another candidate can take
  over. This is the liveness/takeover rule, not a second
  lottery.

### 2.4 The missed-round model (v10) — FIXED

- A block needs a lottery candidate. When there is no eligible
  candidate (all mazes at or below 5x5x5, or no miners at all),
  **no block seals**. The producer logs `[MISSED]` once per
  50-second cycle and waits for the next cycle. The chain does
  not move without a miner.
- A block with `lottery_draw` set to `None` is rejected by
  verification. There is no no-lottery block in v10; the v9.3
  fallback is removed.
- A size-5 maze never wins any lottery, not even alone; a
  size-5 maze beside a size-6 maze never wins (the size-6 maze
  always wins).

### 2.5 The winner must sign — FIXED

- A block seals only when the winning miner signs it. The
  producer sends the unsigned block to the winner over its
  WebSocket connection and waits up to 60 seconds for the
  signed block back. If the winner does not sign in time, the
  block is skipped (and the winner is slashed for the refusal).
  There is no fallback in which the node signs the block itself.
- **The node can never be a miner.** The embedded miner is
  removed in v10: a node never registers as a miner, never
  wins, and never self-signs. A config that still sets
  `embedded_miner` logs a warning once and is ignored.
- **Verification.** Every follower checks that the block's
  signature verifies against `producer_pub`, and that
  `producer_pub` equals both the attestation public key and the
  winner's registered block-signing key. A signature made with
  any other key — including the producer node's own key — is
  rejected. The node does not hold the winner's private key, so
  it cannot produce a valid signature for a block it sealed
  alone.
- The only self-signed block in the chain is the genesis block
  (block 0), written by the node when the chain is created,
  before any miner exists. It is the starting point, not a
  sealed block, and it cannot be used to seal any later block.

### 2.6 Reward — FIXED

- The block reward is `INITIAL_BLOCK_REWARD = 1,000,000`
  (1 MCX) at the genesis era, paid to the winning miner's
  wallet, plus the block's transaction fees. It halves every
  `HALVING_INTERVAL = 2,522,880` blocks.
- Genesis allocates 200 MCX. The hard cap is 5,045,958 MCX.
- A block's `reward_wallet` is the winner's wallet. Only miners
  mint.

## 3. Block format and proof keys — FIXED

A block's proof is verified over `_BLOCK_PROOF_KEYS`:

```
winner, producer_pub, signature, state_root, transactions,
maze_attestation, reward_wallet, maze_updates, attestation_proof,
global_shrink_factor, slashes, maze_state, svf_epoch_certificates,
lottery_draw
```

- `maze_state` is in the block and covered by the proof.
- `lottery_draw` carries the draw (candidates, rank, winner
  index, takeover flag) so a follower can recompute it.
- `svf_epoch_certificates` carries at most the certificates
  the block seals (see section 11).

## 4. Timestamp rule — FIXED

`M < T <= M + 7200`, where `M` is the median of the up to 11
most recent block timestamps and `T` is the candidate block's
timestamp (`BLOCK_TIME_WINDOW_MAX = 7200`).

- **Validity reads no clock.** The check uses only sealed block
  timestamps. A block whose timestamp is outside the window is
  invalid, whenever it arrives.
- **Producer stamping.** The producer stamps
  `T = clamp(now, M + 1, M + 7200)`.
- **Drift.** If a node's wall clock drifts far from the chain,
  the node logs a `[TIME-DRIFT]` WARNING (log-only, once per
  process). Drift never changes validity.

## 5. Attestation and catch proofs — FIXED

- **Attestation gate.** A block's attestation size above
  `MIN_MAZE_SIZE + ATTEST_FRESH_BUFFER` (5 + 5 = 10) must be
  backed by a proven catch: an entry in the block's own
  `maze_updates` or `attestation_proof` with `new_size` equal
  to the attested size, or a reorg base, or a local
  `maze_attestations` row with `last_size >= attested_size`.
  Otherwise the block is rejected.
- **Check A (growth without a catch proof).** Every
  `maze_updates` entry that grows a maze past its live size
  must carry `caught_at_nonce`. A block growing a maze
  `(5 -> N)` with no catch proof is rejected.
- **Proof retention.** Catch proofs are retained per (maze,
  size) in the never-pruned `maze_proofs` table, and the
  producer stores its own sealed blocks' proofs on seal.
  `maze_attestations` is never pruned.
- **Attestation proofs are not state.** `attestation_proof` is
  carried in the block and replay-validated, but it is not
  applied to state and is not in the state-root formula.
- **Maze floor.** `MIN_MAZE_SIZE = 5`. Block validity requires
  the attested size to be at least 5; lottery eligibility
  requires it to be strictly greater than 5.

## 6. State root — FIXED

The state root is a pure function (`_state_root_from_snapshot`)
of a snapshot built by `_state_snapshot_for_block`. Snapshot
sections:

| Prefix | Contents |
|--------|----------|
| `height:{id}` | block height |
| `bal:{wallet}` | MCX balances |
| `tok:{token}:{wallet}` | token balances |
| `cst:{contract}:{key}`, `cst2:{contract}:{key}` | contract storage |
| `htlc:{id}` | HTLC contracts |
| `maze:{maze_id}` | committed maze columns |
| `toki:{address}` | token info |
| `conv:{address}` | contracts (owner, code hash) |
| `mazeatt:{maze_id}` | maze attestations |
| `svfreg:{token}` | registered SVF profiles |
| `svfepoch:{epoch}` | SVF epoch roots |
| `svfcert:{epoch}` | SVF certificates |

Two ordering facts, both load-bearing:

- **Block N's root commits to attestation state as of N−1.**
- **Certificate ordering.** The producer computes the root
  *before* a newly prepared certificate enters its in-memory
  certificate dict, so the declared root has no
  `svfcert:{epoch}` for the block's own certificate. The
  follower therefore verifies the carried certificate but does
  **not** store it during verification; `_append_block` applies
  it to the dict and the database only **after** the root
  check. Storing it earlier makes the follower's post-apply
  root differ from the producer's.

## 7. Gas and fees — FIXED

The gas model is Ethereum's: intrinsic 21000 + calldata 4/16
per byte (zero/non-zero) + 32000 create + 200/byte code
deposit; VM gas costs are pre-Berlin. The fee is
`gas_used x gasPrice`.

- `--gas` is a **cap only**. The transaction fee field is the
  maximum; the sender is charged for gas actually used, and
  the unused part is refunded. A failed transaction is excluded
  from the block and its fee is refunded.
- There is no per-transaction gas cap and no minimum fee.
  `gasPrice` is sender-chosen, including 0. The default
  gas price is 1 and the default gas cap is 100000.
- `MAX_BLOCK_GAS = 10,000,000`. `MAX_BLOCK_TXS = 1000`.
- **SVF fees are hardcoded and node-computed**, not
  sender-chosen: `token_create` 500000 flat;
  `token_transfer` and `token_burn` 1000 + 1 per canonical
  byte. The producer, the executor, and the verifier all
  recompute them; a block whose `_fee_charged` or `_gas_used`
  does not match the recomputation is rejected.
- The constants are bound in the genesis ruleset (v12), so a
  node running different constants cannot join the chain.

## 8. Transactions and nonces — FIXED in intent

- Transactions are checked read-only on mempool admission and
  executed exactly once when sealed into a block.
- The next nonce for a wallet is `max(database, mempool
  confirmed nonces, durable account_nonces table)`. The
  `account_nonces` table is never pruned, is updated on seal
  and import, and is rolled back on reorg — so a restarted node
  reports the correct nonce even when its transaction history
  is pruned.

## 9. Reorgs — FIXED in intent

- A reorg rolls back local blocks above the common height and
  adopts the peer chain when the peer chain is heavier.
- **Reorgs deeper than `PRUNE_BLOCKS` are refused** before any
  state is touched.
- New blocks are **pre-verified** against ancestor attestation
  state before any rollback; a failed pre-verify aborts with
  all state untouched.
- VM state (storage, balances, token balances) is reverted
  from the contract execution journal; MCX and token-balance
  debits are signed deltas settled at the end, not
  order-dependent subtractions.
- Checkpoints are **advisory, not a veto**: a reorg whose fork
  point is below the last checkpoint still heals by weight.
- A final cumulative gate (inside the same transaction) checks:
  adopted blocks are parent-linked from the anchor and present
  hash-equal in the block store; tip height/hash are mirrored;
  `total_minted` is conserved (pre − rewound orphan mint +
  adopted mint, single-sourced formula); and each adopted
  block's persisted transaction set equals its sealed
  `tx_hashes`.
- **Known gaps (open).** `minermazes.size` is not among the
  restored columns; the zero-balance delete checks the pruned
  `transactions` table, so it can wrongly delete a zero-balance
  wallet whose pre-fork transactions are all pruned (bounded by
  the prune window); full state-root re-derivation from the
  common point and `burned_total` conservation are still
  deferred.

## 10. Pruning and the prune floor — FIXED in intent

- `consensus.prune_blocks` must be an integer in **[100,
  10^9]** (default 10000). The deployment uses 100.
- Pruning deletes `blocks` and `transactions` rows older than
  the window. It never deletes `transaction_receipts`,
  `contract_v2`, `svf_evidence`, `svf_certificates`,
  `maze_attestations`, `maze_proofs`, or the durable
  `account_nonces` table.
- **Prune floor.** Pruning must never delete a block that is
  (i) an anchor referenced by a certificate the chain still
  needs, or (ii) a proof source for an epoch not yet certified
  (`_prune_floor`). The floor is the start (`epoch * 100`) of
  the earliest epoch that can still certify and has no
  certificate stored. Epoch 0 is never protected (it has only
  99 evidence records and can never certify). Once an epoch's
  certificate is stored, it stops protecting its blocks.
- **Fail-closed.** The floor is computed from the durable
  database tables, never from volatile in-memory state. If
  either database read fails, or the evidence query returns no
  rows while the chain is past height 100, the floor is **0** —
  protect everything, delete nothing this cycle. Only when the
  reads succeed and genuinely no epoch needs protection does
  the floor return `None`.
- **`prune_blocks` itself is not consensus.** It is excluded
  from the genesis ruleset comparison: nodes with different
  prune windows run on the same chain. What *is* consensus is
  that validity never reads pruned history — and every rule
  that once did (attestation proofs, certificate anchors, guard
  maturity) was fixed to use carried proofs, the prune floor,
  or a chain-global constant instead.

## 11. SVF, in brief

SVF is the chain's built-in verification layer. It is always on
and it is described in full in `SVF.md`. The rules a consensus
reader needs:

- **Epochs.** One epoch is 100 blocks (`SVF_EPOCH_BLOCKS =
  100`). Epoch `e` covers blocks `e*100 … e*100+99`. Epoch 0
  has only 99 evidence records (genesis gets none) and **can
  never certify**. The first certifiable epoch is epoch 1
  (blocks 100–199).
- **Preparation timing.** A certificate for epoch `e` is
  prepared only when `block_id > (e*100 + 99) + PRUNE_BLOCKS`
  — the epoch has ended *and* a full prune window has passed.
  With prune 100 the epoch-1 certificate is first prepared at
  block 300. Preparation refuses to run unless the node holds
  the test key: there is no production certificate generation
  in this code.
- **Anchor.** The certificate's anchor is the hash of the
  epoch's last block (height `e*100+99`). The anchor lookup
  searches only the node's in-memory block list; if it is
  absent the certificate is skipped. (Known open item: no
  database fallback — it bites only past 10,000 blocks,
  `BLOCK_CACHE_MAX`, or after a restart with an old anchor.)
- **Signed message.** The threshold-BLS signature is over the
  canonical message `MCX-SVF-EPOCH-BEACON-V1` + version
  (uint16 1) + chain id + committee epoch + evidence epoch +
  window start + window end + anchor hash + evidence root.
  `PRUNE_BLOCKS` is deliberately **not** part of the signed
  message: it is a local config value, and including it made a
  certificate signed by a prune-100 node unverifiable on a
  prune-200 node.
- **Verification.** A follower carrying a certificate checks,
  in order: the anchor equals the canonical block hash at the
  epoch-end height; the evidence root equals the committed
  epoch root (never taken from the certificate itself); the
  threshold signature verifies against the group public key.
  Any failure rejects the block.
- **Storage.** A carried certificate is stored in
  `svf_certificates` with columns `evidence_epoch, chain_id,
  committee_epoch, window_start_height, window_end_height,
  anchor_block_hash, evidence_root, group_public_key_id,
  threshold_signature, inclusion_block, usable_from`. A
  certificate in block N is usable from block N+1.
- **Maturity (guard side).** `requirePass` targets epoch
  `(block_h - 100 - 100) // 100` — a chain-global lag of 100.
  The local `PRUNE_BLOCKS` must not and does not enter this
  computation.

## 12. What is NOT consensus

- `BLOCK_TIME = 50` is seal pacing only. It is not in the
  effective consensus ruleset.
- The `prune_blocks` value itself (100 vs 200) — see
  section 10.
- The `global_shrink_factor` value: it is sealed in every
  block and adopted verbatim; it is data, not a rule change.
- Log lines, warnings, and the monitor. A `[TIME-DRIFT]`
  warning never changes validity.

## Fixed rules (summary)

SVF always on. Committee key and templates only from the key
file named by `svf.key_file` (missing/unreadable/invalid →
exit 1 naming the file). Open mining. Global per-maze
proportional lottery (weight = size^3 - 125; only mazes above
5x5x5 eligible). No block seals without an eligible miner;
the chain logs `[MISSED]` and waits. The winning miner must
sign the block; the node can never be a miner and never
self-signs. Maze floor strictly greater than 5 for lottery
eligibility; block validity requires attestation size >= 5.
Timestamp `M < T <= M + 7200` with no clock in validity.
`maze_state` in blocks. Wallet and RPC-token rules (see
`MUNEX.md`). Cloud-sync WARNING kept for data dirs inside
OneDrive/Dropbox/Google Drive. No maximum maze size and no
validator restriction. The v3 intent/reservation layer stays
unconnected to execution, sealing, reorg, RPC, and P2P.
