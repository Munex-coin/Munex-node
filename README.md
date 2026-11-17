# Munex-node

The Munex node, v10 (TESTNET CANDIDATE), for the Munex testnet
(chain 6621). The node keeps the chain, seals blocks won by miners,
runs the contract VM, and enforces SVF.

## What is inside

- `node/` — the node code, in two forms of the same v10 code:
  - `node.py` — the standalone single file
  - the same code split into modules (for example `main.py`,
    `P2P.py`, `svf.py`)
- Documentation lives in the [Munex-docs](https://github.com/Munex-coin/Munex-docs) repository:
  - `consensus.md` — the consensus rules (Proof of Spatial Work)
  - `SVF.md` — the SVF verification layer in full

## The chain in brief

Blocks are won by a maze lottery (Proof of Spatial Work): only mazes
above 5x5x5 are eligible, weight is size^3 − 125, a block seals
every 50 seconds only when an eligible miner exists, and the winning
miner must sign the block — a node never seals a block alone. The
block reward is 1 MCX; the hard cap is 5,045,958 MCX; the reward
halves every 2,522,880 blocks. SVF is always on. See
[consensus.md](https://github.com/Munex-coin/Munex-docs/blob/main/consensus.md) and [SVF.md](https://github.com/Munex-coin/Munex-docs/blob/main/SVF.md) for the full rules.

## Running a node

First node (the seed machine), in the `node/` folder:

```
python node.py --allow-new-genesis
```

The first run creates the genesis. Followers copy `genesis.json`
from the seed machine into the `node/` folder and run without the
flag:

```
python node.py
```

## Status

Testnet software (chain 6621). TESTNET CANDIDATE. It has not been
independently audited. See [NOTICE.md](NOTICE.md).

## Related repositories

- [Miner-codes](https://github.com/Munex-coin/Miner-codes) — miners
- [Munex-API](https://github.com/Munex-coin/Munex-API) — developer API scripts
- [Munex-docs](https://github.com/Munex-coin/Munex-docs) — consensus rules, SVF, and the sample contract
