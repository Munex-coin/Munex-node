#!/usr/bin/env python3
"""repair_chain.py — diagnose and repair a Munex chain whose stored block hash
no longer matches the block's fields (the "[Integrity] Block N hash mismatch"
that stops the node on restart).

What it does
------------
1. Runs the same integrity check the node runs at startup (last 100 blocks):
   recompute each block's hash from its stored fields and compare to the
   stored hash. Finds the FIRST bad block.
2. Diagnoses the bad block: checks whether the proof JSON is corrupt, and
   tries omitting each hash-relevant field one at a time to see if the stored
   hash was computed without that field (a field added after sealing).
3. Backs the database up, then repairs by recomputing the hash chain from the
   bad block onward: the bad block's stored hash is set to the hash of its
   CURRENT fields, and every later block gets its parent hash updated to the
   new hash and its own hash recomputed. Block CONTENTS (transactions,
   rewards, maze states, balances) are NOT touched, so no mining history or
   balance is lost. Only hash values change.
4. Re-runs the integrity check to prove the repair.

Usage (run in the folder that holds microcore.db, with the node STOPPED):
    python repair_chain.py
    python repair_chain.py C:\\path\\to\\microcore.db
    python repair_chain.py --yes        (skip the confirmation prompt)

Only the Python standard library is used. The node must be stopped while
this runs, or the database file may be locked / change under it.
"""

import hashlib
import json
import os
import shutil
import sqlite3
import sys
import time

EXCLUDED_FIELDS = {"hash", "signature", "pqc_signature", "finalized"}
PROOF_KEYS = {
    "winner", "producer_pub", "signature", "state_root", "transactions",
    "maze_attestation", "reward_wallet", "maze_updates", "attestation_proof",
    "global_shrink_factor", "slashes", "maze_state", "svf_epoch_certificates",
    "lottery_draw",
}


def canonical_json_bytes(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_block_hash(block):
    unsigned = {k: v for k, v in block.items() if k not in EXCLUDED_FIELDS}
    return hashlib.sha256(canonical_json_bytes(unsigned)).hexdigest()


def unpack_block(row):
    """Rebuild a block dict from a DB row, exactly like the node's BlockRepo."""
    d = dict(row)
    d["miners"] = d["miners"].split(",") if d.get("miners") else []
    d["tx_hashes"] = json.loads(d["tx_hashes"]) if d.get("tx_hashes") else []
    proof = d.get("proof")
    proof_ok = True
    if proof:
        if isinstance(proof, str):
            try:
                proof = json.loads(proof)
            except Exception:
                proof = {}
                proof_ok = False
        if isinstance(proof, dict):
            for k, v in proof.items():
                if k in PROOF_KEYS:
                    d[k] = v
    if "proof" in d:
        del d["proof"]
    return d, proof_ok


def integrity_check(conn, depth=100):
    """Return (bad_block_id, bad_row, diagnosis) for the first bad block,
    or (None, None, None) if the last `depth` blocks are all consistent."""
    latest = conn.execute("SELECT * FROM blocks ORDER BY id DESC LIMIT 1").fetchone()
    if latest is None:
        return None, None, "no blocks in database"
    end = latest["id"]
    start = max(0, end - depth)
    rows = conn.execute(
        "SELECT * FROM blocks WHERE id >= ? AND id <= ? ORDER BY id LIMIT ?",
        (start, end, depth + 1),
    ).fetchall()
    prev_hash = None
    for row in rows:
        block, proof_ok = unpack_block(row)
        bid = block.get("id", 0)
        if bid <= 0:
            prev_hash = block.get("hash", "")
            continue
        expected = calculate_block_hash(block)
        if block.get("hash") != expected:
            return bid, row, ("proof_corrupt" if not proof_ok else "hash_mismatch")
        if prev_hash is not None and block.get("phash") != prev_hash:
            return bid, row, "parent_mismatch"
        prev_hash = block.get("hash", "")
    return None, None, None


def diagnose_field(conn, bad_id, row):
    """Try omitting each hash-relevant field: if omitting field X makes the
    recomputed hash equal the stored hash, the stored hash was computed
    WITHOUT X, i.e. X was added to the block after it was sealed."""
    block, _ = unpack_block(row)
    stored = block.get("hash")
    stripped = {k: v for k, v in block.items() if k not in EXCLUDED_FIELDS}
    for field in sorted(stripped.keys()):
        trial = {k: v for k, v in stripped.items() if k != field}
        if hashlib.sha256(canonical_json_bytes(trial)).hexdigest() == stored:
            return field
    return None


def main():
    db_path = "microcore.db"
    auto_yes = False
    for arg in sys.argv[1:]:
        if arg in ("--yes", "-y"):
            auto_yes = True
        elif arg.startswith("--"):
            print(f"unknown option: {arg}")
            return 2
        else:
            db_path = arg
    if not os.path.isfile(db_path):
        print(f"ERROR: database not found: {db_path}")
        print("Run this in the folder that holds microcore.db, or pass its path.")
        return 2

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    print(f"Database: {os.path.abspath(db_path)}")
    n_blocks = conn.execute("SELECT COUNT(*) FROM blocks").fetchone()[0]
    latest = conn.execute("SELECT id FROM blocks ORDER BY id DESC LIMIT 1").fetchone()
    print(f"Blocks: {n_blocks}, latest id: {latest[0] if latest else None}")

    bad_id, bad_row, reason = integrity_check(conn)
    if bad_id is None:
        print("Integrity check: OK — no bad block in the last 100 blocks.")
        conn.close()
        return 0

    print(f"\nFirst bad block: {bad_id} (reason: {reason})")
    block, proof_ok = unpack_block(bad_row)
    print(f"  stored hash:     {block.get('hash')}")
    print(f"  recomputed hash: {calculate_block_hash(block)}")
    print(f"  proof JSON parses: {proof_ok}")
    if not proof_ok:
        print("  The block's proof data is corrupt/unparseable, so its maze_state,")
        print("  lottery_draw and other proof fields are LOST from the database.")
        print("  This script cannot rebuild them. Do NOT use the hash repair;")
        print("  the chain must be rewound to before this block instead.")
        conn.close()
        return 3
    culprit = diagnose_field(conn, bad_id, bad_row)
    if culprit:
        print(f"  Diagnosis: the stored hash was computed WITHOUT the field "
              f"'{culprit}' — it was added to the block after sealing.")
    else:
        print("  Diagnosis: no single field explains the mismatch — a field VALUE")
        print("  changed after sealing (or several fields did). The current field")
        print("  values are kept; only the hash chain is recomputed.")
    print(f"  Blocks from {bad_id} to the tip will get new hashes; their contents")
    print("  (transactions, rewards, maze states) are NOT changed, so no balance")
    print("  or mining history is lost. Followers re-sync from the new tip hash.")

    if not auto_yes:
        answer = input("\nRepair by recomputing the hash chain from block "
                       f"{bad_id} onward? (y/n): ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted — nothing changed.")
            conn.close()
            return 0

    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = f"{db_path}.bak.{stamp}"
    conn.close()
    shutil.copy2(db_path, backup)
    print(f"Backup written: {backup}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM blocks WHERE id >= ? ORDER BY id", (bad_id,)
    ).fetchall()
    prev_hash = None
    if bad_id > 0:
        parent = conn.execute(
            "SELECT hash FROM blocks WHERE id = ?", (bad_id - 1,)
        ).fetchone()
        prev_hash = parent["hash"] if parent else None
    changed = 0
    for row in rows:
        block, _ = unpack_block(row)
        bid = block["id"]
        if bid > bad_id:
            block["phash"] = prev_hash
        new_hash = calculate_block_hash(block)
        old_hash = block.get("hash")
        conn.execute(
            "UPDATE blocks SET phash = ?, hash = ? WHERE id = ?",
            (block.get("phash"), new_hash, bid),
        )
        conn.execute(
            "UPDATE signed_blocks SET block_hash = ? WHERE block_id = ?",
            (new_hash, bid),
        )
        if new_hash != old_hash:
            changed += 1
        prev_hash = new_hash
    conn.commit()

    bad_id2, _, reason2 = integrity_check(conn)
    if bad_id2 is None:
        print(f"\nRepair complete: {changed} block hash(es) updated "
              f"({bad_id}..{rows[-1]['id']}).")
        print("Integrity check now: OK.")
        print("Start the node again — it should load the chain and keep going.")
        conn.close()
        return 0
    print(f"\nRepair FAILED: block {bad_id2} still bad ({reason2}).")
    print(f"Restore the backup: copy {backup} back over {db_path}.")
    conn.close()
    return 1


if __name__ == "__main__":
    sys.exit(main())
