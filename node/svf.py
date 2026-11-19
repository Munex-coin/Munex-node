import bootstrap
import crypto
import maze
import svf_keys
SVF_ACTIVATION_HEIGHT = 0
_DB_FAILED = object()
SVP_VERSION = 1
SVP_MODES = ('standard_l1', 'spatial_per_transfer', 'spatial_batch', 'hybrid')
SVP_FAMILIES = ('none', 'path_length_band', 'turn_count_band')
SVP_FIELDS = ('batch_max', 'difficulty_max', 'difficulty_min', 'evidence_threshold', 'family', 'fallback', 'min_distinct_miners', 'mode', 'version', 'window_blocks')
SVP_CAPS = {'difficulty': (1, 8), 'evidence_threshold': (1, 16), 'min_distinct_miners': (1, 16), 'window_blocks': (1, 200), 'batch_max': (1, 1000)}
SVP_HASH_DOMAIN = b'MCX-SVP-v1'
SVF_COMMIT_DOMAIN = b'MCX-SVF-COMMIT-v1'

class SVPError(ValueError):
    pass

def _svp_reject_duplicate_keys(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise SVPError(f'duplicate field: {k}')
        out[k] = v
    return out

def _svp_reject_float(_text):
    raise SVPError('floats are not allowed in a profile')

def _svp_reject_constant(_text):
    raise SVPError(f'non-finite constant not allowed: {_text}')

def _svp_int(name, value, lo, hi):
    if isinstance(value, bool) or not isinstance(value, int):
        raise SVPError(f'{name} must be an integer')
    if not lo <= value <= hi:
        raise SVPError(f'{name} out of range [{lo}, {hi}]: {value}')
    return value

def svp_canonical_bytes(profile: dict) -> bytes:
    return bootstrap.json.dumps(profile, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')

def svp_validate(profile: dict) -> dict:
    if not isinstance(profile, dict):
        raise SVPError('profile must be a JSON object')
    if set(profile.keys()) != set(SVP_FIELDS):
        missing = sorted(set(SVP_FIELDS) - set(profile))
        extra = sorted(set(profile) - set(SVP_FIELDS))
        raise SVPError(f'fields must be exactly {list(SVP_FIELDS)}; missing={missing} extra={extra}')
    if isinstance(profile['version'], bool) or profile['version'] != SVP_VERSION:
        raise SVPError(f'unsupported profile version: {profile['version']!r}')
    mode = profile['mode']
    family = profile['family']
    if mode not in SVP_MODES:
        raise SVPError(f'unknown mode: {mode!r}')
    if family not in SVP_FAMILIES:
        raise SVPError(f'unknown family: {family!r}')
    if profile['fallback'] != 'standard_l1':
        raise SVPError('fallback must be standard_l1: a profile can never remove the L1 path')
    dmin = _svp_int('difficulty_min', profile['difficulty_min'], *SVP_CAPS['difficulty'])
    dmax = _svp_int('difficulty_max', profile['difficulty_max'], *SVP_CAPS['difficulty'])
    if dmin > dmax:
        raise SVPError('difficulty_min must not exceed difficulty_max')
    ev = _svp_int('evidence_threshold', profile['evidence_threshold'], *SVP_CAPS['evidence_threshold'])
    md = _svp_int('min_distinct_miners', profile['min_distinct_miners'], *SVP_CAPS['min_distinct_miners'])
    if md > ev:
        raise SVPError('min_distinct_miners must not exceed evidence_threshold')
    _svp_int('window_blocks', profile['window_blocks'], *SVP_CAPS['window_blocks'])
    bm = _svp_int('batch_max', profile['batch_max'], *SVP_CAPS['batch_max'])
    if mode == 'standard_l1':
        if family != 'none' or (dmin, dmax, ev, md, bm) != (1, 1, 1, 1, 1):
            raise SVPError('standard_l1 takes no challenge: family none, all challenge fields at minimum')
    elif mode == 'spatial_per_transfer':
        if family == 'none':
            raise SVPError('spatial modes need a challenge family')
        if bm != 1:
            raise SVPError('spatial_per_transfer must have batch_max 1')
    else:
        if family == 'none':
            raise SVPError('spatial modes need a challenge family')
        if bm < 2:
            raise SVPError(f'{mode} must have batch_max of at least 2')
    return dict(profile)

def svp_parse(raw: bytes) -> dict:
    if not isinstance(raw, (bytes, bytearray)):
        raise SVPError('profile must be bytes')
    try:
        text = bytes(raw).decode('ascii')
        obj = bootstrap.json.loads(text, object_pairs_hook=_svp_reject_duplicate_keys, parse_float=_svp_reject_float, parse_constant=_svp_reject_constant)
    except (UnicodeDecodeError, ValueError) as exc:
        raise SVPError(f'malformed profile: {exc}') from None
    profile = svp_validate(obj)
    if svp_canonical_bytes(profile) != bytes(raw):
        raise SVPError('profile is not in canonical form')
    return profile

def svp_hash(profile: dict) -> bytes:
    return bootstrap.hashlib.sha256(SVP_HASH_DOMAIN + svp_canonical_bytes(svp_validate(profile))).digest()

def svf_commitment(chain_id: int, token_address: str, profile_hash: bytes, batch_id: int, window_start: int, nonce: int) -> bytes:
    if not crypto._valid_wallet(token_address):
        raise SVPError('invalid token address')
    if not isinstance(profile_hash, (bytes, bytearray)) or len(profile_hash) != 32:
        raise SVPError('profile_hash must be 32 bytes')
    for name, value in (('chain_id', chain_id), ('batch_id', batch_id), ('window_start', window_start), ('nonce', nonce)):
        if isinstance(value, bool) or not isinstance(value, int) or (not 0 <= value < 2 ** 64):
            raise SVPError(f'{name} must be an unsigned 64-bit integer')
    token = token_address.lower().encode('ascii')
    h = bootstrap.hashlib.sha256()
    h.update(SVF_COMMIT_DOMAIN)
    h.update(bootstrap.struct.pack('>Q', chain_id))
    h.update(bootstrap.struct.pack('>H', len(token)))
    h.update(token)
    h.update(bytes(profile_hash))
    h.update(bootstrap.struct.pack('>QQQ', batch_id, window_start, nonce))
    return h.digest()

def svf_active_at(height: int) -> bool:
    return SVF_ACTIVATION_HEIGHT is not None and int(height) >= SVF_ACTIVATION_HEIGHT

def _svf_selector(signature: str) -> bytes:
    return bootstrap.eth_keccak(signature.encode('ascii'))[:4]
SVF_DOMAIN_INTENT = b'MCX-SVF-INTENT-v1'
SVF_DOMAIN_BATCH_LEAF = b'MCX-SVF-BATCH-LEAF-v1'
SVF_DOMAIN_BATCH_NODE = b'MCX-SVF-BATCH-NODE-v1'
SVF_DOMAIN_CHALLENGE = b'MCX-SVF-CHALLENGE-v1'
SVF_DOMAIN_EVIDENCE = b'MCX-SVF-EVIDENCE-v1'
SVF_BILLABLE_SIG_BYTES = 65
SVF_FEE_PER_BYTE = 1
SVF_MAX_BATCH_INTENTS = 1000
SVF_MAX_EVIDENCE_RECORDS = 512
SVF_MAX_WINDOW_BLOCKS = 200
SVF_MAX_AMOUNT = 2 ** 63 - 1
SVF_DIRECTIONS = ('east', 'west', 'north', 'south', 'up', 'down')
SVF_INTENT_FIELDS = ('chain_id', 'token', 'sender', 'recipient', 'amount', 'nonce', 'profile_hash', 'valid_after_height', 'valid_before_height')
SVF_EVIDENCE_FIELDS = ('chain_id', 'miner', 'maze_id', 'maze_version', 'move_nonce', 'direction', 'prev_hash', 'parent_height')
SVF_STATES = ('RECEIVED', 'RESERVED', 'EVIDENCE_OPEN', 'EVIDENCE_FROZEN', 'VALIDATED', 'SETTLED', 'REJECTED', 'EXPIRED')
SVF_TRANSITIONS = {'RECEIVED': {'RESERVED', 'REJECTED'}, 'RESERVED': {'EVIDENCE_OPEN', 'EXPIRED'}, 'EVIDENCE_OPEN': {'EVIDENCE_FROZEN', 'EXPIRED'}, 'EVIDENCE_FROZEN': {'VALIDATED', 'REJECTED', 'EXPIRED'}, 'VALIDATED': {'SETTLED', 'EXPIRED'}, 'SETTLED': set(), 'REJECTED': set(), 'EXPIRED': set()}
SVF_RELEASING_STATES = {'REJECTED', 'EXPIRED'}

class SVFBlocked(RuntimeError):
    pass

class SVFReject(ValueError):
    pass

def _svf_int(name, value, lo, hi):
    if isinstance(value, bool) or not isinstance(value, int):
        raise SVFReject(f'{name} must be an integer')
    if not lo <= value <= hi:
        raise SVFReject(f'{name} out of range [{lo}, {hi}]')
    return value

def _svf_hex32(name, value) -> str:
    if not isinstance(value, str) or len(value) != 64 or any((c not in '0123456789abcdef' for c in value)):
        raise SVFReject(f'{name} must be 64 lowercase hex characters')
    return value

def svf_intent_body(intent: dict, expected_chain_id: int) -> dict:
    if not isinstance(intent, dict) or set(intent.keys()) != set(SVF_INTENT_FIELDS):
        raise SVFReject(f'intent fields must be exactly {list(SVF_INTENT_FIELDS)}')
    chain_id = _svf_int('chain_id', intent['chain_id'], 0, 2 ** 63 - 1)
    if chain_id != int(expected_chain_id):
        raise SVFReject('chain_id mismatch (domain separation)')
    for name in ('token', 'sender', 'recipient'):
        if not crypto._valid_wallet(intent[name]):
            raise SVFReject(f'{name} is not a valid wallet')
    if intent['sender'].lower() == intent['recipient'].lower():
        raise SVFReject('self-transfer not allowed')
    amount = _svf_int('amount', intent['amount'], 1, SVF_MAX_AMOUNT)
    nonce = _svf_int('nonce', intent['nonce'], 0, 2 ** 63 - 1)
    profile_hash = _svf_hex32('profile_hash', intent['profile_hash'])
    after = _svf_int('valid_after_height', intent['valid_after_height'], 0, 2 ** 63 - 1)
    before = _svf_int('valid_before_height', intent['valid_before_height'], 1, 2 ** 63 - 1)
    if before <= after:
        raise SVFReject('valid_before_height must exceed valid_after_height')
    return {'chain_id': chain_id, 'token': intent['token'].lower(), 'sender': intent['sender'].lower(), 'recipient': intent['recipient'].lower(), 'amount': amount, 'nonce': nonce, 'profile_hash': profile_hash, 'valid_after_height': after, 'valid_before_height': before}

def svf_billable_bytes(body: dict) -> int:
    return len(svf_keys._svf_canon(body)) + SVF_BILLABLE_SIG_BYTES

def svf_fee(body: dict) -> int:
    fee = svf_billable_bytes(body) * SVF_FEE_PER_BYTE
    if fee <= 0:
        raise SVFReject('SVF fee must be positive')
    return fee

def svf_intent_hash(body: dict, fee: int) -> bytes:
    return bootstrap.hashlib.sha256(SVF_DOMAIN_INTENT + svf_keys._svf_canon(dict(body, fee=int(fee)))).digest()

def svf_reserve_batch(state: dict, intents: list) -> tuple:
    st = {'balances': dict(state['balances']), 'reserved': dict(state['reserved']), 'nonces': dict(state['nonces']), 'open': dict(state['open']), 'seen': set(state['seen'])}
    results = []
    for it in sorted(intents, key=lambda x: (x['order'], x['hash'])):
        h = it['hash']
        key = (it['token'], it['sender'])
        if h in st['seen']:
            results.append((h, 'DUPLICATE'))
            continue
        expected = st['nonces'].get(key, 0)
        if it['nonce'] != expected:
            results.append((h, 'BAD_NONCE'))
            continue
        try:
            amount = it['amount']
            if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
                results.append((h, 'BAD_AMOUNT'))
                continue
        except (TypeError, KeyError):
            results.append((h, 'BAD_AMOUNT'))
            continue
        spendable = st['balances'].get(key, 0) - st['reserved'].get(key, 0)
        if spendable < amount:
            results.append((h, 'INSUFFICIENT_SPENDABLE'))
            continue
        st['seen'].add(h)
        st['reserved'][key] = st['reserved'].get(key, 0) + amount
        st['nonces'][key] = expected + 1
        st['open'][h] = (it['token'], it['sender'], amount)
        results.append((h, 'ACCEPTED'))
    return (st, results)

def svf_release(state: dict, intent_hash: bytes) -> dict:
    if intent_hash not in state['open']:
        raise SVFReject('no open reservation for this intent (already released or never reserved)')
    token, sender, amount = state['open'][intent_hash]
    key = (token, sender)
    st = {'balances': dict(state['balances']), 'reserved': dict(state['reserved']), 'nonces': dict(state['nonces']), 'open': {k: v for k, v in state['open'].items() if k != intent_hash}, 'seen': set(state['seen'])}
    st['reserved'][key] = st['reserved'].get(key, 0) - amount
    if st['reserved'][key] < 0:
        raise SVFReject('reserved balance would go negative')
    return st

def svf_next_state(current: str, nxt: str) -> str:
    if current not in SVF_TRANSITIONS or nxt not in SVF_STATES:
        raise SVFReject('unknown lifecycle state')
    if nxt not in SVF_TRANSITIONS[current]:
        raise SVFReject(f'illegal transition {current} -> {nxt}')
    return nxt

def svf_batch_root(intent_hashes: list) -> bytes:
    if len(intent_hashes) > SVF_MAX_BATCH_INTENTS:
        raise SVFReject('batch exceeds SVF_MAX_BATCH_INTENTS')
    if len(set(intent_hashes)) != len(intent_hashes):
        raise SVFReject('duplicate intent in batch')
    for i, h in enumerate(intent_hashes):
        if not isinstance(h, (bytes, bytearray)) or len(h) != 32:
            raise SVFReject(f'intent_hashes[{i}] must be exactly 32 bytes')
    if not intent_hashes:
        return bootstrap.hashlib.sha256(SVF_DOMAIN_BATCH_NODE + b'empty').digest()
    level = [bootstrap.hashlib.sha256(SVF_DOMAIN_BATCH_LEAF + bytes(h)).digest() for h in sorted(intent_hashes)]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(bootstrap.hashlib.sha256(SVF_DOMAIN_BATCH_NODE + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]

def svf_challenge(beacon, chain_id: int, token: str, profile_hash: str, batch_root: bytes, window_start: int, window_end: int) -> bytes:
    if beacon is None:
        raise SVFBlocked('B1 randomness beacon unavailable: SVF activation is blocked')
    if not isinstance(beacon, (bytes, bytearray)) or len(beacon) != 32:
        raise SVFReject('beacon must be 32 bytes')
    _svf_int('chain_id', chain_id, 0, 2 ** 63 - 1)
    if not crypto._valid_wallet(token):
        raise SVFReject('invalid token')
    _svf_hex32('profile_hash', profile_hash)
    if not isinstance(batch_root, (bytes, bytearray)) or len(batch_root) != 32:
        raise SVFReject('batch_root must be 32 bytes')
    _svf_int('window_start', window_start, 0, 2 ** 63 - 1)
    _svf_int('window_end', window_end, 1, 2 ** 63 - 1)
    span = window_end - window_start
    if not 1 <= span <= SVF_MAX_WINDOW_BLOCKS:
        raise SVFReject(f'evidence window must span 1..{SVF_MAX_WINDOW_BLOCKS} blocks')
    tok = token.lower().encode('ascii')
    h = bootstrap.hashlib.sha256()
    h.update(SVF_DOMAIN_CHALLENGE)
    h.update(bootstrap.struct.pack('>Q', chain_id))
    h.update(bootstrap.struct.pack('>H', len(tok)) + tok)
    h.update(bytes.fromhex(profile_hash))
    h.update(bytes(batch_root))
    h.update(bootstrap.struct.pack('>QQ', window_start, window_end))
    h.update(bytes(beacon))
    return h.digest()

def svf_evidence_body(rec: dict) -> dict:
    if not isinstance(rec, dict) or set(rec.keys()) != set(SVF_EVIDENCE_FIELDS):
        raise SVFReject(f'evidence fields must be exactly {list(SVF_EVIDENCE_FIELDS)}')
    if rec['direction'] not in SVF_DIRECTIONS:
        raise SVFReject('unknown direction')
    if not crypto._valid_wallet(rec['miner']):
        raise SVFReject('miner must be a wallet-format identity')
    prev = rec['prev_hash']
    if prev != '00' * 32:
        _svf_hex32('prev_hash', prev)
    return {'chain_id': _svf_int('chain_id', rec['chain_id'], 0, 2 ** 63 - 1), 'miner': rec['miner'].lower(), 'maze_id': str(rec['maze_id']), 'maze_version': _svf_int('maze_version', rec['maze_version'], 0, 2 ** 63 - 1), 'move_nonce': _svf_int('move_nonce', rec['move_nonce'], 0, 2 ** 63 - 1), 'direction': rec['direction'], 'prev_hash': prev, 'parent_height': _svf_int('parent_height', rec['parent_height'], 0, 2 ** 63 - 1)}

def svf_evidence_hash(body: dict) -> bytes:
    return bootstrap.hashlib.sha256(SVF_DOMAIN_EVIDENCE + svf_keys._svf_canon(body)).digest()

def svf_verify_evidence_chain(records: list, verify_sig) -> dict:
    if not isinstance(records, list) or not 1 <= len(records) <= SVF_MAX_EVIDENCE_RECORDS:
        raise SVFReject(f'evidence must contain 1..{SVF_MAX_EVIDENCE_RECORDS} records')
    prev_h = '00' * 32
    first = None
    expect_nonce = None
    for entry in records:
        if not isinstance(entry, dict) or set(entry.keys()) != {'body', 'signature'}:
            raise SVFReject('each record must carry exactly a body and a signature')
        body = svf_evidence_body(entry['body'])
        if first is None:
            first = body
            expect_nonce = body['move_nonce']
        for k in ('chain_id', 'miner', 'maze_id', 'maze_version'):
            if body[k] != first[k]:
                raise SVFReject(f'record {k} differs within the window')
        if body['move_nonce'] != expect_nonce:
            raise SVFReject('move_nonce is not contiguous (gap, duplicate or reorder)')
        if body['prev_hash'] != prev_h:
            raise SVFReject('prev_hash does not link to the previous record')
        if not isinstance(entry['signature'], str) or not verify_sig(body['miner'], svf_keys._svf_canon(body), entry['signature']):
            raise SVFReject('record signature does not verify')
        prev_h = svf_evidence_hash(body).hex()
        expect_nonce += 1
    return {'count': len(records), 'tip_hash': prev_h}
SVF_PROFILE_MAGIC = b'MCXS'
SVF_PROFILE_SCHEMA_VERSION = 1
SVF_PROFILE_FAMILY_ID = 1
SVF_PROFILE_SIZE = 42
SVF_EPOCH_BLOCKS = 100
SVF_PROFILE_DOMAIN = b'MCX-SVF-PROFILE-V1'
SVF_EPOCH_DOMAIN = b'MCX-SVF-EPOCH-V1'
SVF_EVIDENCE_DOMAIN = b'MCX-SVF-EVIDENCE-V1'
SVF_EVIDENCE_LEAF_DOMAIN = b'MCX-SVF-EVIDENCE-LEAF-V1'
SVF_EVIDENCE_NODE_DOMAIN = b'MCX-SVF-EVIDENCE-NODE-V1'
SVF_CHALLENGE_DOMAIN = b'MCX-SVF-CHALLENGE-SEED-V1'
SVF_FY_DOMAIN = b'MCX-SVF-FY-V1'
SVF_GUARD_ADDRESS = bytes.fromhex('0000000000000000000000000000000000000800')
_SVF_PROFILE_REGISTRY: dict = {}
_SVF_EVIDENCE_STORE: dict = {}
_SVF_EPOCH_ROOTS: dict = {}
_SVF_CERTIFICATE_STORE: dict = {}

def svf_profile_hash(chain_id: int, token_address: str, profile_bytes: bytes) -> bytes:
    _tok = str(token_address).lower() if isinstance(token_address, str) else ''
    if _tok and (not _tok.startswith('0x')):
        _tok = '0x' + _tok
    if not crypto._valid_wallet(_tok):
        raise SVFReject('invalid token address for profile hash')
    if not isinstance(profile_bytes, (bytes, bytearray)) or len(profile_bytes) != SVF_PROFILE_SIZE:
        raise SVFReject('profile_bytes must be exactly 42 bytes')
    h = bootstrap.hashlib.sha256()
    h.update(SVF_PROFILE_DOMAIN)
    h.update(bootstrap.struct.pack('>Q', int(chain_id)))
    tok = _tok.lower()
    if tok.startswith('0x'):
        tok = tok[2:]
    h.update(bytes.fromhex(tok))
    h.update(bytes(profile_bytes))
    return h.digest()

def svf_parse_profile(raw: bytes) -> dict:
    if not isinstance(raw, (bytes, bytearray)) or len(raw) != SVF_PROFILE_SIZE:
        raise SVFReject('profile must be exactly 42 bytes')
    if raw[:4] != SVF_PROFILE_MAGIC:
        raise SVFReject('invalid profile magic')
    schema_version = bootstrap.struct.unpack('>H', raw[4:6])[0]
    if schema_version != SVF_PROFILE_SCHEMA_VERSION:
        raise SVFReject(f'unsupported profile schema version: {schema_version}')
    family_id = raw[6]
    if family_id != SVF_PROFILE_FAMILY_ID:
        raise SVFReject(f'unsupported profile family: {family_id}')
    sample_blocks = raw[7]
    min_distinct_winners = raw[8]
    min_growth_blocks = raw[9]
    min_total_attestation_weight = int.from_bytes(raw[10:42], 'big')
    if not 1 <= sample_blocks <= SVF_EPOCH_BLOCKS:
        raise SVFReject(f'sample_blocks out of range [1, {SVF_EPOCH_BLOCKS}]: {sample_blocks}')
    if not 1 <= min_distinct_winners <= sample_blocks:
        raise SVFReject(f'min_distinct_winners out of range [1, {sample_blocks}]: {min_distinct_winners}')
    if not 0 <= min_growth_blocks <= sample_blocks:
        raise SVFReject(f'min_growth_blocks out of range [0, {sample_blocks}]: {min_growth_blocks}')
    if min_total_attestation_weight <= 0:
        raise SVFReject('min_total_attestation_weight must be positive')
    return {'schema_version': schema_version, 'family_id': family_id, 'sample_blocks': sample_blocks, 'min_distinct_winners': min_distinct_winners, 'min_growth_blocks': min_growth_blocks, 'min_total_attestation_weight': min_total_attestation_weight}

def svf_profile_bytes(profile: dict) -> bytes:
    if profile['schema_version'] != SVF_PROFILE_SCHEMA_VERSION:
        raise SVFReject(f'unsupported schema version: {profile['schema_version']}')
    if profile['family_id'] != SVF_PROFILE_FAMILY_ID:
        raise SVFReject(f'unsupported family id: {profile['family_id']}')
    sb = bytearray()
    sb += SVF_PROFILE_MAGIC
    sb += bootstrap.struct.pack('>H', profile['schema_version'])
    sb += bytes([profile['family_id']])
    sb += bytes([profile['sample_blocks']])
    sb += bytes([profile['min_distinct_winners']])
    sb += bytes([profile['min_growth_blocks']])
    sb += profile['min_total_attestation_weight'].to_bytes(32, 'big')
    return bytes(sb)

class SVFBlockEvidence:

    def __init__(self, block_id: int, block_hash: str, winner_pubkey: str, attested_size: int, attestation_weight: int, growth_present: bool, record_hash: bytes):
        self.block_id = block_id
        self.block_hash = block_hash
        self.winner_pubkey = winner_pubkey.lower()
        self.attested_size = attested_size
        self.attestation_weight = attestation_weight
        self.growth_present = growth_present
        self.record_hash = record_hash if isinstance(record_hash, bytes) else bytes.fromhex(record_hash)

def compute_block_evidence(block: dict, block_id: int) -> SVFBlockEvidence:
    att = block.get('maze_attestation')
    if not isinstance(att, dict):
        raise SVFReject('block has no maze_attestation')
    attested_size = int(att.get('size', 0))
    if attested_size <= 0:
        raise SVFReject('attestation size must be positive')
    maze_updates = block.get('maze_updates', [])
    if not isinstance(maze_updates, list):
        raise SVFReject('block maze_updates is not a list')
    att_pub = str(att.get('pubkey', '') or '')
    if not att_pub:
        raise SVFReject('maze_attestation has no pubkey')
    winner_pubkey = att_pub.lower()
    winner = block.get('winner') or att_pub
    growth_present = False
    for upd in maze_updates:
        if not isinstance(upd, dict):
            continue
        _um = str(upd.get('maze_id') or upd.get('miner_id') or '')
        if _um != str(winner):
            continue
        _type = str(upd.get('type', '') or '')
        if _type in ('goal_catch', 'growth', 'maze_update') and upd.get('caught_at_nonce') is not None:
            growth_present = True
            break
        if upd.get('new_size') is not None and upd.get('caught_at_nonce') is not None:
            growth_present = True
            break
    att_weight = maze._maze_att_weight(attested_size)
    block_hash = block.get('hash')
    if not block_hash:
        raise SVFReject('block has no hash')
    block_hash_bytes = bytes.fromhex(block_hash) if isinstance(block_hash, str) else bytes(block_hash)
    winner_pubkey_bytes = bytes.fromhex(winner_pubkey.removeprefix('0x')) if winner_pubkey.startswith('0x') else bytes.fromhex(winner_pubkey)
    h = bootstrap.hashlib.sha256()
    h.update(SVF_EVIDENCE_DOMAIN)
    h.update(bootstrap.struct.pack('>Q', int(block_id)))
    h.update(block_hash_bytes)
    h.update(winner_pubkey_bytes)
    h.update(bootstrap.struct.pack('>Q', attested_size))
    h.update(bootstrap.struct.pack('>Q', att_weight))
    h.update(b'\x01' if growth_present else b'\x00')
    record_hash = h.digest()
    return SVFBlockEvidence(block_id=block_id, block_hash=block_hash, winner_pubkey=winner_pubkey, attested_size=attested_size, attestation_weight=att_weight, growth_present=growth_present, record_hash=record_hash)

def compute_epoch_root(records: list) -> bytes:
    if len(records) != SVF_EPOCH_BLOCKS:
        raise SVFReject(f'epoch root requires exactly {SVF_EPOCH_BLOCKS} records, got {len(records)}')

    def _get(rec, key):
        if isinstance(rec, dict):
            return rec[key]
        return getattr(rec, key)
    sorted_recs = sorted(records, key=lambda r: _get(r, 'block_id'))
    level = [bootstrap.hashlib.sha256(SVF_EVIDENCE_LEAF_DOMAIN + b'\x00' + _get(r, 'record_hash')).digest() for r in sorted_recs]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level) - 1, 2):
            nxt.append(bootstrap.hashlib.sha256(SVF_EVIDENCE_NODE_DOMAIN + b'\x00' + level[i] + level[i + 1]).digest())
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]

def _svf_epoch_root_if_complete(records, epoch_id):
    valid = [r for r in records or [] if r is not None]
    if len(valid) != SVF_EPOCH_BLOCKS:
        return None

    def _bid(r):
        return r['block_id'] if isinstance(r, dict) else r.block_id
    srt = sorted(valid, key=_bid)
    if [int(_bid(r)) for r in srt] != list(range(epoch_id * SVF_EPOCH_BLOCKS, epoch_id * SVF_EPOCH_BLOCKS + SVF_EPOCH_BLOCKS)):
        return None
    return compute_epoch_root(srt)

def compute_epoch_challenge(beacon: bytes, chain_id: int, epoch_id: int, token_address: str, profile_hash: bytes, evidence_root: bytes) -> bytes:
    if not isinstance(beacon, (bytes, bytearray)) or len(beacon) != 32:
        raise SVFReject('beacon must be 32 bytes')
    _svf_int('chain_id', chain_id, 0, 2 ** 63 - 1)
    _svf_int('evidence_epoch', epoch_id, 0, 2 ** 63 - 1)
    _tok = str(token_address).lower() if isinstance(token_address, str) else ''
    if _tok and (not _tok.startswith('0x')):
        _tok = '0x' + _tok
    if not crypto._valid_wallet(_tok):
        raise SVFReject('invalid token address for challenge')
    token_address = _tok
    if isinstance(profile_hash, (bytes, bytearray)):
        if len(profile_hash) != 32:
            raise SVFReject('profile_hash must be 32 bytes')
        profile_hash_hex = bytes(profile_hash).hex()
    elif isinstance(profile_hash, str):
        _svf_hex32('profile_hash', profile_hash)
        profile_hash_hex = profile_hash
    else:
        raise SVFReject('profile_hash must be 32 bytes or 64-char hex string')
    if isinstance(evidence_root, (bytes, bytearray)):
        if len(evidence_root) != 32:
            raise SVFReject('evidence_root must be 32 bytes')
        evidence_root_hex = bytes(evidence_root).hex()
    elif isinstance(evidence_root, str):
        _svf_hex32('evidence_root', evidence_root)
        evidence_root_hex = evidence_root
    else:
        raise SVFReject('evidence_root must be 32 bytes or 64-char hex string')
    h = bootstrap.hashlib.sha256()
    h.update(SVF_CHALLENGE_DOMAIN)
    h.update(b'\x00')
    h.update(bootstrap.struct.pack('>Q', chain_id))
    h.update(bootstrap.struct.pack('>Q', epoch_id))
    tok = token_address.lower().removeprefix('0x')
    h.update(bytes.fromhex(tok))
    h.update(bytes.fromhex(profile_hash_hex))
    h.update(bytes.fromhex(evidence_root_hex))
    h.update(bytes(beacon))
    return h.digest()

def fisher_yates_shuffle(challenge_seed: bytes, n: int) -> list:
    import hmac as _hmac
    if n <= 0:
        return []
    if n == 1:
        return [0]
    permutation = list(range(n))
    counter = 0
    for i in range(n - 1, 0, -1):
        n_step = i + 1
        limit = 2 ** 256 // n_step * n_step
        while True:
            counter += 1
            msg = SVF_FY_DOMAIN + bootstrap.struct.pack('>I', counter)
            digest = _hmac.new(challenge_seed, msg, bootstrap.hashlib.sha256).digest()
            x = int.from_bytes(digest, 'big')
            if x < limit:
                break
        j = x % n_step
        permutation[i], permutation[j] = (permutation[j], permutation[i])
    return permutation

def _svf_rec_get(rec, key, default=None):
    if isinstance(rec, dict):
        return rec.get(key, default)
    return getattr(rec, key, default)

def evaluate_profile(profile: dict, evidence_records: list, block_id: int, challenge_seed: bytes=None, epoch_root: bytes=None, certificate: dict=None, chain_id: int=None, token_address: str=None, profile_hash: bytes=None, prune_blocks: int=0) -> str:
    if not evidence_records:
        return 'UNAVAILABLE'
    if any((r is None for r in evidence_records)):
        return 'UNAVAILABLE'
    sample_blocks = int(profile.get('sample_blocks', 0))
    if not 1 <= sample_blocks <= SVF_EPOCH_BLOCKS:
        return 'UNAVAILABLE'
    if len(evidence_records) != SVF_EPOCH_BLOCKS:
        return 'UNAVAILABLE'
    sorted_recs = sorted(evidence_records, key=lambda r: _svf_rec_get(r, 'block_id', 0))
    expected_heights = []
    epoch_id = sorted_recs[0].get('block_id', 0) // SVF_EPOCH_BLOCKS
    for k in range(SVF_EPOCH_BLOCKS):
        expected_heights.append(epoch_id * SVF_EPOCH_BLOCKS + k)
    actual_heights = [int(_svf_rec_get(r, 'block_id', -1)) for r in sorted_recs]
    if actual_heights != expected_heights:
        return 'UNAVAILABLE'
    if epoch_root is not None:
        try:
            computed_root = compute_epoch_root(sorted_recs)
            if computed_root != (epoch_root if isinstance(epoch_root, bytes) else bytes.fromhex(epoch_root)):
                return 'FAIL'
        except SVFReject:
            return 'FAIL'
    end_height = epoch_id * SVF_EPOCH_BLOCKS + SVF_EPOCH_BLOCKS - 1
    if not end_height + int(prune_blocks) < int(block_id):
        return 'UNAVAILABLE'
    if certificate is None:
        return 'UNAVAILABLE'
    cert_sig = certificate.get('threshold_signature') or certificate.get('signature')
    if not cert_sig:
        return 'UNAVAILABLE'
    try:
        sig_bytes = bytes.fromhex(cert_sig) if isinstance(cert_sig, str) else bytes(cert_sig)
    except (ValueError, TypeError):
        return 'UNAVAILABLE'
    if len(sig_bytes) == 0:
        return 'UNAVAILABLE'
    beacon_output = bootstrap.hashlib.sha256(b'MCX-SVF-BEACON-OUTPUT-V1' + b'\x00' + sig_bytes).digest()
    if challenge_seed is None:
        if chain_id is None or token_address is None or profile_hash is None or (epoch_root is None):
            return 'UNAVAILABLE'
        try:
            challenge_seed = compute_epoch_challenge(beacon_output, int(chain_id), epoch_id, token_address, profile_hash, epoch_root)
        except SVFReject:
            return 'UNAVAILABLE'
    permutation = fisher_yates_shuffle(challenge_seed, SVF_EPOCH_BLOCKS)
    selected_indices = sorted(permutation[:sample_blocks])
    sampled_weight = 0
    sampled_winners = set()
    sampled_growth = 0
    for idx in selected_indices:
        rec = sorted_recs[idx]
        sampled_weight += int(_svf_rec_get(rec, 'attestation_weight', 0))
        sampled_winners.add(_svf_rec_get(rec, 'winner_pubkey'))
        if _svf_rec_get(rec, 'growth_present'):
            sampled_growth += 1
    min_weight = int(profile.get('min_total_attestation_weight', 0))
    min_distinct = int(profile.get('min_distinct_winners', 0))
    min_growth = int(profile.get('min_growth_blocks', 0))
    if sampled_weight >= min_weight and len(sampled_winners) >= min_distinct and (sampled_growth >= min_growth):
        return 'PASS'
    return 'FAIL'
