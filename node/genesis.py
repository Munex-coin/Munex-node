import bootstrap
import config
import config as _config
import crypto
import gas
import svf_keys
import db
_node_genesis_hash = ''
_node_genesis_data = None
FORK_ID = 0

def resolve_genesis_file(config=None, cli_path=None) -> str:
    if cli_path:
        return str(cli_path)
    _env = bootstrap.os.environ.get('MCX_GENESIS_FILE', '')
    if _env.strip():
        return _env.strip()
    try:
        _cfg = ((config or {}).get('node', {}) or {}).get('genesis_file', '')
        if isinstance(_cfg, str) and _cfg.strip():
            return _cfg.strip()
    except (AttributeError, TypeError):
        pass
    return 'genesis.json'

def _write_genesis_file_atomic(body: dict) -> None:
    _dir = bootstrap.os.path.dirname(bootstrap.os.path.abspath(config.GENESIS_FILE)) or '.'
    _fd, _tmp = bootstrap.tempfile.mkstemp(prefix='.genesis.', suffix='.tmp', dir=_dir)
    try:
        with bootstrap.os.fdopen(_fd, 'w', encoding='utf-8') as f:
            bootstrap.json.dump(body, f, indent=2)
            f.flush()
            try:
                bootstrap.os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        bootstrap.os.replace(_tmp, bootstrap.os.path.abspath(config.GENESIS_FILE))
    except Exception as _we:
        try:
            if bootstrap.os.path.exists(_tmp):
                bootstrap.os.remove(_tmp)
        except OSError:
            pass
        bootstrap.logger.error(f'[GENESIS] Failed to write {bootstrap.os.path.abspath(config.GENESIS_FILE)}: {_we}. If the path is under OneDrive/Desktop, try running outside a synced folder or set node.genesis_file to a local path.')
        raise

def load_genesis_file():
    global _node_genesis_hash, _node_genesis_data, FORK_ID
    _abs = bootstrap.os.path.abspath(config.GENESIS_FILE)
    if not bootstrap.os.path.exists(config.GENESIS_FILE):
        bootstrap.logger.info(f'[GENESIS] No genesis file at {_abs}')
        _node_genesis_data = None
        return None
    try:
        with open(config.GENESIS_FILE, 'r') as f:
            data = bootstrap.json.load(f)
        _node_genesis_hash = data.get('hash', '')
        _node_genesis_data = data
        if _node_genesis_hash:
            FORK_ID = int(_node_genesis_hash[:8], 16) ^ int(_node_genesis_hash[8:16], 16)
        try:
            _recomputed = _genesis_identity_hash(_canonical_genesis_payload(data))
            _match = 'MATCH' if str(_recomputed).lower() == str(_node_genesis_hash).lower() else 'MISMATCH'
        except Exception as _re:
            _recomputed, _match = (f'<unrecomputable: {_re}>', 'UNRECOMPUTABLE')
        bootstrap.logger.info(f'[GENESIS] Loaded genesis from {_abs} (declared={_node_genesis_hash} recomputed={_recomputed} {_match})')
        try:
            svf_keys._svf_load_from_genesis(data.get('svf_public'))
        except svf_keys.SVFKeyError as _e:
            bootstrap.logger.error(f'[SVF] {_e}; refusing to start')
            bootstrap.sys.exit(1)
        return data
    except Exception as e:
        bootstrap.logger.error(f'[GENESIS] Failed to read {_abs}: {e}')
        _node_genesis_data = None
        return None

def _genesis_state_root(alloc: dict) -> str:
    _snap = {'height:0': 0}
    for _a, _v in alloc.items():
        _snap[f'balance:{_a}'] = int(_v)
    return db._state_root_from_snapshot(_snap)

def _genesis_economics_ok(data: dict):
    if not isinstance(data, dict):
        return (False, 'genesis body is not a dict')
    alloc = data.get('alloc')
    if not isinstance(alloc, dict):
        return (False, 'genesis alloc missing or not a map')
    try:
        total = data.get('total_minted', -1)
        if not isinstance(total, int) or isinstance(total, bool):
            return (False, 'invalid total_minted')
        total = int(total)
    except (TypeError, ValueError):
        return (False, 'invalid total_minted')
    if total < 0 or total > config.MAX_SUPPLY:
        return (False, 'total_minted out of range')
    _sum = 0
    for _a, _v in alloc.items():
        if not isinstance(_a, str) or len(_a) != 42 or (not _a.startswith('0x')):
            return (False, f'malformed alloc address {_a!r}')
        _hex = _a[2:]
        if not all((c in '0123456789abcdef' for c in _hex)):
            return (False, f'non-canonical alloc address {_a!r}')
        if not isinstance(_v, int) or isinstance(_v, bool):
            return (False, f'invalid alloc amount for {_a!r}')
        _amt = int(_v)
        if _amt < 0 or _amt > config.MAX_SUPPLY:
            return (False, f'alloc amount out of range for {_a!r}')
        _sum += _amt
    if _sum != total:
        return (False, 'alloc does not sum to total_minted')
    _root = data.get('state_root', '')
    if not _root:
        return (False, 'missing state_root')
    try:
        if _genesis_state_root(alloc) != _root:
            return (False, 'state_root does not match alloc')
    except Exception as e:
        return (False, f'state_root recomputation failed: {e}')
    return (True, 'ok')
GENESIS_IDENTITY_VERSION = 1
GENESIS_CONSENSUS_RULESET_VERSION = 12
GENESIS_IDENTITY_FIELDS = ('id', 'ts', 'phash', 'miners', 'reward', 'tx_count', 'merkle_root', 'nonce', 'difficulty', 'version', 'challenge', 'coverage', 'total_tx_value', 'total_fees', 'tx_hashes', 'state_root', 'producer_pub', 'alloc', 'total_minted', 'chain_id', 'consensus', 'validators', 'svf_public')
GENESIS_TRANSPORT_KEYS = frozenset({'hash', 'signature', 'finalized'})

def _fixed_consensus_params() -> dict:
    return {'genesis_supply': int(config.GENESIS_SUPPLY), 'max_supply': int(config.MAX_SUPPLY), 'initial_block_reward': int(config.INITIAL_BLOCK_REWARD), 'halving_interval': int(config.HALVING_INTERVAL), 'subs': int(config.SUBS), 'min_maze_size': int(config.MIN_MAZE_SIZE), 'token_transfer_fee_per_byte': int(gas.TOKEN_TRANSFER_FEE_PER_BYTE), 'token_transfer_v2': bool(gas.TOKEN_FEE_V2_ENABLED), 'gas_base_cost': int(config.GAS_BASE_COST), 'gas_per_zero_byte': int(config.GAS_PER_ZERO_BYTE), 'gas_per_nonzero_byte': int(config.GAS_PER_NONZERO_BYTE), 'gas_create_cost': int(config.GAS_CREATE_COST), 'gas_code_deposit_per_byte': int(config.GAS_CODE_DEPOSIT_PER_BYTE), 'svf_fee_per_byte': int(gas.TOKEN_TRANSFER_FEE_PER_BYTE), 'svf_fee_base': int(gas.SVF_FEE_BASE), 'svf_fee_create': int(gas.SVF_FEE_CREATE), 'token_transfer_sig_wire_bytes': int(gas.TOKEN_TRANSFER_SIG_WIRE_BYTES), 'max_token_burn_bps': int(gas.MAX_TOKEN_BURN_BPS), 'active_miner_window': int(config.ACTIVE_MINER_WINDOW_BLOCKS), 'block_future_skew': int(config.BLOCK_FUTURE_SKEW)}

def _consensus_record_from_config(config) -> dict:
    _c = (config or {}).get('consensus', {}) or {}
    _v = (config or {}).get('vm', {}) or {}
    _p = (config or {}).get('p2p', {}) or {}
    _dc = _config.DEFAULT_CONFIG.get('consensus', {})
    _dv = _config.DEFAULT_CONFIG.get('vm', {})
    _dp = _config.DEFAULT_CONFIG.get('p2p', {})
    try:
        _validators = _config._normalize_validator_list(_c.get('validators', _dc.get('validators', [])))
    except Exception:
        _validators = []
    _rec = {'ruleset_version': GENESIS_CONSENSUS_RULESET_VERSION, 'max_misses': _config._rule_int('consensus.max_misses', _c.get('max_misses'), _dc.get('max_misses', 3)), 'ban_duration': _config._rule_int('p2p.ban_duration', _p.get('ban_duration'), _dp.get('ban_duration', 3600)), 'prune_blocks': _config._rule_int('consensus.prune_blocks', _c.get('prune_blocks'), _dc.get('prune_blocks', 10000)), 'wall_density_3d': _config._rule_density(_c.get('wall_density_3d'), _dc.get('wall_density_3d', 0.55)), 'gas_price': int(_config.GAS_PRICE), 'gas_limit_default': int(_config.GAS_LIMIT_DEFAULT), 'max_bytecode': int(_config.MAX_BYTECODE), 'max_block_gas': int(_config.MAX_BLOCK_GAS), 'max_block_txs': int(_config.MAX_BLOCK_TXS), 'htlc_v1_enabled': _config._strict_bool('consensus.htlc_v1_enabled', _c.get('htlc_v1_enabled', _dc.get('htlc_v1_enabled', False))), 'lottery_scale': _config._validate_lottery_value('lottery_scale', _c.get('lottery_scale', _dc.get('lottery_scale', 1 << 249)), 1), 'attest_fresh_buffer': _config._validate_lottery_value('attest_fresh_buffer', _c.get('attest_fresh_buffer', _dc.get('attest_fresh_buffer', 5)), 0), 'attest_growth_per_block': _config._validate_lottery_value('attest_growth_per_block', _c.get('attest_growth_per_block', _dc.get('attest_growth_per_block', 5)), 0), 'slot_timeout': _config._validate_lottery_value('slot_timeout', _c.get('slot_timeout', _dc.get('slot_timeout', 30)), 1), 'validators': _validators, 'code': {'version': str(_config.VERSION), 'chain_id': int(_config.CHAIN_ID)}}
    _rec.update(_fixed_consensus_params())
    return _rec

def _effective_consensus_ruleset() -> dict:
    _live = {'ruleset_version': GENESIS_CONSENSUS_RULESET_VERSION, 'max_misses': int(config.MAX_MISSES), 'ban_duration': int(config.BAN_DURATION), 'prune_blocks': int(config.PRUNE_BLOCKS), 'wall_density_3d': float(config.WALL_DENSITY_3D), 'gas_price': int(config.GAS_PRICE), 'gas_limit_default': int(config.GAS_LIMIT_DEFAULT), 'max_bytecode': int(config.MAX_BYTECODE), 'max_block_gas': int(config.MAX_BLOCK_GAS), 'max_block_txs': int(config.MAX_BLOCK_TXS), 'htlc_v1_enabled': bool(config.HTLC_V1_ENABLED), 'lottery_scale': int(config.LOTTERY_SCALE), 'attest_fresh_buffer': int(config.ATTEST_FRESH_BUFFER), 'attest_growth_per_block': int(config.ATTEST_GROWTH_PER_BLOCK), 'slot_timeout': int(config.SLOT_TIMEOUT), 'validators': sorted(config._effective_validators()), 'code': {'version': str(config.VERSION), 'chain_id': int(config.CHAIN_ID)}}
    _live.update(_fixed_consensus_params())
    return _live

def _canonical_genesis_payload(data: dict) -> dict:
    if not isinstance(data, dict):
        raise ValueError('genesis body is not a dict')
    _extra = [k for k in data if k not in GENESIS_IDENTITY_FIELDS and k not in GENESIS_TRANSPORT_KEYS]
    if _extra:
        raise ValueError('unknown genesis fields: ' + ', '.join(sorted(map(str, _extra))))
    _missing = [k for k in GENESIS_IDENTITY_FIELDS if k not in data]
    if _missing:
        raise ValueError('missing genesis fields: ' + ', '.join(_missing))
    try:
        _payload = {'id': int(data['id']), 'ts': data['ts'], 'phash': str(data['phash']), 'miners': list(data['miners']), 'reward': int(data['reward']), 'tx_count': int(data['tx_count']), 'merkle_root': str(data['merkle_root']), 'nonce': int(data['nonce']), 'difficulty': int(data['difficulty']), 'version': str(data['version']), 'challenge': str(data['challenge']), 'coverage': data['coverage'], 'total_tx_value': int(data['total_tx_value']), 'total_fees': int(data['total_fees']), 'tx_hashes': list(data['tx_hashes']), 'state_root': str(data['state_root']), 'producer_pub': str(data['producer_pub']), 'alloc': dict(data['alloc']), 'total_minted': int(data['total_minted']), 'chain_id': int(data['chain_id']), 'consensus': dict(data['consensus']), 'validators': list(data['validators'])}
    except (TypeError, ValueError) as e:
        raise ValueError(f'malformed genesis field: {e}')
    if not isinstance(_payload['ts'], (int, float)) or isinstance(_payload['ts'], bool):
        raise ValueError('malformed genesis field: ts must be a number')
    if not isinstance(_payload['coverage'], (int, float)) or isinstance(_payload['coverage'], bool):
        raise ValueError('malformed genesis field: coverage must be a number')
    if not isinstance(data['alloc'], dict) or not isinstance(data['consensus'], dict):
        raise ValueError('malformed genesis field: alloc/consensus must be maps')
    if not isinstance(data['validators'], list) or any((not isinstance(v, str) for v in data['validators'])):
        raise ValueError('malformed genesis field: validators must be a list of strings')
    _payload['svf_public'] = svf_keys._normalize_svf_public(data['svf_public'])
    return _payload

def _genesis_identity_hash(payload: dict) -> str:
    return bootstrap.hashlib.sha256(crypto.canonical_json_bytes(payload)).hexdigest()

def _genesis_export_verified_impl(body):
    if not isinstance(body, dict):
        return (False, 'genesis body is not a dict')
    try:
        if int(body.get('id', -1)) != 0:
            return (False, 'genesis id must be 0')
    except Exception:
        return (False, 'invalid genesis id')
    if str(body.get('version', '')) != str(config.VERSION):
        return (False, 'genesis version mismatch')
    try:
        if int(body.get('chain_id', -1)) != int(config.CHAIN_ID):
            return (False, 'chain_id mismatch')
    except Exception:
        return (False, 'invalid chain_id')
    if str(body.get('phash', '')) != '0' * 64:
        return (False, 'genesis phash must be all zeros')
    gh = str(body.get('hash', '')).lower()
    if len(gh) != 64 or not all((c in '0123456789abcdef' for c in gh)):
        return (False, 'invalid genesis hash format')
    try:
        _payload = _canonical_genesis_payload(body)
    except ValueError as e:
        return (False, str(e))
    try:
        _recomputed = _genesis_identity_hash(_payload)
    except Exception as e:
        return (False, f'hash recomputation failed: {e}')
    if _recomputed != gh:
        return (False, 'recomputed genesis identity hash does not match declared hash')
    ok, why = _genesis_economics_ok(body)
    if not ok:
        return (False, why)
    try:
        _v_top = config._normalize_validator_list(body.get('validators'))
        _v_rec_raw = body.get('consensus', {}).get('validators', None)
        _v_rec = config._normalize_validator_list(_v_rec_raw if isinstance(_v_rec_raw, (list, tuple)) else [])
        if _v_top != _v_rec:
            return (False, 'genesis validators list disagrees with consensus record')
    except Exception as e:
        return (False, f'validators comparison failed: {e}')
    try:
        _want = _effective_consensus_ruleset()
        _got = body.get('consensus')
        if not isinstance(_got, dict):
            return (False, 'genesis consensus record missing or not a map')

        def _norm(d):
            return bootstrap.json.loads(bootstrap.json.dumps(d, sort_keys=True, allow_nan=False))
        try:
            _nw, _ng = (_norm(_want), _norm(_got))
        except (TypeError, ValueError) as _je:
            return (False, f'consensus record not JSON-stable: {_je}')
        _nw_cmp = {k: v for k, v in _nw.items() if k != 'prune_blocks'}
        _ng_cmp = {k: v for k, v in _ng.items() if k != 'prune_blocks'}
        if _ng_cmp != _nw_cmp:
            for _k in sorted(set(_nw_cmp) | set(_ng_cmp)):
                if _nw_cmp.get(_k) != _ng_cmp.get(_k):
                    return (False, f"genesis consensus ruleset differs from local effective config at '{_k}': genesis={_ng_cmp.get(_k)!r} local={_nw_cmp.get(_k)!r}")
            return (False, 'genesis consensus ruleset shape differs from local effective config')
    except Exception as e:
        return (False, f'consensus record comparison failed: {e}')
    return (True, 'ok')

def genesis_export_verified(body):
    try:
        return _genesis_export_verified_impl(body)
    except RecursionError:
        return (False, 'malformed genesis (nesting too deep)')
    except Exception as _e:
        return (False, f'malformed genesis ({type(_e).__name__})')

def strict_replayed_sizes(entries, eligible_rows) -> bootstrap.Tuple[bootstrap.Dict[str, int], bootstrap.Optional[str]]:
    local: bootstrap.Dict[str, int] = {}
    for r in eligible_rows or []:
        try:
            size = int(r['size'])
        except Exception:
            continue
        for k in ('maze_id', 'minerid'):
            mid = None
            try:
                mid = r[k]
            except Exception:
                mid = r.get(k) if isinstance(r, dict) else None
            if mid:
                local[str(mid)] = size
    sizes: bootstrap.Dict[str, int] = {}
    for e in entries or []:
        mid = e.get('minerid')
        if not mid:
            return ({}, 'entry missing minerid')
        if str(mid) not in local:
            return ({}, f'declared entry for unknown miner {str(mid)[:16]}')
        try:
            claimed = int(e.get('mazesize', 0))
        except (TypeError, ValueError):
            return ({}, f'invalid mazesize for {str(mid)[:16]}')
        if claimed != local[str(mid)]:
            return ({}, f'mazesize mismatch for {str(mid)[:16]}: declared {claimed}, local {local[str(mid)]}')
        sizes[str(mid)] = claimed
    return (sizes, None)
