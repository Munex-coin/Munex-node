import bootstrap
CONFIG_PATH = bootstrap.os.environ.get('MCX_CONFIG', 'config.yaml')
DEFAULT_CONFIG = {'node': {'ws_port': 8080, 'ws_bind_ip': '0.0.0.0', 'api_port': 8085, 'p2p_port': 8081, 'public_url': None, 'external_ip': '', 'external_port': 8081, 'bind_ip': '0.0.0.0', 'rpc_bind_ip': '127.0.0.1', 'rpc_token': '', 'rpc_trust_loopback': False, 'mainnet': True}, 'database': {'url': None, 'require_postgres': False}, 'consensus': {'block_time': 50, 'min_step_interval': 0, 'max_misses': 3, 'epoch_length': 100, 'prune_blocks': 10000, 'wall_density_3d': 0.55, 'initial_required_knowledge': 10, 'min_required_knowledge': 5, 'max_required_knowledge': 100, 'knowledge_adjustment_interval': 5, 'target_catch_time': 60.0, 'finality_threshold': 0.66, 'commit_reveal_activation_height': 0, 'lottery_scale': 1 << 249, 'attest_fresh_buffer': 5, 'attest_growth_per_block': 5, 'slot_timeout': 30, 'validators': []}, 'fees': {'max_fee': 100000, 'fee_per_byte': 10, 'rbf_increment': 1.1, 'cpfp_min_fee': 100}, 'p2p': {'genesis_node': 'munexseed.duckdns.org', 'dns_seeds': ['munexseed.duckdns.org'], 'bootstrap_nodes': ['munexseed.duckdns.org:8081'], 'dht_bootstrap_nodes': ['munexseed.duckdns.org:8083'], 'fallback_nodes': [], 'max_peers': 50, 'ban_threshold': 5, 'ban_duration': 3600, 'dht_enabled': True, 'discovery_interval': 300, 'discovery_timeout': 60, 'registry_url': 'https://munex-registry.animax-plorer22.workers.dev/nodes', 'registry_enabled': True, 'registry_interval': 300, 'allow_private_peers': False}, 'vm': {'max_state_size': 1024, 'sandbox': True, 'require_sandbox': True, 'timeout_seconds': 5}, 'mempool': {'max_size': 10000, 'expiry': 3600, 'max_tx_per_block': 100}, 'svf': {'key_file': ''}}

def load_config():
    cfg = bootstrap.copy.deepcopy(DEFAULT_CONFIG)
    if bootstrap.os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                loaded = bootstrap.yaml.safe_load(f) or {}
            for k, v in loaded.items():
                if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
            return cfg
        except Exception as e:
            bootstrap.logger.warning(f'Failed to load {CONFIG_PATH}: {e}, using defaults')
            return cfg
    else:
        with open(CONFIG_PATH, 'w') as f:
            bootstrap.yaml.dump(DEFAULT_CONFIG, f)
        bootstrap.logger.info('Created default config.yaml. Please edit it.')
        return cfg
CONFIG = load_config()
WS_PORT = CONFIG['node'].get('ws_port', 8080)
API_PORT = CONFIG['node'].get('api_port', 8085)
P2P_PORT = CONFIG['node'].get('p2p_port', 8081)
PUBLIC_URL = CONFIG['node'].get('public_url', None)
_db_url_raw = CONFIG.get('database', {}).get('url', None)
DB_URL = _db_url_raw if isinstance(_db_url_raw, str) and _db_url_raw.strip() and (_db_url_raw.strip().lower() not in ('null', 'none', '~')) else 'sqlite://microcore.db'
EXTERNAL_IP = CONFIG['node'].get('external_ip', '')
EXTERNAL_PORT = CONFIG['node'].get('external_port', P2P_PORT)
BIND_IP = CONFIG['node'].get('bind_ip', '0.0.0.0')
RPC_BIND_IP = CONFIG['node'].get('rpc_bind_ip', DEFAULT_CONFIG['node']['rpc_bind_ip'])
BLOCK_TIME = 50
BLOCK_FUTURE_SKEW = 600
BLOCK_MAX_FORWARD_GAP = 30 * 24 * 3600
COMMIT_REVEAL_ACTIVATION_HEIGHT = CONFIG['consensus'].get('commit_reveal_activation_height', 0)
MIN_STEP_INTERVAL = 0.0
RULE_INT_BOUNDS = {'consensus.max_misses': (1, 1000), 'consensus.prune_blocks': (100, 10 ** 9), 'fees.min_fee': (1, 10 ** 12), 'fees.token_creation_multiplier': (1, 10 ** 9), 'vm.gas_price': (1, 10 ** 9), 'vm.max_bytecode': (1024, 1 << 20), 'p2p.ban_duration': (1, 31536000)}

def _rule_int(path, v, default=None):
    if v is None:
        v = default
    lo, hi = RULE_INT_BOUNDS[path]
    if isinstance(v, bool) or not isinstance(v, int) or (not lo <= v <= hi):
        raise ValueError(f'config {path} must be an int in [{lo}, {hi}], got {v!r}')
    return v

def _rule_density(v, default=0.55):
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (not bootstrap.math.isfinite(v)) or (not 0 <= v < 1):
        raise ValueError(f'config consensus.wall_density_3d must be a finite number in [0, 1), got {v!r}')
    return max(0.55, float(v))
MAX_MISSES = _rule_int('consensus.max_misses', CONFIG['consensus'].get('max_misses'), 3)
EPOCH_LENGTH = CONFIG['consensus'].get('epoch_length', 100)
PRUNE_BLOCKS = _rule_int('consensus.prune_blocks', CONFIG['consensus'].get('prune_blocks'), 10000)
VALIDATORS = CONFIG['consensus'].get('validators', [])
WALL_DENSITY_3D = _rule_density(CONFIG['consensus'].get('wall_density_3d'))
INITIAL_REQUIRED_KNOWLEDGE = CONFIG['consensus'].get('initial_required_knowledge', 10)
MIN_REQUIRED_KNOWLEDGE = CONFIG['consensus'].get('min_required_knowledge', 5)
KNOWLEDGE_ADJUSTMENT_INTERVAL = CONFIG['consensus'].get('knowledge_adjustment_interval', 5)
TARGET_CATCH_TIME = CONFIG['consensus'].get('target_catch_time', 60.0)
GENESIS_NODE = 'munexseed.duckdns.org'
GENESIS_NODE_HOST = 'munexseed.duckdns.org'
GENESIS_NODE_P2P_PORT = 8081
GENESIS_NODE_DHT_PORT = 8083
GENESIS_NODE_WS_PORT = 8080
GENESIS_BOOTSTRAP_ENDPOINT = f'{GENESIS_NODE_HOST}:{GENESIS_NODE_P2P_PORT}'
REGISTRY_URL_DEFAULT = 'https://munex-registry.animax-plorer22.workers.dev/nodes'
BURN_ADDRESS_ZERO = '0x0000000000000000000000000000000000000000'
BURN_ADDRESS_DEAD = '0x000000000000000000000000000000000000dEaD'
BURN_ADDRESSES = {BURN_ADDRESS_ZERO.lower(), BURN_ADDRESS_DEAD.lower()}
DNS_SEEDS = list(dict.fromkeys([GENESIS_NODE_HOST] + CONFIG.get('p2p', {}).get('dns_seeds', [])))
BOOTSTRAP_NODES = list(dict.fromkeys([GENESIS_BOOTSTRAP_ENDPOINT] + CONFIG.get('p2p', {}).get('bootstrap_nodes', [])))
MAX_PEERS = CONFIG['p2p'].get('max_peers', 50)
BAN_THRESHOLD = CONFIG['p2p'].get('ban_threshold', 5)
BAN_DURATION = _rule_int('p2p.ban_duration', CONFIG['p2p'].get('ban_duration'), 3600)
WS_MAX_CONNECTIONS = 200
WS_MAX_CONNECTIONS_PER_IP = 20
DHT_ENABLED = CONFIG['p2p'].get('dht_enabled', True)
GAS_PRICE = 1
GAS_LIMIT_DEFAULT = 100000
MAX_BYTECODE = 65536
GAS_BASE_COST = 21000
GAS_PER_ZERO_BYTE = 4
GAS_PER_NONZERO_BYTE = 16
GAS_CREATE_COST = 32000
GAS_CODE_DEPOSIT_PER_BYTE = 200

def _strict_int(name, v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or (not lo <= v <= hi):
        raise ValueError(f'config vm.{name} must be an int in [{lo}, {hi}], got {v!r}')
    return v
GAS_LIMIT_DEFAULT = _strict_int('gas_limit_default', GAS_LIMIT_DEFAULT, 21000, 10000000)
MAX_BLOCK_GAS = 10000000
MAX_BLOCK_TXS = 1000
MAX_STATE_SIZE = CONFIG['vm'].get('max_state_size', 1024)
VM_SANDBOX = CONFIG['vm'].get('sandbox', True)
VM_REQUIRE_SANDBOX = CONFIG['vm'].get('require_sandbox', False)
VM_TIMEOUT = CONFIG['vm'].get('timeout_seconds', 5)
MAX_VM_MEMORY = 64 * 1024 * 1024
SSTORE_REFUND = 4800
SSTORE_SET = 20000
SSTORE_RESET = 2900
VM_RLIMIT_AS_BYTES = 256 * 1024 * 1024
MEMPOOL_MAX_SIZE = CONFIG['mempool'].get('max_size', 10000)
MEMPOOL_EXPIRY = CONFIG['mempool'].get('expiry', 3600)
MEMPOOL_MAX_NONCE_GAP = CONFIG['mempool'].get('max_nonce_gap', 10)
MAX_TX_PER_BLOCK = CONFIG['mempool'].get('max_tx_per_block', 100)
NODE_HOST = '0.0.0.0'
WS_PATH = '/ws'
RPC_PATH = '/rpc'
SYMBOL = 'MCX'
NAME = 'MicroCore'
VERSION = '64.3-PoSW'
SUBS = 1000000
SCHEMA_VERSION = 1
CHAIN_ID = 6621
TESTNET_GENESIS_HASH = '4aa436a1aa8d20ba8194faa99d544f1f81052670b7f1ada7b5c734dc571a5864'
SECP256K1_N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
PROTOCOL_VERSION = 64
POG_ACTIVATION_HEIGHT = 100000
MIN_MAZE_SIZE = 5
WEIGHT_START_SIZE = 6
SHRINK_THRESHOLD = 1000
SHRINK_INTERVAL = 100
SHRINK_INTERVAL_SEC = 3600
ACTIVE_MINER_WINDOW_BLOCKS = 5
LOTTERY_SCALE = int(CONFIG['consensus'].get('lottery_scale', 1 << 249))
ATTEST_FRESH_BUFFER = int(CONFIG['consensus'].get('attest_fresh_buffer', 5))
ATTEST_GROWTH_PER_BLOCK = int(CONFIG['consensus'].get('attest_growth_per_block', 5))
SLOT_TIMEOUT = int(CONFIG['consensus'].get('slot_timeout', 30))
CONSENSUS_PARAM_KEYS = ('lottery_scale', 'attest_fresh_buffer', 'attest_growth_per_block', 'slot_timeout')

def _consensus_defaults():
    _c = DEFAULT_CONFIG.get('consensus', {})
    return {'lottery_scale': int(_c.get('lottery_scale', 1 << 249)), 'attest_fresh_buffer': int(_c.get('attest_fresh_buffer', 5)), 'attest_growth_per_block': int(_c.get('attest_growth_per_block', 5)), 'slot_timeout': int(_c.get('slot_timeout', 30))}

def _validate_lottery_value(name, v, minimum: int) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f'config consensus.{name} must be an int >= {minimum}, got {v!r}')
    if v < minimum:
        raise ValueError(f'config consensus.{name} must be an int >= {minimum}, got {v!r}')
    return v

def _strict_bool(name, v, default=False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s == 'true':
            return True
        if s == 'false':
            return False
    raise ValueError(f'config {name} must be a boolean (true/false), got {v!r}')

def apply_consensus_config(config) -> dict:
    import genesis
    global LOTTERY_SCALE, ATTEST_FRESH_BUFFER, ATTEST_GROWTH_PER_BLOCK, SLOT_TIMEOUT, VALIDATORS
    global MAX_MISSES, BAN_DURATION, PRUNE_BLOCKS, WALL_DENSITY_3D
    global GAS_PRICE, GAS_LIMIT_DEFAULT, MAX_BYTECODE
    global MAX_BLOCK_GAS, MAX_BLOCK_TXS, HTLC_V1_ENABLED
    _c = (config or {}).get('consensus', {}) or {}
    _vals = validate_validators_config(_c.get('validators'))
    rec = genesis._consensus_record_from_config(config)
    LOTTERY_SCALE = rec['lottery_scale']
    ATTEST_FRESH_BUFFER = rec['attest_fresh_buffer']
    ATTEST_GROWTH_PER_BLOCK = rec['attest_growth_per_block']
    SLOT_TIMEOUT = rec['slot_timeout']
    VALIDATORS = _vals
    MAX_MISSES = rec['max_misses']
    BAN_DURATION = rec['ban_duration']
    PRUNE_BLOCKS = rec['prune_blocks']
    WALL_DENSITY_3D = rec['wall_density_3d']
    GAS_PRICE = rec['gas_price']
    GAS_LIMIT_DEFAULT = rec['gas_limit_default']
    MAX_BYTECODE = rec['max_bytecode']
    MAX_BLOCK_GAS = rec['max_block_gas']
    MAX_BLOCK_TXS = rec['max_block_txs']
    HTLC_V1_ENABLED = rec['htlc_v1_enabled']
    return {'lottery_scale': LOTTERY_SCALE, 'attest_fresh_buffer': ATTEST_FRESH_BUFFER, 'attest_growth_per_block': ATTEST_GROWTH_PER_BLOCK, 'slot_timeout': SLOT_TIMEOUT, 'validators': sorted(_effective_validators()), 'max_misses': int(MAX_MISSES), 'ban_duration': int(BAN_DURATION), 'prune_blocks': int(PRUNE_BLOCKS), 'wall_density_3d': float(WALL_DENSITY_3D), 'gas_price': int(GAS_PRICE), 'gas_limit_default': int(GAS_LIMIT_DEFAULT), 'max_bytecode': int(MAX_BYTECODE), 'max_block_gas': int(MAX_BLOCK_GAS), 'max_block_txs': int(MAX_BLOCK_TXS), 'htlc_v1_enabled': bool(HTLC_V1_ENABLED)}

def check_consensus_params(config, genesis_data):
    import genesis
    try:
        _want = genesis._consensus_record_from_config(config)
    except (TypeError, ValueError):
        return (False, 'unparseable consensus config')
    _rec = (genesis_data or {}).get('consensus') if isinstance(genesis_data, dict) else None
    if not isinstance(_rec, dict):
        return (True, 'grandfathered-no-record')
    _want = {k: v for k, v in _want.items() if k != 'prune_blocks'}
    _rec = {k: v for k, v in _rec.items() if k != 'prune_blocks'}

    def _diff(path, want, got):
        if isinstance(want, dict):
            if not isinstance(got, dict):
                return f'{path or 'consensus'} missing/unparseable in genesis record'
            for _k in want:
                _r = _diff(f'{path}.{_k}' if path else str(_k), want[_k], got.get(_k))
                if _r:
                    return _r
            return ''
        if got != want:
            return f'{path} mismatch: config={want!r} genesis={got!r}'
        return ''
    _reason = _diff('', _want, _rec)
    if _reason:
        return (False, _reason)
    return (True, 'ok')

def _normalize_validator_key(v) -> str:
    s = str(v).strip().lower()
    if s.startswith('0x'):
        s = s[2:]
    return s

def _normalize_validator_list(vals) -> list:
    try:
        if not isinstance(vals, (list, tuple)):
            return []
        return sorted({_normalize_validator_key(v) for v in vals if v})
    except Exception:
        return []
_VALIDATOR_KEY_RE = bootstrap.re.compile('^04[0-9a-f]{128}$')

def validate_validators_config(raw) -> list:
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        raise ValueError(f"consensus.validators must be a YAML LIST of public keys (got {type(raw).__name__}); a single key still needs list syntax: '- 04ab...'")
    out = set()
    for i, v in enumerate(raw):
        if not isinstance(v, str):
            raise ValueError(f'consensus.validators[{i}] must be a string public key')
        k = _normalize_validator_key(v)
        if not _VALIDATOR_KEY_RE.fullmatch(k):
            raise ValueError(f"consensus.validators[{i}] is not an uncompressed secp256k1 public key (expected '04' + 128 hex chars, got {len(k)} chars)")
        out.add(k)
    return sorted(out)

def _effective_validators() -> frozenset:
    return frozenset()
_VALIDATOR_MODE_WARNED = False

def _validator_boot_mode() -> str:
    global _VALIDATOR_MODE_WARNED
    _configured = []
    try:
        _configured = _normalize_validator_list(VALIDATORS or [])
    except Exception:
        _configured = []
    if _configured and (not _VALIDATOR_MODE_WARNED):
        _VALIDATOR_MODE_WARNED = True
        bootstrap.logger.warning('[VALIDATORS] consensus.validators lists %d producer key(s) but open mining is in effect (C1): the producer set is ignored and any eligible maze may produce.', len(_configured))
    return 'open'
EXPECTED_GENESIS_PIN = None

def _expected_genesis_pin(config):
    raw = ((config or {}).get('p2p') or {}).get('expected_genesis_hash', None)
    if raw is None:
        _code_pin = (TESTNET_GENESIS_HASH or '').strip().lower()
        if _code_pin:
            if len(_code_pin) != 64 or any((c not in '0123456789abcdef' for c in _code_pin)):
                raise ValueError('TESTNET_GENESIS_HASH must be exactly 64 hex characters')
            return _code_pin
        return None
    if not isinstance(raw, str):
        raise ValueError('p2p.expected_genesis_hash must be a string of 64 hex characters')
    v = raw.strip().lower()
    if len(v) != 64 or any((c not in '0123456789abcdef' for c in v)):
        raise ValueError('p2p.expected_genesis_hash must be exactly 64 hex characters')
    return v

def _genesis_pin_failure(gh, pin):
    if pin is None:
        return None
    if str(gh or '').strip().lower() != pin:
        return f'peer genesis {str(gh or '')[:16]} does not match pinned p2p.expected_genesis_hash {pin[:16]}'
    return None

def _update_genesis_pin_in_file(new_hash):
    global TESTNET_GENESIS_HASH
    _new = str(new_hash or '').strip().lower()
    if len(_new) != 64 or any((c not in '0123456789abcdef' for c in _new)):
        return
    if (TESTNET_GENESIS_HASH or '').strip().lower() == _new:
        return
    try:
        _src = bootstrap.os.path.abspath(__file__)
        with open(_src, 'rb') as _f:
            _data = _f.read()
        _old_line = ('TESTNET_GENESIS_HASH = "' + (TESTNET_GENESIS_HASH or '').strip() + '"').encode('utf-8')
        if _data.count(_old_line) != 1:
            raise RuntimeError('pin line not found exactly once')
        _new_line = ('TESTNET_GENESIS_HASH = "' + _new + '"').encode('utf-8')
        _data = _data.replace(_old_line, _new_line)
        _tmp = _src + '.tmp-pin'
        with open(_tmp, 'wb') as _f:
            _f.write(_data)
        bootstrap.os.replace(_tmp, _src)
        TESTNET_GENESIS_HASH = _new
        bootstrap.logger.info('[GENESIS] genesis pin updated in %s to %s... (distribute this file to followers)', _src, _new[:16])
    except Exception as _e:
        bootstrap.logger.warning('[GENESIS] could not update the genesis pin in the node file (%s); followers must set p2p.expected_genesis_hash to %s', _e, _new)

def _mainnet_guard_failures(config, allow_new_genesis=False) -> list:
    _cfg = config or {}
    failures = []
    _db_url = str((_cfg.get('database') or {}).get('url', '') or '')
    if _db_url.startswith('postgresql://'):
        if bootstrap.os.environ.get('MCX_PG_PASSWORD') in (None, '', 'postgres'):
            failures.append('MCX_PG_PASSWORD must be set to a non-default value')
        if bootstrap.os.environ.get('MCX_DB_PASS') in (None, '', 'postgres'):
            failures.append('MCX_DB_PASS must be set to a non-default value')
    _vm = _cfg.get('vm') or {}
    if not bool(_vm.get('require_sandbox', False)):
        failures.append('vm.require_sandbox must be true')
    if bootstrap.sys.platform == 'win32' and bool(_vm.get('require_sandbox', False)):
        _ov = bootstrap.os.environ.get('MCX_ALLOW_UNSANDBOXED_VM', '').strip().lower()
        if _ov not in ('1', 'true', 'yes', 'on'):
            try:
                _ans = input('[SANDBOX] Windows VM worker is not isolated. Accept this risk? (y/n): ').strip().lower()
            except EOFError:
                _ans = ''
            if _ans not in ('y', 'yes'):
                failures.append('on Windows the VM worker is not isolated: run on Linux, or set MCX_ALLOW_UNSANDBOXED_VM=1 to accept that risk knowingly')
    try:
        if _expected_genesis_pin(_cfg) is None and (not allow_new_genesis):
            failures.append('p2p.expected_genesis_hash must be set (64 hex chars) unless this is the genesis creator')
    except ValueError as _pe:
        failures.append(str(_pe))
    _rtl = (_cfg.get('node') or {}).get('rpc_trust_loopback', True)
    if _rtl is None or bool(_rtl):
        failures.append('node.rpc_trust_loopback must be false')
    return failures
FINALITY_THRESHOLD = CONFIG['consensus'].get('finality_threshold', 0.66)
FINALITY_EPOCH_LENGTH = 100
RBF_INCREMENT = CONFIG['fees'].get('rbf_increment', 1.1)
CPFP_MIN_FEE = CONFIG['fees'].get('cpfp_min_fee', 100)
INITIAL_BLOCK_REWARD = 1000000
HALVING_INTERVAL = 2522880
GENESIS_SUPPLY = 200 * SUBS
FIRST_ERA_MINT_HEIGHTS = HALVING_INTERVAL - 1
MAX_SUPPLY = 2 * FIRST_ERA_MINT_HEIGHTS * INITIAL_BLOCK_REWARD + GENESIS_SUPPLY
TOKEN_MAX_SUPPLY = 5045760 * SUBS
TOKEN_MAX_MINEABLE_SUPPLY = TOKEN_MAX_SUPPLY
HTLC_V1_ENABLED = _strict_bool('consensus.htlc_v1_enabled', CONFIG['consensus'].get('htlc_v1_enabled', False))
TOKEN_DEFAULT_DECIMALS = 18
DISCOVERY_INTERVAL = 300
HEARTBEAT_INTERVAL = 30
SYNC_INTERVAL = 10
CHECKPOINT_SYNC_THRESHOLD = 500
SYNC_STUCK_TRIP_COOLDOWN = 300
DHT_PORT = int(CONFIG.get('p2p', {}).get('dht_port', 8083))
DHT_BOOTSTRAP_NODES = [(GENESIS_NODE_HOST, GENESIS_NODE_DHT_PORT)]
DHT_SHARD_COUNT = 16
DHT_PEERS_KEY_PREFIX = 'mcx_peers_shard_'
DHT_ENTRY_TTL = 600
DHT_MAX_ENTRIES_PER_SHARD = 64
PEER_CACHE_FILE = 'microcore_peers.json'
P2P_MAGIC = b'MCX1'
P2P_VERSION = 1
ASN_STATIC_MAP = (('3.0.0.0/8', 'AS16509-AWS'), ('13.32.0.0/15', 'AS16509-AWS'), ('13.64.0.0/11', 'AS8075-AZURE'), ('18.0.0.0/8', 'AS16509-AWS'), ('20.0.0.0/8', 'AS8075-AZURE'), ('34.64.0.0/10', 'AS396982-GCP'), ('34.192.0.0/10', 'AS14618-AWS'), ('35.152.0.0/13', 'AS14618-AWS'), ('35.184.0.0/13', 'AS396982-GCP'), ('35.192.0.0/12', 'AS396982-GCP'), ('40.64.0.0/10', 'AS8075-AZURE'), ('46.101.0.0/16', 'AS14061-DIGITALOCEAN'), ('51.104.0.0/13', 'AS8075-AZURE'), ('52.0.0.0/8', 'AS16509-AWS'), ('54.0.0.0/8', 'AS14618-AWS'), ('64.225.0.0/16', 'AS14061-DIGITALOCEAN'), ('68.183.0.0/16', 'AS14061-DIGITALOCEAN'), ('95.216.0.0/16', 'AS24940-HETZNER'), ('104.16.0.0/13', 'AS13335-CLOUDFLARE'), ('104.24.0.0/14', 'AS13335-CLOUDFLARE'), ('104.131.0.0/16', 'AS14061-DIGITALOCEAN'), ('104.196.0.0/14', 'AS396982-GCP'), ('116.202.0.0/15', 'AS24940-HETZNER'), ('116.203.0.0/16', 'AS24940-HETZNER'), ('128.140.0.0/17', 'AS24940-HETZNER'), ('138.68.0.0/16', 'AS14061-DIGITALOCEAN'), ('142.132.128.0/17', 'AS24940-HETZNER'), ('159.65.0.0/16', 'AS14061-DIGITALOCEAN'), ('159.69.0.0/16', 'AS24940-HETZNER'), ('165.227.0.0/16', 'AS14061-DIGITALOCEAN'), ('167.99.0.0/16', 'AS14061-DIGITALOCEAN'), ('168.119.0.0/16', 'AS24940-HETZNER'), ('172.64.0.0/13', 'AS13335-CLOUDFLARE'), ('176.9.0.0/16', 'AS24940-HETZNER'), ('178.62.0.0/16', 'AS14061-DIGITALOCEAN'), ('188.166.0.0/16', 'AS14061-DIGITALOCEAN'), ('195.201.0.0/16', 'AS24940-HETZNER'), ('206.189.0.0/16', 'AS14061-DIGITALOCEAN'))
MSG_HANDSHAKE, MSG_PING, MSG_PONG, MSG_GET_BLOCKS, MSG_BLOCKS, MSG_NEW_BLOCK, MSG_NEW_TX, MSG_GET_PEERS, MSG_PEERS, MSG_SLASH, MSG_BAN, MSG_UNBAN, MSG_GET_STATUS, MSG_STATUS, MSG_GET_CHECKPOINT, MSG_CHECKPOINT = range(1, 17)
MSG_NEW_MOVE = 17
GENESIS_FILE = 'genesis.json'
