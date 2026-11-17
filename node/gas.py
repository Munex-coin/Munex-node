import bootstrap
import config
import util

def _gas_ceiling(gas_in) -> int:
    try:
        g = config.GAS_LIMIT_DEFAULT if gas_in is None else gas_in
        if isinstance(g, str):
            g = int(g, 16) if g.lower().startswith('0x') else int(g)
        g = int(g)
    except (TypeError, ValueError):
        g = config.GAS_LIMIT_DEFAULT
    return max(0, g)
VM_GAS_TX_TYPES = ('contract_deploy', 'contract_call', 'htlc_create')

def _gas_data_cost(data_bytes) -> int:
    if not data_bytes:
        return 0
    _z = data_bytes.count(0)
    return _z * config.GAS_PER_ZERO_BYTE + (len(data_bytes) - _z) * config.GAS_PER_NONZERO_BYTE

def _gas_data_bytes(d) -> bytes:
    if d is None:
        return b''
    if isinstance(d, bytes):
        return d
    if isinstance(d, dict):
        return _gas_data_bytes(d.get('raw', ''))
    if isinstance(d, str):
        _s = d[2:] if d.startswith(('0x', '0X')) else d
        if not _s:
            return b''
        try:
            return bytes.fromhex(_s)
        except ValueError:
            return d.encode()
    return util.tx_data_to_bytes(d)

def _gas_intrinsic(tx) -> int:
    _t = str(tx.get('tx_type', 'send')) if isinstance(tx, dict) else 'send'
    _cost = config.GAS_BASE_COST
    _data = None
    if isinstance(tx, dict):
        if _t == 'contract_deploy':
            _cost += config.GAS_CREATE_COST
            _raw = tx.get('bytecode', tx.get('data'))
            _data = _gas_data_bytes(_raw) if _raw is not None else b''
        elif _t in ('contract_call', 'htlc_create'):
            _raw = tx.get('data', tx.get('input', b''))
            _data = _gas_data_bytes(_raw) if _raw is not None else b''
        elif tx.get('data') is not None:
            _data = _gas_data_bytes(tx.get('data'))
    if _data:
        _cost += _gas_data_cost(_data)
    return _cost

def _gas_price_of(tx) -> int:
    try:
        _p = tx.get('gasPrice', tx.get('gas_price', config.GAS_PRICE)) if isinstance(tx, dict) else config.GAS_PRICE
        _p = int(_p)
    except (TypeError, ValueError):
        _p = config.GAS_PRICE
    return _p if _p >= 0 else config.GAS_PRICE

def _tx_declared_gas(tx) -> int:
    if not isinstance(tx, dict):
        raise ValueError('transaction is not an object')
    if tx.get('tx_type') in VM_GAS_TX_TYPES:
        return _gas_ceiling(tx.get('gas', config.GAS_LIMIT_DEFAULT))
    _g = tx.get('gas')
    if _g is None:
        return _gas_intrinsic(tx)
    try:
        _g = int(_g, 16) if isinstance(_g, str) and _g.lower().startswith('0x') else int(_g)
    except (TypeError, ValueError):
        return _gas_intrinsic(tx)
    return max(_gas_intrinsic(tx), _g)

def _block_limits_ok(tx_list):
    try:
        txs = tx_list or []
        if len(txs) > config.MAX_BLOCK_TXS:
            return (False, f'{len(txs)} txs > MAX_BLOCK_TXS {config.MAX_BLOCK_TXS}')
        total = 0
        for t in txs:
            total += _tx_declared_gas(t)
            if total > config.MAX_BLOCK_GAS:
                return (False, f'declared gas {total} > MAX_BLOCK_GAS {config.MAX_BLOCK_GAS}')
        return (True, '')
    except (TypeError, ValueError, OverflowError) as e:
        return (False, f'malformed transactions: {e}')

def get_block_reward(height):
    halvings = height // config.HALVING_INTERVAL
    reward = config.INITIAL_BLOCK_REWARD
    for _ in range(halvings):
        reward //= 2
        if reward == 0:
            break
    return reward

def _validated_block_reward(block: dict, canonical_minted: int):
    try:
        bid = int(block.get('id', -1))
        if bid <= 0:
            if int(block.get('reward', 0) or 0) != 0 or int(block.get('total_fees', 0) or 0) != 0:
                return None
            return (0, 0, 0)
        txs = block.get('transactions', [])
        if txs is None:
            txs = []
        fees = 0
        for _tx in txs:
            if not isinstance(_tx, dict):
                return None
            fees += int(_tx.get('_fee_charged', _tx.get('fee', 0)) or 0)
        if int(block.get('total_fees', 0) or 0) != fees:
            return None
        subsidy = get_block_reward(bid)
        room = int(canonical_minted if canonical_minted else 0)
        room = config.MAX_SUPPLY - room
        if room < 0:
            room = 0
        base = subsidy if subsidy < room else room
        if int(block.get('reward', 0) or 0) != base + fees:
            return None
        return (base, fees, base + fees)
    except (TypeError, ValueError, OverflowError):
        return None

def _reorg_base_mint(block: dict) -> int:
    try:
        return max(0, int(block.get('reward', 0) or 0) - int(block.get('total_fees', 0) or 0))
    except (TypeError, ValueError):
        return 0
TOKEN_TRANSFER_FEE_PER_BYTE = 1
_tt_v2_raw = (config.CONFIG.get('fees') or {}).get('token_transfer_v2', False)
if not isinstance(_tt_v2_raw, bool):
    raise SystemExit('[CONFIG] fees.token_transfer_v2 must be a YAML boolean')
TOKEN_FEE_V2_ENABLED = _tt_v2_raw
TOKEN_TRANSFER_SIG_WIRE_BYTES = 65
TYPICAL_TOKEN_TRANSFER_BYTES = 200
MAX_TOKEN_BURN_BPS = 1000
_TOKEN_TRANSFER_SIZE_FIELDS = ('tx_type', 'from_wallet', 'to_wallet', 'token_address', 'value', 'nonce', 'timestamp', 'data')
_TOKEN_TRANSFER_INT_FIELDS = ('value', 'nonce')
SVF_FEE_BASE = 1000
SVF_FEE_CREATE = 500000

def get_token_creation_fee(mempool_size):
    return SVF_FEE_CREATE

def token_transfer_size_bytes(tx) -> int:
    body = {}
    for k in _TOKEN_TRANSFER_SIZE_FIELDS:
        v = tx.get(k)
        if v is None:
            continue
        if k in _TOKEN_TRANSFER_INT_FIELDS:
            if isinstance(v, bool):
                raise ValueError(f'{k} must not be a boolean')
            v = int(v)
        elif k == 'timestamp':
            v = int(float(v))
        body[k] = v
    payload = bootstrap.json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    return len(payload) + int(TOKEN_TRANSFER_SIG_WIRE_BYTES)

def token_transfer_fee(tx) -> int:
    fee = SVF_FEE_BASE + token_transfer_size_bytes(tx) * int(TOKEN_TRANSFER_FEE_PER_BYTE)
    if fee <= 0:
        raise ValueError('token transfer fee must be positive')
    return fee
_TOKEN_BURN_SIZE_FIELDS = ('token_address', 'from_wallet', 'value', 'nonce', 'timestamp')
_TOKEN_BURN_INT_FIELDS = ('value', 'nonce')

def token_burn_size_bytes(tx) -> int:
    body = {}
    for k in _TOKEN_BURN_SIZE_FIELDS:
        v = tx.get(k)
        if v is None:
            continue
        if k in _TOKEN_BURN_INT_FIELDS:
            if isinstance(v, bool):
                raise ValueError(f'{k} must not be a boolean')
            v = int(v)
        elif k == 'timestamp':
            v = int(float(v))
        body[k] = v
    payload = bootstrap.json.dumps(body, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')
    return len(payload) + int(TOKEN_TRANSFER_SIG_WIRE_BYTES)

def token_burn_fee(tx) -> int:
    fee = SVF_FEE_BASE + token_burn_size_bytes(tx) * int(TOKEN_TRANSFER_FEE_PER_BYTE)
    if fee <= 0:
        raise ValueError('token burn fee must be positive')
    return fee

def _svf_native_fee(tx) -> int:
    _t = str(tx.get('tx_type', 'send')) if isinstance(tx, dict) else 'send'
    if _t == 'token_create':
        return SVF_FEE_CREATE
    if _t == 'token_transfer':
        return token_transfer_fee(tx)
    if _t == 'token_burn':
        return token_burn_fee(tx)
    return 0

def quote_transfer_fee(mempool_size) -> int:
    return config.GAS_BASE_COST * config.GAS_PRICE

def quote_token_transfer_fee() -> int:
    return SVF_FEE_BASE + int(TOKEN_TRANSFER_FEE_PER_BYTE) * int(TYPICAL_TOKEN_TRANSFER_BYTES) + int(TOKEN_TRANSFER_SIG_WIRE_BYTES) * int(TOKEN_TRANSFER_FEE_PER_BYTE)

def quote_token_creation_fee(mempool_size) -> int:
    return get_token_creation_fee(mempool_size)

def _temporal_fee_ok(temporal_config) -> bool:
    try:
        v = int((temporal_config or {}).get('burn_fee_bps', 0) or 0)
    except (TypeError, ValueError, AttributeError):
        return False
    return 0 <= v <= MAX_TOKEN_BURN_BPS

def _tx_size(tx: bootstrap.Dict) -> int:
    return len(bootstrap.json.dumps(tx, separators=(',', ':')).encode('utf-8'))
