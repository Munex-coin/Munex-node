import bootstrap
import config
BLOCK_TIME_WINDOW_MAX = 7200
MEDIAN_WINDOW_BLOCKS = 11

def _median_ancestor_timestamp(ancestor_ts: list) -> float:
    vals = sorted((float(t) for t in ancestor_ts or [] if isinstance(t, (int, float))))
    if not vals:
        return 0.0
    n = len(vals)
    if n % 2 == 1:
        return vals[n // 2]
    return (vals[n // 2 - 1] + vals[n // 2]) / 2.0

def _block_timestamp_ok(block_ts, ancestor_ts, is_genesis=False) -> bool:
    if is_genesis:
        return True
    try:
        T = float(block_ts)
    except (TypeError, ValueError, OverflowError):
        return False
    M = _median_ancestor_timestamp(ancestor_ts)
    if M <= 0:
        return False
    return M < T <= M + BLOCK_TIME_WINDOW_MAX

def _clamp_producer_timestamp(now_ts, ancestor_ts) -> float:
    M = _median_ancestor_timestamp(ancestor_ts)
    if M <= 0:
        M = float(now_ts)
    lo = M + 1.0
    hi = M + BLOCK_TIME_WINDOW_MAX
    return max(lo, min(float(now_ts), hi))

def _chain_time_drift_seconds(chain_time, local_clock) -> float:
    return abs(float(chain_time) - float(local_clock))

def _topic_to_int(t):
    try:
        if isinstance(t, int):
            return t
        s = str(t).strip()
        return int(s, 16) if s.lower().startswith('0x') else int(s)
    except (TypeError, ValueError):
        return None

def _log_matches_filter(log_address, log_topics, addresses, topics) -> bool:
    try:
        if addresses is not None:
            want = [addresses] if isinstance(addresses, str) else list(addresses)
            if str(log_address or '').lower() not in [str(a or '').lower() for a in want]:
                return False
        if topics:
            lt = []
            for _t in log_topics or []:
                _ti = _topic_to_int(_t)
                if _ti is None:
                    return False
                lt.append(_ti)
            for _i, _f in enumerate(topics):
                if _f is None:
                    continue
                _want = _f if isinstance(_f, list) else [_f]
                _wi = []
                for _x in _want:
                    _xi = _topic_to_int(_x)
                    if _xi is None:
                        return False
                    _wi.append(_xi)
                if _i >= len(lt) or lt[_i] not in _wi:
                    return False
    except Exception:
        return False
    return True

def _enrich_eth_log(log, block_hash, block_number, tx_hash, tx_index, log_index) -> dict:
    try:
        _topics = []
        for _t in log.get('topics') or []:
            _ti = _topic_to_int(_t)
            _topics.append('0x' + (int(_ti).to_bytes(32, 'big').hex() if _ti is not None else '00' * 32))
    except Exception:
        _topics = []
    _data = log.get('data', '')
    _data = _data if isinstance(_data, str) and _data.startswith('0x') else '0x' + (str(_data) if isinstance(_data, str) else '')
    return {'address': log.get('address', ''), 'topics': _topics, 'data': _data, 'blockHash': block_hash, 'blockNumber': block_number, 'transactionHash': tx_hash, 'transactionIndex': tx_index, 'logIndex': hex(log_index), 'removed': False}

def _eth_sig_fields(tx: dict):
    try:
        sig = tx.get('signature', '')
        if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
            decoded = decode_raw_eth_transaction(sig)
            v = int(decoded.get('v', 0) or 0)
            r = int(decoded.get('r', 0) or 0)
            s = int(decoded.get('s', 0) or 0)
            if v and r and s:
                return (hex(v), hex(r), hex(s))
    except Exception:
        pass
    return (None, None, None)

def _logs_bloom(logs) -> str:
    try:
        arr = bytearray(256)
        items = []
        for log in logs or []:
            if not isinstance(log, dict):
                continue
            try:
                items.append(bytes.fromhex(str(log.get('address', '')).removeprefix('0x')))
            except (ValueError, AttributeError):
                pass
            for _t in log.get('topics') or []:
                try:
                    _ti = _topic_to_int(_t)
                    if _ti is None:
                        continue
                    items.append(int(_ti).to_bytes(32, 'big'))
                except Exception:
                    continue
        for _x in items:
            try:
                _h = bootstrap.eth_keccak(bytes(_x))
            except Exception:
                continue
            for _k in range(3):
                _pos = _h[2 * _k] * 256 + _h[2 * _k + 1] & 2047
                arr[255 - (_pos >> 3)] |= 1 << (_pos & 7)
        return '0x' + bytes(arr).hex()
    except Exception:
        return '0x' + '00' * 256

def _cumulative_gas_used(ordered_pairs, tx_hash) -> int:
    try:
        _total = 0
        for _h, _g in ordered_pairs:
            _total += int(_g or 0)
            if _h == tx_hash:
                return _total
    except Exception:
        pass
    return 0

def _tx_lists_consistent(tx_hashes, tx_list):
    try:
        if not isinstance(tx_hashes, list) or not isinstance(tx_list, list):
            return (False, 'not lists')
        if len(tx_hashes) != len(tx_list):
            return (False, 'length mismatch')
        for _h, _t in zip(tx_hashes, tx_list):
            if not isinstance(_t, dict) or _t.get('tx_hash') != _h:
                return (False, 'ordered hash mismatch')
    except Exception:
        return (False, 'uncomparable')
    return (True, '')

def pubkey_to_address(pub_hex: str) -> str:
    pub_hex = pub_hex.removeprefix('0x')
    if pub_hex.startswith('04'):
        pub_bytes = bytes.fromhex(pub_hex)
        if len(pub_bytes) != 65 or pub_bytes[0] != 4:
            raise ValueError('Expected an uncompressed secp256k1 public key')
        return '0x' + bootstrap.eth_keccak(pub_bytes[1:])[-20:].hex()
    return pub_hex if pub_hex.startswith('0x') else '0x' + pub_hex

def checksum_address(addr: str) -> str:
    raw = addr.lower().removeprefix('0x')
    if len(raw) != 40 or not all((ch in '0123456789abcdef' for ch in raw)):
        raise ValueError('Invalid address')
    digest = bootstrap.eth_keccak(raw.encode('ascii')).hex()
    return '0x' + ''.join((ch.upper() if ch in 'abcdef' and int(digest[i], 16) >= 8 else ch for i, ch in enumerate(raw)))
_LOCALHOST_ORIGIN_RE = bootstrap.re.compile('^https?://(localhost|127\\.0\\.0\\.1|\\[::1\\])(:\\d+)?$')

def _cors_origin_allowed(origin) -> bool:
    if not origin or not isinstance(origin, str):
        return False
    return bool(_LOCALHOST_ORIGIN_RE.match(origin))

def _validate_ws_bind(ws_bind_ip, ws_port, api_port):
    _bind = str(ws_bind_ip if ws_bind_ip not in (None, '') else '0.0.0.0')
    if _bind.lower() == 'all':
        _bind = '0.0.0.0'
    if _bind not in ('0.0.0.0', '::'):
        try:
            bootstrap.ipaddress.ip_address(_bind)
        except ValueError:
            raise ValueError(f'node.ws_bind_ip must be 0.0.0.0, ::, or a valid IP literal, got {_bind!r}')
    for _name, _p in (('node.ws_port', ws_port), ('node.api_port', api_port)):
        if isinstance(_p, bool):
            raise ValueError(f'{_name} must be an integer port 1..65535, got {_p!r}')
        try:
            _pi = int(str(_p).strip()) if isinstance(_p, str) else int(_p)
        except (TypeError, ValueError):
            raise ValueError(f'{_name} must be an integer port 1..65535, got {_p!r}')
        if isinstance(_p, float) or not 1 <= _pi <= 65535:
            raise ValueError(f'{_name} must be an integer port 1..65535, got {_p!r}')
    return (_bind, int(ws_port), int(api_port))

def _detect_lan_ip() -> str:
    try:
        s = bootstrap.socket.socket(bootstrap.socket.AF_INET, bootstrap.socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        lan_ip = s.getsockname()[0]
        s.close()
        return lan_ip or '127.0.0.1'
    except Exception:
        return '127.0.0.1'

class _BadInt(ValueError):
    pass

def _rint(data, key, default=0):
    try:
        return int(data.get(key, default))
    except (TypeError, ValueError):
        raise _BadInt(key)

def _rfloat_opt(data, key):
    if key not in data:
        return None
    try:
        return float(data.get(key))
    except (TypeError, ValueError):
        raise _BadInt(key)

def _ws_page_params(data):
    try:
        _lim = int(data.get('limit', 10))
    except (TypeError, ValueError):
        _lim = 10
    try:
        _off = int(data.get('offset', 0))
    except (TypeError, ValueError):
        _off = 0
    return (max(1, min(_lim, 500)), max(0, _off))

def get_public_ip():
    try:
        return bootstrap.requests.get('https://api.ipify.org', timeout=5).json()['ip']
    except Exception:
        try:
            return bootstrap.requests.get('https://icanhazip.com', timeout=5).text.strip()
        except Exception:
            bootstrap.logger.error('Failed to determine public IP — node cannot register on the network.')
            return None

def save_peers_to_cache(peers):
    try:
        with open(config.PEER_CACHE_FILE, 'w') as f:
            bootstrap.json.dump(list(set(peers)), f, indent=2)
    except Exception as e:
        bootstrap.logger.error(f'[CACHE] Save peers failed: {e}')

def load_peers_from_cache():
    try:
        with open(config.PEER_CACHE_FILE, 'r') as f:
            return bootstrap.json.load(f)
    except Exception:
        return []

def decode_raw_eth_transaction(raw_tx: str) -> dict:
    if raw_tx.startswith('0x'):
        raw_tx = raw_tx[2:]
    tx_bytes = bytes.fromhex(raw_tx)
    decoded = bootstrap.rlp.decode(tx_bytes)
    if len(decoded) != 9:
        raise ValueError('Only legacy transactions (9 fields) supported')
    nonce = int.from_bytes(decoded[0], 'big')
    gasPrice = int.from_bytes(decoded[1], 'big')
    gas = int.from_bytes(decoded[2], 'big')
    to = decoded[3].hex()
    to = '0x' + to if to else ''
    value = int.from_bytes(decoded[4], 'big')
    data = decoded[5].hex()
    v = int.from_bytes(decoded[6], 'big')
    r = int.from_bytes(decoded[7], 'big')
    s = int.from_bytes(decoded[8], 'big')
    chain_id = None
    if v >= 35:
        chain_id = (v - 35) // 2
    tx_hash = bootstrap.eth_keccak(tx_bytes).hex()
    from_addr = None
    try:
        if bootstrap.Account is not None:
            recovered = bootstrap.Account.recover_transaction(tx_bytes)
            from_addr = recovered.lower() if recovered.startswith('0x') else '0x' + recovered.lower()
    except Exception:
        from_addr = None
    return {'nonce': nonce, 'gasPrice': gasPrice, 'gas': gas, 'to': to, 'value': value, 'data': data, 'v': v, 'r': r, 's': s, 'hash': '0x' + tx_hash, 'from': from_addr, 'chainId': chain_id}

def _raw_chain_id_ok(decoded: dict) -> bool:
    try:
        return int(decoded.get('chainId')) == config.CHAIN_ID
    except (TypeError, ValueError):
        return False

def _derive_token_address(tx_hash: str, owner: str, name: str, symbol: str) -> str:
    return '0x' + bootstrap.eth_keccak(f'{tx_hash}:{owner}:{name}:{symbol}'.encode()).hex()[-40:]

def _moved_value_of(tx: dict) -> int:
    try:
        _v = int(tx.get('_value_moved', 0) or 0)
    except (TypeError, ValueError):
        _v = 0
    if not _v:
        try:
            _dd = tx.get('data') or {}
            if isinstance(_dd, str):
                _dd = bootstrap.json.loads(_dd)
            if isinstance(_dd, dict):
                _v = int(_dd.get('_value_moved', 0) or 0)
        except (TypeError, ValueError):
            _v = 0
    return _v if _v > 0 else 0

def compute_contract_address(sender: str, nonce: int) -> str:
    sender_bytes = bytes.fromhex(sender[2:] if sender.startswith('0x') else sender)
    if bootstrap.rlp is None:
        raise RuntimeError('rlp library is required for compute_contract_address')
    encoded = bootstrap.rlp.encode([sender_bytes, nonce])
    return '0x' + bootstrap.eth_keccak(encoded)[-20:].hex()

def tx_data_to_hex(d) -> str:
    if isinstance(d, dict):
        d = d.get('raw', '')
    if d is None:
        return ''
    return str(d)

def tx_data_to_bytes(d) -> bytes:
    s = tx_data_to_hex(d)
    if not s:
        return b''
    if s.startswith(('0x', '0X')):
        s = s[2:]
    try:
        return bytes.fromhex(s)
    except ValueError:
        return s.encode()

def _rlp_encode_int(val: int) -> bytes:
    if val == 0:
        return b'\x00'
    return val.to_bytes((val.bit_length() + 7) // 8, 'big')

def _rlp_encode_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 128:
        return data
    if len(data) < 56:
        return bytes([128 + len(data)]) + data
    length_bytes = _rlp_encode_int(len(data))
    return bytes([183 + len(length_bytes)]) + length_bytes + data

def _rlp_encode_list(items: list) -> bytes:
    payload = b''.join(items)
    if len(payload) < 56:
        return bytes([192 + len(payload)]) + payload
    length_bytes = _rlp_encode_int(len(payload))
    return bytes([247 + len(length_bytes)]) + length_bytes + payload

def _pg_convert_placeholders(query):
    result = []
    param_num = 1
    in_quote = False
    for i, c in enumerate(query):
        if in_quote:
            result.append(c)
            if c == "'" and (i == 0 or query[i - 1] != '\\'):
                in_quote = False
        elif c == "'":
            in_quote = True
            result.append(c)
        elif c == '?':
            result.append(f'${param_num}')
            param_num += 1
        else:
            result.append(c)
    return ''.join(result)

def _redact_dsn(text: str) -> str:
    try:
        return bootstrap.re.sub('(://)([^/@\\s]+)@', lambda m: m.group(1) + ('***' if ':' in m.group(2) else m.group(2)) + '@', str(text or ''))
    except Exception:
        return '<unprintable db error>'
