import bootstrap
import config
import config as _config
_SECRETS_DIR_CACHE: bootstrap.Optional[str] = None
_RPC_TOKEN_FILE_CACHE: bootstrap.Optional[str] = None
_RPC_TOKEN_FILE_TRIED = False

def _wallet_file_path() -> str:
    return bootstrap.os.path.join(bootstrap.os.path.dirname(bootstrap.os.path.abspath(config.CONFIG_PATH)), 'wallet.json')

def _read_wallet_file() -> dict:
    try:
        with open(_wallet_file_path(), 'r') as f:
            d = bootstrap.json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}

def _save_wallet_file(encrypted: str, address: str, pub: str) -> str:
    path = _wallet_file_path()
    data = bootstrap.json.dumps({'address': address, 'public_key': pub, 'private_key_encrypted': encrypted}, indent=2).encode('utf-8')
    _write_secret_file(path, data)
    return path

def _strip_wallet_from_config() -> None:
    if not bootstrap.os.path.exists(config.CONFIG_PATH):
        return
    with open(config.CONFIG_PATH, 'r') as f:
        d = bootstrap.yaml.safe_load(f) or {}
    d.pop('private_key_encrypted', None)
    d.pop('public_key', None)
    with open(config.CONFIG_PATH, 'w') as f:
        bootstrap.yaml.dump(d, f)

def _secrets_dir(config=None) -> str:
    global _SECRETS_DIR_CACHE
    if _SECRETS_DIR_CACHE:
        return _SECRETS_DIR_CACHE
    _d = bootstrap.os.getcwd()
    try:
        _url = (((config if config is not None else _config.CONFIG) or {}).get('database', {}) or {}).get('url')
        if isinstance(_url, str) and _url.lower().startswith('sqlite://'):
            _raw = _url[len('sqlite://'):].strip().strip('"\'')
            if _raw:
                _d = bootstrap.os.path.dirname(bootstrap.os.path.abspath(_raw)) or bootstrap.os.getcwd()
    except Exception:
        pass
    try:
        _existed = bootstrap.os.path.isdir(_d)
        bootstrap.os.makedirs(_d, exist_ok=True)
        if not _existed and bootstrap.os.name != 'nt':
            bootstrap.os.chmod(_d, 448)
    except Exception:
        pass
    _dl = _d.lower()
    if 'onedrive' in _dl or 'dropbox' in _dl or 'google drive' in _dl:
        bootstrap.logger.warning('[DATA-PATH] Node data directory %s is inside a cloud-synced folder (OneDrive/Dropbox/Google Drive). Files in this folder may sync to the cloud; keep secret files out of synced folders.', _d)
    _SECRETS_DIR_CACHE = _d
    return _d

def _write_secret_file(path, data: bytes) -> None:
    _d = bootstrap.os.path.dirname(path) or '.'
    _fd, _tmp = bootstrap.tempfile.mkstemp(prefix='.secret-', dir=_d)
    try:
        with bootstrap.os.fdopen(_fd, 'wb') as _f:
            _f.write(data)
            _f.flush()
            bootstrap.os.fsync(_f.fileno())
        if bootstrap.os.name != 'nt':
            bootstrap.os.chmod(_tmp, 384)
        bootstrap.os.replace(_tmp, path)
    except BaseException:
        try:
            bootstrap.os.unlink(_tmp)
        except Exception:
            pass
        raise

def _read_secret_file(path) -> str:
    try:
        if bootstrap.os.path.isfile(path):
            with open(path, 'rb') as _f:
                return _f.read().decode('utf-8').strip()
    except Exception:
        pass
    return ''

def _rpc_token_file_path(config=None) -> str:
    return bootstrap.os.path.abspath(bootstrap.os.path.join(_secrets_dir(config), 'rpc_token'))

def _rpc_bearer_token(config) -> str:
    try:
        _env = (bootstrap.os.environ.get('MCX_RPC_TOKEN', '') or '').strip()
        if _env:
            return _env
        _cfg = str(((config or {}).get('node', {}) or {}).get('rpc_token', '') or '').strip()
        if _cfg:
            return _cfg
        global _RPC_TOKEN_FILE_CACHE, _RPC_TOKEN_FILE_TRIED
        if not _RPC_TOKEN_FILE_TRIED:
            _RPC_TOKEN_FILE_TRIED = True
            _saved = _read_secret_file(_rpc_token_file_path(config))
            if _saved:
                _RPC_TOKEN_FILE_CACHE = _saved
        return _RPC_TOKEN_FILE_CACHE or ''
    except Exception:
        return ''

def _generate_and_save_rpc_token(config) -> str:
    global _RPC_TOKEN_FILE_CACHE, _RPC_TOKEN_FILE_TRIED
    _tok = ''
    for _ in range(8):
        _tok = bootstrap.secrets.token_urlsafe(24)
        if len(_tok) >= 24 and (not _is_weak_token(_tok)):
            break
    else:
        bootstrap.logger.error('[RPC-AUTH] Could not generate a token that passes the strength checks (8 attempts). Refusing to start.')
        return ''
    try:
        _path = _rpc_token_file_path(config)
        _write_secret_file(_path, (_tok + '\n').encode('utf-8'))
        _RPC_TOKEN_FILE_CACHE = _tok
        _RPC_TOKEN_FILE_TRIED = True
        bootstrap.logger.warning(f'[RPC-AUTH] No RPC token configured. Generated one and saved it to {_path}. Read it from that file, or set MCX_RPC_TOKEN.')
        return _tok
    except Exception as e:
        bootstrap.logger.error(f'[RPC-AUTH] Generated an RPC token but could not save it to disk ({e}). Refusing to start.')
        return ''
_RPC_TRUST_BAD_LOGGED = False
_RPC_TRUST_ABSENT = object()

def _rpc_trust_loopback_raw(config):
    node = config.get('node') if isinstance(config, dict) else None
    if not isinstance(node, dict):
        return _RPC_TRUST_ABSENT
    return node['rpc_trust_loopback'] if 'rpc_trust_loopback' in node else _RPC_TRUST_ABSENT

def validate_rpc_security_config(config) -> None:
    _raw = _rpc_trust_loopback_raw(config)
    if _raw is _RPC_TRUST_ABSENT:
        return
    if _raw is None:
        raise ValueError('config node.rpc_trust_loopback must be a boolean (true/false), got None (explicit null is malformed; omit the key for the legacy default)')
    _config._strict_bool('node.rpc_trust_loopback', _raw, True)

def _rpc_trust_loopback_effective(config) -> bool:
    global _RPC_TRUST_BAD_LOGGED
    _raw_eff = _rpc_trust_loopback_raw(config)
    if _raw_eff is _RPC_TRUST_ABSENT:
        return True
    if _raw_eff is None:
        if not _RPC_TRUST_BAD_LOGGED:
            _RPC_TRUST_BAD_LOGGED = True
            bootstrap.logger.error('[RPC-AUTH] config node.rpc_trust_loopback is null (malformed) — failing closed: loopback NOT trusted, bearer token required')
        return False
    try:
        return _config._strict_bool('node.rpc_trust_loopback', _raw_eff, True)
    except ValueError as _e:
        if not _RPC_TRUST_BAD_LOGGED:
            _RPC_TRUST_BAD_LOGGED = True
            bootstrap.logger.error(f'[RPC-AUTH] {_e} — failing closed: loopback NOT trusted, bearer token required')
        return False
_TOKEN_WEAK_SUBSTRINGS = ('changeme', 'replaceme', 'placeholder', 'yourtoken', 'yoursecret', 'example')

def _normalise_token(token: str) -> str:
    return token.casefold().replace('_', '').replace('-', '').replace(' ', '')

def _is_weak_token(token: str) -> bool:
    if not token:
        return False
    normalised = _normalise_token(token)
    for bad in _TOKEN_WEAK_SUBSTRINGS:
        if bad in normalised:
            return True
    if len(set(normalised)) < 10:
        return True
    return False

def _bind_is_loopback_only(bind_ip) -> bool:
    if not bind_ip or not isinstance(bind_ip, str):
        return False
    s = bind_ip.strip()
    if s.lower() in ('localhost', 'ip6-localhost', 'ipv6-localhost'):
        return True
    try:
        return bootstrap.ipaddress.ip_address(s).is_loopback
    except ValueError:
        try:
            infos = bootstrap.socket.getaddrinfo(s, None, type=bootstrap.socket.SOCK_STREAM)
        except OSError:
            return False
        return bool(infos) and all((bootstrap.ipaddress.ip_address(info[4][0]).is_loopback for info in infos))

def validate_rpc_startup_token(config) -> None:
    _rpc_bind = str((config or {}).get('node', {}).get('rpc_bind_ip', _config.RPC_BIND_IP) or _config.RPC_BIND_IP)
    _loopback_only = _bind_is_loopback_only(_rpc_bind)
    _trust_loopback = _rpc_trust_loopback_effective(config)
    _token_required = not _loopback_only or not _trust_loopback
    if not _token_required:
        return
    _token = _rpc_bearer_token(config)
    if not _token:
        _token = _generate_and_save_rpc_token(config)
    if not _token:
        bootstrap.logger.error('[RPC-AUTH] JSON-RPC HTTP API is bound to %s (not loopback-only) with no API access secret. This is NOT related to deploying fungible tokens — it only protects POST /rpc from the network. For a local node: set node.rpc_bind_ip: 127.0.0.1 (default). To expose RPC on the LAN: set MCX_RPC_TOKEN or node.rpc_token to a >=24-char random secret. Refusing to start.', _rpc_bind)
        bootstrap.sys.exit(1)
    if 'CHANGE_ME' in _token:
        bootstrap.logger.error("[RPC-AUTH] Configured bearer token is a placeholder (contains 'CHANGE_ME'). Refusing to start. Set MCX_RPC_TOKEN / node.rpc_token to a real secret.")
        bootstrap.sys.exit(1)
    if _is_weak_token(_token):
        bootstrap.logger.error('[RPC-AUTH] Configured bearer token is a placeholder or weak value. Refusing to start. Set MCX_RPC_TOKEN / node.rpc_token to a >=24-char random secret.')
        bootstrap.sys.exit(1)
    if len(_token) < 24:
        bootstrap.logger.error('[RPC-AUTH] Configured bearer token is %d characters (< 24). Refusing to start.', len(_token))
        bootstrap.sys.exit(1)

def _rpc_remote_authorized(request, config) -> bool:
    try:
        if bootstrap.ipaddress.ip_address(request.remote or '').is_loopback:
            if _rpc_trust_loopback_effective(config):
                return True
    except ValueError:
        pass
    except Exception:
        return False
    want = _rpc_bearer_token(config)
    if not want:
        return False
    try:
        auth = (request.headers.get('Authorization', '') or '').strip()
    except Exception:
        return False
    if not auth.lower().startswith('bearer '):
        return False
    try:
        return bootstrap.hmac.compare_digest(auth[7:].strip(), want)
    except Exception:
        return False
