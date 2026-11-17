import bootstrap
import config
import config as _config

def _normalize_svf_public(value) -> dict:
    if not isinstance(value, dict):
        raise ValueError('malformed genesis field: svf_public must be an object')
    _cid = value.get('chain_id')
    if isinstance(_cid, bool) or not isinstance(_cid, int):
        raise ValueError('malformed genesis field: svf_public.chain_id must be an integer')
    _gpk = value.get('group_public_key')
    if not isinstance(_gpk, str):
        raise ValueError('malformed genesis field: svf_public.group_public_key must be a hex string')
    _gpk_norm = _gpk.strip().lower()
    if len(_gpk_norm) != 192:
        raise ValueError('malformed genesis field: svf_public.group_public_key must be 96 bytes (192 hex chars)')
    try:
        bytes.fromhex(_gpk_norm)
    except ValueError:
        raise ValueError('malformed genesis field: svf_public.group_public_key is not valid hex')
    _th = value.get('template_hashes')
    if not isinstance(_th, dict):
        raise ValueError('malformed genesis field: svf_public.template_hashes must be an object')
    _norm_th = {}
    for _name, _sha in _th.items():
        if not isinstance(_name, str) or not _name.strip():
            raise ValueError('malformed genesis field: svf_public.template_hashes keys must be non-empty strings')
        if not isinstance(_sha, str):
            raise ValueError('malformed genesis field: svf_public.template_hashes values must be hex strings')
        _sha_norm = _sha.strip().lower()
        if len(_sha_norm) != 64:
            raise ValueError('malformed genesis field: svf_public.template_hashes values must be 32 bytes (64 hex chars)')
        try:
            bytes.fromhex(_sha_norm)
        except ValueError:
            raise ValueError('malformed genesis field: svf_public.template_hashes values must be valid hex')
        _norm_th[_name] = _sha_norm
    return {'chain_id': int(_cid), 'group_public_key': _gpk_norm, 'template_hashes': {k: _norm_th[k] for k in sorted(_norm_th)}}

class SVFReject(ValueError):
    pass
'\nSVF v1 Threshold-BLS Consensus using py_ecc for all curve operations.\n\nBLS12-381 curve:\n- G1: points over F_q (base field), coordinates are FQ elements (integers mod q)\n- G2: points over F_q^2, coordinates are FQ2 elements (pairs of FQ elements)\n\nSerialization:\n- G1 point (public key): x(48 bytes) + y(48 bytes) = 96 bytes uncompressed\n- G2 point (signature): x(96 bytes) + y(96 bytes) = 192 bytes uncompressed\n'
from py_ecc.optimized_bls12_381 import multiply as _bls_multiply, add as _bls_add, G1, G2, FQ, FQ2, pairing, final_exponentiate, is_on_curve, is_inf, normalize, optimized_swu_G2, curve_order, field_modulus, b, b2
from hashlib import sha256
from py_ecc.bls.hash_to_curve import hash_to_G2
_BLS_CURVE_ORDER = curve_order
_BLS_FIELD_MODULUS = field_modulus
SVF_COMMITTEE_N = 4
SVF_COMMITTEE_F = 1
SVF_COMMITTEE_THRESHOLD = 3
SVF_COMMITTEE_EPOCH = 0
SVF_GROUP_PUBLIC_KEY = None
SVF_APPROVED_TEMPLATES = {}
_SVF_TESTNET_TEMPLATE_HASHES = [{'name': 'direct_erc20', 'sha256': '42ef31de0b91480beda1431b9e447a39c086d343ef6d69d206d94bb71e450437', 'audit_ref': 'testnet tooling: forwarder contract calling SVF guard 0x0800 (no audit)'}]
SVF_KEY_IS_TEST = None
SVF_KEY_CHAIN_ID = None
SVF_KEY_FILE = None
SVF_KEY_DKG = None
_SVF_REJECTED_PLACEHOLDER_HASHES = frozenset({'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90', '00' * 32})

class SVFKeyError(ValueError):
    pass

def _svf_key_file_path(config=None):
    cfg = config if isinstance(config, dict) else _config.CONFIG or {}
    svf_cfg = cfg.get('svf') or {}
    if not isinstance(svf_cfg, dict):
        return None
    _kf = svf_cfg.get('key_file')
    if isinstance(_kf, str) and _kf.strip():
        return _kf.strip()
    return None

def _svf_load_key_file(key_file, config=None):
    global SVF_GROUP_PUBLIC_KEY, SVF_APPROVED_TEMPLATES, SVF_KEY_IS_TEST
    global SVF_KEY_CHAIN_ID, SVF_KEY_FILE, SVF_KEY_DKG
    if not key_file or not isinstance(key_file, str):
        raise SVFKeyError('svf.key_file is not set: no SVF key file configured')
    _path = str(key_file)
    try:
        _st = bootstrap.os.stat(_path)
    except FileNotFoundError:
        raise SVFKeyError(f'SVF key file not found: {_path}')
    except OSError as _e:
        raise SVFKeyError(f'SVF key file unreadable: {_path}: {_e}')
    if bootstrap.sys.platform != 'win32':
        if int(_st.st_mode) & 36:
            raise SVFKeyError(f'SVF key file permissions are too open (group/other read): {_path}: chmod 0600 the key file')
    elif int(_st.st_mode) & 36:
        bootstrap.logger.warning(f'[SVF] key file {_path} is group/other readable (Windows: WARNING only)')
    try:
        with open(_path, 'r', encoding='utf-8') as _f:
            _raw = bootstrap.json.load(_f)
    except FileNotFoundError:
        raise SVFKeyError(f'SVF key file not found: {_path}')
    except (OSError, ValueError) as _e:
        raise SVFKeyError(f'SVF key file unreadable or invalid JSON: {_path}: {_e}')
    if not isinstance(_raw, dict):
        raise SVFKeyError(f'SVF key file must be a JSON object: {_path}')
    _chain_id = _raw.get('chain_id')
    if isinstance(_chain_id, bool) or not isinstance(_chain_id, int):
        raise SVFKeyError(f'SVF key file chain_id must be an integer: {_path}')
    if int(_chain_id) != int(_config.CHAIN_ID):
        raise SVFKeyError(f'SVF key file chain_id {_chain_id} does not equal running chain id {int(_config.CHAIN_ID)}: {_path}')
    _test = _raw.get('test')
    if not isinstance(_test, bool):
        raise SVFKeyError(f'SVF key file test must be a boolean: {_path}')
    if _test:
        if int(_chain_id) != 6621:
            raise SVFKeyError(f'SVF test key file chain_id must be 6621 (testnet): {_path}')
    else:
        if int(_chain_id) == 6621:
            raise SVFKeyError(f'SVF real key file chain_id must not be 6621 (testnet): {_path}')
        if 'test_seed' in _raw:
            raise SVFKeyError(f'SVF real key file must not contain test_seed: {_path}')
        _cer = _raw.get('ceremony_record')
        if not isinstance(_cer, str) or not _cer.strip():
            raise SVFKeyError(f'SVF real key file ceremony_record must be non-empty: {_path}')
    _gpk_hex = _raw.get('group_public_key')
    if not isinstance(_gpk_hex, str):
        raise SVFKeyError(f'SVF key file group_public_key must be a hex string: {_path}')
    try:
        _gpk = bytes.fromhex(_gpk_hex.strip())
    except ValueError:
        raise SVFKeyError(f'SVF key file group_public_key is not valid hex: {_path}')
    if len(_gpk) != 96:
        raise SVFKeyError(f'SVF key file group_public_key must be 96 bytes: {_path}')
    try:
        _g1_from_bytes(_gpk)
    except Exception as _e:
        raise SVFKeyError(f'SVF key file group_public_key is not a valid G1 subgroup point: {_path}: {_e}')
    _templates = _raw.get('template_hashes')
    if not isinstance(_templates, list):
        raise SVFKeyError(f'SVF key file template_hashes must be a list: {_path}')
    _approved = {}
    _seen_hashes = set()
    for _t in _templates:
        if not isinstance(_t, dict):
            raise SVFKeyError(f'SVF key file template entry must be an object: {_path}')
        _name = _t.get('name')
        _sha = _t.get('sha256')
        _audit = _t.get('audit_ref')
        if not isinstance(_name, str) or not _name.strip():
            raise SVFKeyError(f'SVF key file template name must be a non-empty string: {_path}')
        if not isinstance(_sha, str):
            raise SVFKeyError(f'SVF key file template sha256 must be a hex string: {_path}')
        _sha_norm = _sha.strip().lower()
        if len(_sha_norm) != 64:
            raise SVFKeyError(f'SVF key file template sha256 must be 32 bytes (64 hex chars): {_path}')
        try:
            bytes.fromhex(_sha_norm)
        except ValueError:
            raise SVFKeyError(f'SVF key file template sha256 is not valid hex: {_path}')
        if not isinstance(_audit, str):
            raise SVFKeyError(f'SVF key file template audit_ref must be a string: {_path}')
        if _sha_norm in _SVF_REJECTED_PLACEHOLDER_HASHES:
            raise SVFKeyError(f'SVF key file template hash is a base placeholder value: {_path}')
        if _sha_norm in _seen_hashes:
            raise SVFKeyError(f'SVF key file template hashes must be unique: {_path}')
        if _name in _approved:
            raise SVFKeyError(f'SVF key file template names must be unique: {_path}')
        _seen_hashes.add(_sha_norm)
        _approved[_name] = _sha_norm
    _dkg = None
    if _test:
        _seed_hex = _raw.get('test_seed')
        if not isinstance(_seed_hex, str):
            raise SVFKeyError(f'SVF test key file test_seed must be present: {_path}')
        _seed_norm = _seed_hex.strip().lower()
        if len(_seed_norm) != 64:
            raise SVFKeyError(f'SVF test key file test_seed must be 64 hex chars: {_path}')
        try:
            _seed = bytes.fromhex(_seed_norm)
        except ValueError:
            raise SVFKeyError(f'SVF test key file test_seed is not valid hex: {_path}')
        _dkg = _svf_committee_dkg(_seed)
        if _dkg.get('group_public_key') != _gpk.hex():
            raise SVFKeyError(f'SVF test key file group_public_key does not match the key derived from test_seed: {_path}')
    SVF_GROUP_PUBLIC_KEY = _gpk
    SVF_APPROVED_TEMPLATES = dict(_approved)
    SVF_KEY_IS_TEST = bool(_test)
    SVF_KEY_CHAIN_ID = int(_chain_id)
    SVF_KEY_FILE = _path
    SVF_KEY_DKG = _dkg
    bootstrap.logger.info(f'[SVF] key file {_path}: chain_id={int(_chain_id)} test={bool(_test)} group_public_key={_gpk.hex()}')
    for _name, _sha in sorted(_approved.items()):
        bootstrap.logger.info(f'[SVF] template {_name} sha256={_sha}')
    return {'chain_id': int(_chain_id), 'test': bool(_test), 'group_public_key': _gpk.hex(), 'template_hashes': dict(_approved), 'key_file': _path, 'dkg': _dkg}

def _svf_ensure_key_loaded(config=None):
    global SVF_KEY_FILE
    if SVF_GROUP_PUBLIC_KEY is not None and SVF_KEY_FILE is not None:
        return {'chain_id': SVF_KEY_CHAIN_ID, 'test': SVF_KEY_IS_TEST, 'group_public_key': SVF_GROUP_PUBLIC_KEY.hex(), 'template_hashes': dict(SVF_APPROVED_TEMPLATES), 'key_file': SVF_KEY_FILE, 'dkg': SVF_KEY_DKG}
    _kf = _svf_key_file_path(config)
    if _kf is None:
        _default_kf = _svf_default_key_path()
        if bootstrap.os.path.isfile(_default_kf):
            try:
                return _svf_load_key_file(_default_kf, config=config)
            except SVFKeyError as _e:
                bootstrap.logger.error(f'[SVF] {_e}; refusing to start')
                bootstrap.sys.exit(1)
        bootstrap.logger.info('[SVF] svf.key_file is not set in config; waiting for SVF parameters from genesis (no key file configured)')
        return None
    try:
        return _svf_load_key_file(_kf, config=config)
    except SVFKeyError as _e:
        bootstrap.logger.error(f'[SVF] {_e}; refusing to start')
        bootstrap.sys.exit(1)

def _svf_public_for_genesis() -> dict:
    if SVF_GROUP_PUBLIC_KEY is None or SVF_KEY_CHAIN_ID is None:
        _kf = _svf_key_file_path()
        if _kf:
            raise SVFKeyError(f'SVF parameters not loaded from key file: {_kf}')
        raise SVFKeyError('SVF parameters not loaded: svf.key_file is not set in config; no SVF key file configured')
    return {'chain_id': int(SVF_KEY_CHAIN_ID), 'group_public_key': SVF_GROUP_PUBLIC_KEY.hex(), 'template_hashes': {k: v for k, v in sorted(SVF_APPROVED_TEMPLATES.items())}}

def _svf_default_key_path():
    _gf = config.GENESIS_FILE or 'genesis.json'
    _d = bootstrap.os.path.dirname(bootstrap.os.path.abspath(str(_gf)))
    return bootstrap.os.path.join(_d, 'svf_test_key.json')

def _svf_auto_generate_test_key():
    _seed = bootstrap.os.urandom(32)
    _dkg = _svf_committee_dkg(_seed)
    _key = {'chain_id': 6621, 'test': True, 'group_public_key': _dkg['group_public_key'], 'template_hashes': [dict(_t) for _t in _SVF_TESTNET_TEMPLATE_HASHES], 'ceremony_record': 'auto-generated testnet key (node-generated on genesis creation)', 'test_seed': _seed.hex()}
    _path = _svf_default_key_path()
    _fd = bootstrap.os.open(_path, bootstrap.os.O_WRONLY | bootstrap.os.O_CREAT | bootstrap.os.O_TRUNC, 384)
    try:
        bootstrap.os.write(_fd, (bootstrap.json.dumps(_key, indent=2) + '\n').encode('utf-8'))
    finally:
        bootstrap.os.close(_fd)
    try:
        bootstrap.os.chmod(_path, 384)
    except OSError:
        pass
    _svf_load_key_file(_path)
    bootstrap.logger.info('[SVF] auto-generated testnet key file %s (chain 6621, group key %s...)', _path, _dkg['group_public_key'][:16])
    return _svf_public_for_genesis()

def _svf_load_from_genesis(svf_public):
    global SVF_GROUP_PUBLIC_KEY, SVF_APPROVED_TEMPLATES, SVF_KEY_IS_TEST, SVF_KEY_CHAIN_ID
    if SVF_GROUP_PUBLIC_KEY is not None:
        return None
    if not svf_public:
        return None
    try:
        _norm = _normalize_svf_public(svf_public)
    except ValueError as _e:
        raise SVFKeyError(f'genesis svf_public is malformed: {_e}')
    if int(_norm['chain_id']) != int(config.CHAIN_ID):
        raise SVFKeyError(f'genesis svf_public chain_id {_norm['chain_id']} does not equal running chain id {int(config.CHAIN_ID)}')
    try:
        _gpk = bytes.fromhex(_norm['group_public_key'])
    except ValueError:
        raise SVFKeyError('genesis svf_public group_public_key is not valid hex')
    if len(_gpk) != 96:
        raise SVFKeyError('genesis svf_public group_public_key must be 96 bytes')
    try:
        _g1_from_bytes(_gpk)
    except Exception as _e:
        raise SVFKeyError(f'genesis svf_public group_public_key is not a valid G1 subgroup point: {_e}')
    SVF_GROUP_PUBLIC_KEY = _gpk
    SVF_APPROVED_TEMPLATES = dict(_norm['template_hashes'])
    SVF_KEY_CHAIN_ID = int(_norm['chain_id'])
    SVF_KEY_IS_TEST = bool(int(_norm['chain_id']) == 6621)
    bootstrap.logger.info(f'[SVF] loaded public parameters from genesis: chain_id={SVF_KEY_CHAIN_ID} test={SVF_KEY_IS_TEST} group_public_key={_gpk.hex()}')
    for _name, _sha in sorted(SVF_APPROVED_TEMPLATES.items()):
        bootstrap.logger.info(f'[SVF] template {_name} sha256={_sha}')
    return {'chain_id': SVF_KEY_CHAIN_ID, 'test': SVF_KEY_IS_TEST, 'group_public_key': _gpk.hex(), 'template_hashes': dict(SVF_APPROVED_TEMPLATES)}
BLS_SIG_DST = b'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_'

def _g1_to_bytes(point) -> bytes:
    x, y, z = point
    if z != 1:
        point = normalize(point)
        x, y = (point[0], point[1])
    x_val = int(x) if hasattr(x, '__int__') else int(x.coeffs[0])
    y_val = int(y) if hasattr(y, '__int__') else int(y.coeffs[0])
    return x_val.to_bytes(48, 'big') + y_val.to_bytes(48, 'big')

def _svf_in_prime_subgroup(point) -> bool:
    try:
        return bool(is_inf(_bls_multiply(point, _BLS_CURVE_ORDER)))
    except Exception:
        return False

def _g1_from_bytes(data: bytes):
    if not isinstance(data, (bytes, bytearray)) or len(data) != 96:
        raise ValueError('G1 point must be exactly 96 bytes')
    x = int.from_bytes(data[0:48], 'big')
    y = int.from_bytes(data[48:96], 'big')
    if x >= _BLS_FIELD_MODULUS or y >= _BLS_FIELD_MODULUS:
        raise ValueError('G1 coordinate out of field range')
    pt = (FQ(x), FQ(y), FQ(1))
    if not is_on_curve(pt, b):
        raise ValueError('G1 point not on curve')
    if not _svf_in_prime_subgroup(pt):
        raise ValueError('G1 point not in prime-order subgroup')
    return pt

def _g2_to_bytes(point) -> bytes:
    x, y, z = point
    z_is_one = False
    if hasattr(z, 'coeffs'):
        z_is_one = z.coeffs[0] == 1 and z.coeffs[1] == 0
    elif z == (1, 0) or z == 1:
        z_is_one = True
    if not z_is_one:
        point = normalize(point)
        x, y = (point[0], point[1])
    x0 = int(x.coeffs[0]) if hasattr(x, 'coeffs') else int(x[0])
    x1 = int(x.coeffs[1]) if hasattr(x, 'coeffs') else int(x[1])
    y0 = int(y.coeffs[0]) if hasattr(y, 'coeffs') else int(y[0])
    y1 = int(y.coeffs[1]) if hasattr(y, 'coeffs') else int(y[1])
    x_bytes = x0.to_bytes(48, 'big') + x1.to_bytes(48, 'big')
    y_bytes = y0.to_bytes(48, 'big') + y1.to_bytes(48, 'big')
    return x_bytes + y_bytes

def _g2_from_bytes(data: bytes):
    if not isinstance(data, (bytes, bytearray)) or len(data) != 192:
        raise ValueError('G2 point must be exactly 192 bytes')
    x0 = int.from_bytes(data[0:48], 'big')
    x1 = int.from_bytes(data[48:96], 'big')
    y0 = int.from_bytes(data[96:144], 'big')
    y1 = int.from_bytes(data[144:192], 'big')
    if x0 >= _BLS_FIELD_MODULUS or x1 >= _BLS_FIELD_MODULUS or y0 >= _BLS_FIELD_MODULUS or (y1 >= _BLS_FIELD_MODULUS):
        raise ValueError('G2 coordinate out of field range')
    pt = (FQ2([x0, x1]), FQ2([y0, y1]), FQ2([1, 0]))
    if not is_on_curve(pt, b2):
        raise ValueError('G2 point not on curve')
    if not _svf_in_prime_subgroup(pt):
        raise ValueError('G2 point not in prime-order subgroup')
    return pt

def _svf_bls_keygen(seed: bytes) -> tuple:
    sk_int = int.from_bytes(seed, 'big') % _BLS_CURVE_ORDER
    if sk_int == 0:
        sk_int = 1
    pk = _bls_multiply(G1, sk_int)
    return (sk_int, _g1_to_bytes(pk))

def _svf_bls_sk_to_pk(sk_int: int) -> bytes:
    pk = _bls_multiply(G1, sk_int % _BLS_CURVE_ORDER)
    return _g1_to_bytes(pk)

def _svf_bls_sign(sk_int: int, message: bytes) -> bytes:
    h_msg = hash_to_G2(message, BLS_SIG_DST, sha256)
    sig = _bls_multiply(h_msg, sk_int % _BLS_CURVE_ORDER)
    return _g2_to_bytes(sig)

def _svf_bls_verify(pk_bytes: bytes, message: bytes, sig_bytes: bytes) -> bool:
    try:
        pk = _g1_from_bytes(pk_bytes)
        sig = _g2_from_bytes(sig_bytes)
        h_msg = hash_to_G2(message, BLS_SIG_DST, sha256)
        left = final_exponentiate(pairing(h_msg, pk))
        right = final_exponentiate(pairing(sig, G1))
        return left == right
    except Exception:
        return False

def _svf_shamir_share(sk_int: int, n: int, t: int) -> list:
    import secrets as _secrets
    coeffs = [sk_int % _BLS_CURVE_ORDER]
    for _ in range(1, t):
        coeffs.append(_secrets.randbelow(_BLS_CURVE_ORDER))

    def _eval_poly(x, coeffs):
        result = 0
        for c in reversed(coeffs):
            result = (result * x + c) % _BLS_CURVE_ORDER
        return result
    shares = []
    for i in range(1, n + 1):
        shares.append((i, _eval_poly(i, coeffs)))
    return shares

def _svf_shamir_reconstruct(shares: list, p: int=_BLS_CURVE_ORDER) -> int:
    x_vals = [s[0] for s in shares]
    y_vals = [s[1] for s in shares]
    k = len(shares)
    result = 0
    for i in range(k):
        xi, yi = (x_vals[i], y_vals[i])
        li = 1
        for j in range(k):
            if i != j:
                xj = x_vals[j]
                li = li * (0 - xj) * pow(xi - xj, -1, p) % p
        result = (result + yi * li) % p
    return result

def _svf_committee_dkg(seed: bytes, n: int=SVF_COMMITTEE_N, t: int=SVF_COMMITTEE_THRESHOLD) -> dict:
    sk_int, pk_bytes = _svf_bls_keygen(seed)
    shares = _svf_shamir_share(sk_int, n, t)
    member_shares = {}
    member_pubkeys = []
    for i, share_val in shares:
        member_shares[i] = share_val
        member_pubkeys.append(_svf_bls_sk_to_pk(share_val))
    return {'committee_epoch': SVF_COMMITTEE_EPOCH, 'group_public_key': pk_bytes.hex(), 'threshold': t, 'member_count': n, 'member_pubkeys': [pk.hex() for pk in member_pubkeys], 'member_shares': {str(i): v for i, v in shares}}

def _svf_committee_partial_sign(share_sk_int: int, message: bytes) -> bytes:
    return _svf_bls_sign(share_sk_int, message)

def _svf_committee_verify_partial(share_pk_bytes: bytes, message: bytes, partial_sig_bytes: bytes) -> bool:
    return _svf_bls_verify(share_pk_bytes, message, partial_sig_bytes)

def _svf_committee_combine_partials(partial_sigs: list, shares: list, message: bytes, p: int=_BLS_CURVE_ORDER) -> bytes:
    if not partial_sigs or not shares or len(partial_sigs) != len(shares):
        raise SVFReject('partial signatures and shares must be non-empty and equal length')
    x_vals = [s[0] for s in shares]
    k = len(shares)
    lagrange_coeffs = []
    for i in range(k):
        xi = x_vals[i]
        li = 1
        for j in range(k):
            if i != j:
                xj = x_vals[j]
                li = li * (0 - xj) * pow(xi - xj, -1, p) % p
        lagrange_coeffs.append(li % p)
    combined = None
    for li, sig_bytes in zip(lagrange_coeffs, partial_sigs):
        sig = _g2_from_bytes(sig_bytes)
        scaled = _bls_multiply(sig, int(li))
        if combined is None:
            combined = scaled
        else:
            combined = _bls_add(combined, scaled)
    if combined is None:
        raise SVFReject('no partial signatures to combine')
    return _g2_to_bytes(combined)

def _svf_committee_generate_certificate(dkg_config: dict, evidence_root: bytes, chain_id: int, committee_epoch: int, evidence_epoch: int, window_start: int, window_end: int, anchor_hash: str) -> dict:
    import hashlib as _hashlib
    import struct as _struct
    msg = b'MCX-SVF-EPOCH-BEACON-V1'
    msg += _struct.pack('>H', 1)
    msg += _struct.pack('>Q', chain_id)
    msg += _struct.pack('>Q', committee_epoch)
    msg += _struct.pack('>Q', evidence_epoch)
    msg += _struct.pack('>Q', window_start)
    msg += _struct.pack('>Q', window_end)
    msg += bytes.fromhex(anchor_hash)
    msg += evidence_root
    t = dkg_config['threshold']
    n = dkg_config['member_count']
    partials = []
    member_ids = sorted((int(k) for k in dkg_config['member_shares'].keys()))
    for mid in member_ids[:t]:
        share_sk = dkg_config['member_shares'][str(mid)]
        partial_sig = _svf_committee_partial_sign(share_sk, msg)
        partials.append((mid, partial_sig))
    member_pubkeys = dkg_config['member_pubkeys']
    share_pks = []
    for mid in member_ids[:t]:
        _pk = member_pubkeys[mid - 1]
        share_pks.append(bytes.fromhex(_pk) if isinstance(_pk, str) else _pk)
    for (mid, psig), spk in zip(partials, share_pks):
        if not _svf_committee_verify_partial(spk, msg, psig):
            raise SVFReject(f'Partial signature verification failed for member {mid}')
    selected_shares = [(mid, dkg_config['member_shares'][str(mid)]) for mid in member_ids[:t]]
    partial_sig_bytes = [psig for _, psig in partials]
    threshold_sig = _svf_committee_combine_partials(partial_sig_bytes, selected_shares, msg)
    group_pk = bytes.fromhex(dkg_config['group_public_key'])
    if not _svf_bls_verify(group_pk, msg, threshold_sig):
        raise SVFReject('Combined threshold signature verification failed')
    beacon_output = _hashlib.sha256(b'MCX-SVF-BEACON-OUTPUT-V1' + b'\x00' + threshold_sig).digest()
    return {'protocol_version': 1, 'chain_id': chain_id, 'committee_epoch': committee_epoch, 'evidence_epoch': evidence_epoch, 'window_start_height': window_start, 'window_end_height': window_end, 'anchor_block_hash': anchor_hash, 'evidence_root': evidence_root.hex() if isinstance(evidence_root, bytes) else evidence_root, 'group_public_key_id': dkg_config['group_public_key'], 'group_pubkey': dkg_config['group_public_key'], 'threshold_signature': threshold_sig.hex(), 'beacon_output': beacon_output.hex(), 'canonical_message': msg.hex()}
