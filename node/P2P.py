import bootstrap
import config
import crypto
import util
import maze
import svf_keys
import genesis
import repos
try:
    from kademlia.network import Server
    from kademlia.storage import ForgetfulStorage
    DHT_AVAILABLE = True
except ImportError:
    DHT_AVAILABLE = False
    bootstrap.logger.warning('[DHT] kademlia not installed. Falling back to peers cache.')

@bootstrap.dataclass
class EncryptedPeer:
    address: str
    reader: bootstrap.asyncio.StreamReader
    writer: bootstrap.asyncio.StreamWriter
    send_key: bytes
    recv_key: bytes
    send_nonce: int
    recv_nonce: int
    session_id: bytes
    node_id: str
    pub: str
    height: int
    version: str
    last_seen: float
    p2p_port: int = 8081
    score: int = 0
    banned: bool = False
    write_lock: bootstrap.asyncio.Lock = bootstrap.field(default_factory=bootstrap.asyncio.Lock)
    pqe: bool = False
    send_queue: bootstrap.asyncio.PriorityQueue = bootstrap.field(default_factory=lambda: bootstrap.asyncio.PriorityQueue(maxsize=1000))
    _send_counter: int = 0

    def encrypt_message(self, payload: bytes) -> bytes:
        nonce = self.send_nonce.to_bytes(12, 'big')
        self.send_nonce += 1
        aesgcm = bootstrap.AESGCM(self.send_key)
        return aesgcm.encrypt(nonce, payload, self.session_id + b'\x00' * 4)

    def decrypt_message(self, ciphertext: bytes) -> bootstrap.Optional[bytes]:
        nonce = self.recv_nonce.to_bytes(12, 'big')
        self.recv_nonce += 1
        aesgcm = bootstrap.AESGCM(self.recv_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, self.session_id + b'\x00' * 4)
        except bootstrap.InvalidTag:
            return None

def parse_ip_port(addr: str, default_port: int=8081) -> bootstrap.Tuple[str, int]:
    addr = str(addr).strip()
    if addr.startswith('['):
        end_bracket = addr.find(']')
        if end_bracket != -1:
            host = addr[1:end_bracket]
            rest = addr[end_bracket + 1:]
            if rest.startswith(':'):
                try:
                    return (host, int(rest[1:]))
                except ValueError:
                    pass
            return (host, default_port)
    if ':' in addr:
        parts = addr.rsplit(':', 1)
        try:
            return (parts[0], int(parts[1]))
        except ValueError:
            return (addr, default_port)
    return (addr, default_port)

def _mutual_dial_keep(local_id, remote_id) -> bool:
    try:
        if not local_id or not remote_id:
            return False
        if local_id == remote_id:
            return False
        return local_id < remote_id
    except TypeError:
        return False

def _dial_dup_action(local_id, remote_id, direction, loopback, has_existing) -> str:
    if not has_existing:
        return 'register'
    if not loopback:
        return 'close_new'
    if direction == 'in':
        keeper = _mutual_dial_keep(remote_id, local_id)
    else:
        keeper = _mutual_dial_keep(local_id, remote_id)
    return 'replace_existing' if keeper else 'close_new'

async def perform_handshake(reader: bootstrap.asyncio.StreamReader, writer: bootstrap.asyncio.StreamWriter, my_node_id: str, my_height: int, my_version: str, my_priv_key: str, my_pub_key: str, allow_genesis_learn: bool=False) -> bootstrap.Optional[EncryptedPeer]:
    try:
        writer.write(config.P2P_MAGIC)
        await writer.drain()
        remote_magic = await reader.readexactly(4)
    except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    if remote_magic != config.P2P_MAGIC:
        return None
    priv_ephemeral = bootstrap.ec.generate_private_key(bootstrap.ec.SECP256K1())
    pub_ephemeral = priv_ephemeral.public_key()
    pub_ephemeral_raw = pub_ephemeral.public_bytes(encoding=bootstrap.serialization.Encoding.X962, format=bootstrap.serialization.PublicFormat.UncompressedPoint)
    priv_mlkem = None
    pub_mlkem_raw = b''
    if bootstrap.MLKEM_AVAILABLE:
        try:
            priv_mlkem = bootstrap.mlkem.MLKEM768PrivateKey.generate()
            pub_mlkem_raw = priv_mlkem.public_key().public_bytes_raw()
        except Exception:
            priv_mlkem = None
    writer.write(bootstrap.struct.pack('>H', len(pub_ephemeral_raw)) + pub_ephemeral_raw)
    await writer.drain()
    try:
        len_data = await reader.readexactly(2)
    except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    remote_pub_len = bootstrap.struct.unpack('>H', len_data)[0]
    if remote_pub_len < 33 or remote_pub_len > 65:
        return None
    try:
        remote_pub_raw = await reader.readexactly(remote_pub_len)
    except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    try:
        remote_pub = bootstrap.ec.EllipticCurvePublicKey.from_encoded_point(bootstrap.ec.SECP256K1(), remote_pub_raw)
    except Exception:
        return None
    shared_secret = priv_ephemeral.exchange(bootstrap.ec.ECDH(), remote_pub)
    hkdf = bootstrap.HKDF(algorithm=bootstrap.hashes.SHA256(), length=80, salt=b'mcx_p2p_salt', info=b'mcx_p2p_handshake', backend=bootstrap.default_backend())
    derived = hkdf.derive(shared_secret)
    key_lo = derived[:32]
    key_hi = derived[32:64]
    if pub_ephemeral_raw < remote_pub_raw:
        send_key, recv_key = (key_lo, key_hi)
    else:
        send_key, recv_key = (key_hi, key_lo)
    session_id = derived[64:80]
    auth_message = f'{pub_ephemeral_raw.hex()}{session_id.hex()}{my_node_id}'
    auth_sig = crypto.sign_message(my_priv_key, auth_message)
    hello_dict = {'node_id': my_node_id, 'height': my_height, 'version': my_version, 'session_id': session_id.hex(), 'pub_key': my_pub_key, 'auth_sig': auth_sig, 'p2p_port': config.P2P_PORT, 'genesis_hash': genesis._node_genesis_hash, 'fork_id': genesis.FORK_ID}
    if not genesis._node_genesis_hash:
        hello_dict['want_genesis'] = True
    if genesis._node_genesis_hash and genesis._node_genesis_data:
        hello_dict['genesis_body'] = genesis._node_genesis_data
    if priv_mlkem:
        hello_dict['pqe'] = True
        hello_dict['pqe_pub'] = pub_mlkem_raw.hex()
    hello_payload = bootstrap.json.dumps(hello_dict).encode()
    aesgcm_send = bootstrap.AESGCM(send_key)
    nonce = b'\x00' * 12
    encrypted_hello = aesgcm_send.encrypt(nonce, hello_payload, session_id + b'\x00' * 4)
    writer.write(bootstrap.struct.pack('>I', len(encrypted_hello)) + encrypted_hello)
    await writer.drain()
    try:
        len_data = await reader.readexactly(4)
    except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    hello_len = bootstrap.struct.unpack('>I', len_data)[0]
    if hello_len <= 0 or hello_len > 65536:
        return None
    try:
        encrypted_remote_hello = await reader.readexactly(hello_len)
    except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    aesgcm_recv = bootstrap.AESGCM(recv_key)
    try:
        remote_hello_data = aesgcm_recv.decrypt(nonce, encrypted_remote_hello, session_id + b'\x00' * 4)
        remote_hello = bootstrap.json.loads(remote_hello_data.decode())
    except (bootstrap.InvalidTag, bootstrap.json.JSONDecodeError):
        return None
    if remote_hello.get('session_id') != session_id.hex():
        return None
    peername = writer.get_extra_info('peername')
    if isinstance(peername, tuple):
        host = peername[0]
        port = peername[1]
        if host in ('101.127.80.48', config.GENESIS_NODE_HOST):
            host = config.GENESIS_NODE_HOST
        addr_str = f'[{host}]:{port}' if ':' in str(host) else f'{host}:{port}'
    else:
        addr_str = str(peername).replace('101.127.80.48', config.GENESIS_NODE_HOST)
    remote_genesis = remote_hello.get('genesis_hash', '')
    remote_genesis_body = remote_hello.get('genesis_body')
    remote_want_genesis = remote_hello.get('want_genesis', False)
    if genesis._node_genesis_hash and remote_genesis:
        if remote_genesis != genesis._node_genesis_hash:
            bootstrap.logger.warning(f'[P2P] Peer genesis mismatch: peer={remote_genesis[:16]} local={genesis._node_genesis_hash[:16]}')
            return None
    elif genesis._node_genesis_hash and (not remote_genesis):
        if remote_want_genesis:
            bootstrap.logger.info(f'[P2P] Peer {addr_str} has no genesis and requested it — accepting; peer will sync')
        else:
            bootstrap.logger.warning(f'[P2P] Peer handshake rejected: local genesis present, remote genesis empty (no want_genesis flag)')
            return None
    elif not genesis._node_genesis_hash and remote_genesis:
        if not allow_genesis_learn:
            bootstrap.logger.info(f'[P2P] Peer {addr_str} offered genesis but this node is not learning a genesis; ignoring')
            return None
        if bootstrap.os.path.exists(config.GENESIS_FILE):
            bootstrap.logger.warning(f'[P2P] Refusing to overwrite existing {config.GENESIS_FILE}')
            return None
        if not isinstance(remote_genesis_body, dict):
            bootstrap.logger.warning(f'[P2P] Peer {addr_str} has genesis but sent no body')
            return None
        if remote_genesis_body.get('hash') != remote_genesis:
            bootstrap.logger.warning(f'[P2P] genesis_body hash does not match hello hash')
            return None
        if int(remote_genesis_body.get('chain_id', 0)) != config.CHAIN_ID:
            bootstrap.logger.warning(f'[P2P] genesis_body chain_id mismatch')
            return None
        ok, why = genesis.genesis_export_verified(remote_genesis_body)
        if not ok:
            bootstrap.logger.warning(f"[P2P] Genesis verification failed: {why} (config.yaml consensus.*/vm.*/fees.*/p2p.ban_duration/validators must match the genesis creator's)")
            return None
        gh = remote_genesis_body.get('hash', '')
        if len(gh) != 64 or not all((c in '0123456789abcdef' for c in gh.lower())):
            bootstrap.logger.warning(f'[P2P] genesis_body hash format invalid')
            return None
        _pin_why = config._genesis_pin_failure(gh, config.EXPECTED_GENESIS_PIN)
        if _pin_why:
            bootstrap.logger.error(f'[P2P] {_pin_why}; refusing to learn genesis from {addr_str}')
            return None
        try:
            genesis._write_genesis_file_atomic(remote_genesis_body)
        except Exception as e:
            bootstrap.logger.error(f'[P2P] Failed to write {config.GENESIS_FILE}: {e}')
            return None
        genesis._node_genesis_hash = gh
        genesis._node_genesis_data = remote_genesis_body
        genesis.FORK_ID = int(gh[:8], 16) ^ int(gh[8:16], 16)
        bootstrap.logger.info(f'[P2P] Learned genesis from {addr_str}: hash={gh[:16]}...')
        try:
            svf_keys._svf_load_from_genesis(remote_genesis_body.get('svf_public'))
        except svf_keys.SVFKeyError as _e:
            bootstrap.logger.error(f'[SVF] {_e}; refusing to learn genesis from {addr_str}')
            bootstrap.sys.exit(1)
    else:
        bootstrap.logger.warning(f'[P2P] Peer handshake rejected: both genesis empty')
        return None
    remote_fork_id = remote_hello.get('fork_id', 0)
    if remote_fork_id and genesis.FORK_ID and (remote_fork_id != genesis.FORK_ID):
        bootstrap.logger.warning(f'[P2P] Peer fork_id mismatch: peer={remote_fork_id} local={genesis.FORK_ID} (genesis hashes match, possible fork)')
    remote_node_id = remote_hello.get('node_id')
    remote_static_pub = remote_hello.get('pub_key')
    remote_auth_sig = remote_hello.get('auth_sig')
    if not remote_node_id or not remote_static_pub or (not remote_auth_sig):
        bootstrap.logger.debug('[Handshake] Peer did not send identity proof — rejecting.')
        return None
    try:
        claimed = remote_node_id.lower()
        pub_b = bytes.fromhex(remote_static_pub.removeprefix('0x'))
        addr_keccak = util.pubkey_to_address(remote_static_pub).lower()
        addr_sha3 = ('0x' + bootstrap.hashlib.sha3_256(pub_b[1:]).digest()[-20:].hex()).lower()
        if claimed not in (addr_keccak, addr_sha3):
            bootstrap.logger.debug(f'[Handshake] node_id does not match claimed pubkey — rejecting (claimed {remote_node_id[:16]})')
            return None
    except Exception:
        return None
    remote_auth_message = f'{remote_pub_raw.hex()}{session_id.hex()}{remote_node_id}'
    if not crypto.verify_signature(remote_static_pub, remote_auth_message, remote_auth_sig):
        bootstrap.logger.debug(f'[Handshake] Identity signature failed — rejecting (claimed {remote_node_id[:16]})')
        return None
    pqe_active = False
    remote_pqe_pub_hex = remote_hello.get('pqe_pub')
    if priv_mlkem and remote_hello.get('pqe') and remote_pqe_pub_hex:
        try:
            remote_pqe_pub_bytes = bytes.fromhex(remote_pqe_pub_hex)
            remote_mlkem_pub = bootstrap.mlkem.MLKEM768PublicKey.from_public_bytes(remote_pqe_pub_bytes)
            ss_local, ct_local = remote_mlkem_pub.encapsulate()
            ct_nonce = b'\x01' * 12
            enc_ct_local = aesgcm_send.encrypt(ct_nonce, ct_local, session_id + b'PQE_EXCHANGE')
            writer.write(bootstrap.struct.pack('>I', len(enc_ct_local)) + enc_ct_local)
            await writer.drain()
            len_data = await reader.readexactly(4)
            ct_len = bootstrap.struct.unpack('>I', len_data)[0]
            if ct_len <= 0 or ct_len > 65536:
                return None
            enc_ct_remote = await reader.readexactly(ct_len)
            ct_remote = aesgcm_recv.decrypt(ct_nonce, enc_ct_remote, session_id + b'PQE_EXCHANGE')
            ss_remote = priv_mlkem.decapsulate(ct_remote)
            if pub_ephemeral_raw < remote_pub_raw:
                combined_secret = shared_secret + ss_local + ss_remote
            else:
                combined_secret = shared_secret + ss_remote + ss_local
            hkdf_pq = bootstrap.HKDF(algorithm=bootstrap.hashes.SHA384(), length=64, salt=b'mcx_nsa_cnsa2_pqe_salt', info=b'mcx_p2p_mlkem768_aes256gcm', backend=bootstrap.default_backend())
            pq_derived = hkdf_pq.derive(combined_secret)
            if pub_ephemeral_raw < remote_pub_raw:
                send_key, recv_key = (pq_derived[:32], pq_derived[32:64])
            else:
                send_key, recv_key = (pq_derived[32:64], pq_derived[:32])
            pqe_active = True
            bootstrap.logger.info(f'[P2P] Established NSA CNSA 2.0 Hybrid PQE (ML-KEM-768 + SECP256K1 + AES-256-GCM) with {addr_str}')
        except Exception as e:
            bootstrap.logger.warning(f'[P2P] Post-quantum key exchange failed with {addr_str}: {e}')
            return None
    peer = EncryptedPeer(address=addr_str, reader=reader, writer=writer, send_key=send_key, recv_key=recv_key, send_nonce=1, recv_nonce=1, session_id=session_id, node_id=remote_node_id, pub=remote_static_pub, height=remote_hello.get('height', 0), version=remote_hello.get('version', 'unknown'), last_seen=bootstrap.time.time(), p2p_port=remote_hello.get('p2p_port', config.P2P_PORT), pqe=pqe_active)
    return peer

def _ssrf_ip_blocked(ip_str: str) -> bool:
    try:
        ip_obj = bootstrap.ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved or ip_obj.is_multicast or (str(ip_obj) == '169.254.169.254')

def _lan_dialable(ip_str: str) -> bool:
    try:
        o = bootstrap.ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if str(o) == '169.254.169.254':
        return False
    return bool(o.is_private or o.is_loopback)

async def _ssrf_allows_dial(h: str, p: int, local_ips, public_ip, allow_private: bool=False) -> bootstrap.Tuple[bool, str, object]:
    try:
        bootstrap.ipaddress.ip_address(h)
        dial_ips = [h]
    except ValueError:
        try:
            loop = bootstrap.asyncio.get_event_loop()
            _, _, dial_ips = await loop.run_in_executor(None, bootstrap.socket.gethostbyname_ex, h)
        except (OSError, UnicodeError):
            return (False, f'unresolvable host {h}', None)
        if not dial_ips:
            return (False, f'unresolvable host {h}', None)
    for dip in dial_ips:
        if _ssrf_ip_blocked(dip):
            if not (allow_private and _lan_dialable(dip)):
                continue
        if (dip in (local_ips or set()) or (public_ip and dip == public_ip)) and int(p or 0) == int(config.P2P_PORT):
            continue
        return (True, 'private-lan' if _lan_dialable(dip) and _ssrf_ip_blocked(dip) else 'public', dip)
    return (False, f'no dialable address for {h}', None)

def resolve_seed_lists(p2p_cfg) -> tuple:
    p2p_cfg = p2p_cfg or {}
    genesis_node = p2p_cfg.get('genesis_node', config.GENESIS_NODE_HOST) or config.GENESIS_NODE_HOST
    _cfg_dns = p2p_cfg.get('dns_seeds', None)
    dns_seeds = list(dict.fromkeys(_cfg_dns)) if _cfg_dns is not None else list(config.DNS_SEEDS)
    _cfg_boot = p2p_cfg.get('bootstrap_nodes', None)
    bootstrap_nodes = list(dict.fromkeys(_cfg_boot)) if _cfg_boot is not None else list(config.BOOTSTRAP_NODES)
    try:
        dht_port = int(p2p_cfg.get('dht_port', config.DHT_PORT))
    except (TypeError, ValueError):
        dht_port = config.DHT_PORT
    raw_dht = p2p_cfg.get('dht_bootstrap_nodes', None)
    if raw_dht is not None:
        dht = []
        for n in raw_dht:
            if isinstance(n, (list, tuple)) and len(n) == 2:
                dht.append((str(n[0]), int(n[1])))
            else:
                h, p = parse_ip_port(str(n), default_port=dht_port)
                dht.append((h, p))
    else:
        dht = [(parse_ip_port(b, default_port=dht_port)[0], dht_port) for b in bootstrap_nodes]
        if not dht and _cfg_boot is None:
            dht = [(config.GENESIS_NODE_HOST, config.GENESIS_NODE_DHT_PORT)]
    return (genesis_node, dns_seeds, bootstrap_nodes, dht)

class P2PNode:

    def __init__(self, node, db):
        self.node = node
        self.db = db
        self.peer_ban_repo = repos.PeerBanRepo(db)
        self.peers: bootstrap.Dict[str, EncryptedPeer] = {}
        self.banned_peers: bootstrap.Dict[str, float] = {}
        self.banned_node_ids: bootstrap.Dict[str, float] = {}
        self._pending_checkpoint_requests: bootstrap.Dict[str, bootstrap.asyncio.Future] = {}
        self._lock = bootstrap.asyncio.Lock()
        self._server = None
        self._dht_server = None
        self._dht_task = None
        self._discovery_stop = bootstrap.asyncio.Event()
        self._metrics = {'messages_sent': 0, 'messages_received': 0, 'bytes_sent': 0, 'bytes_received': 0, 'connections': 0, 'errors': 0, 'peers_discovered': 0}
        self.peer_scores: bootstrap.Dict[str, bootstrap.Dict] = {}
        self.reputation_weights = {'valid_block': 2, 'valid_tx': 1, 'valid_peer_list': 1, 'ping_response': 1, 'invalid_message': -2, 'decrypt_failed': -5, 'oversized_message': -10, 'protocol_violation': -15, 'invalid_block': -20, 'invalid_tx': -15}
        self.score_decay_interval = 3600
        self.max_positive_score = 100
        self.min_score_for_ban = -config.BAN_THRESHOLD
        self.rate_limits = {config.MSG_PING: (30, 60), config.MSG_GET_PEERS: (10, 60), config.MSG_GET_BLOCKS: (60, 60), config.MSG_GET_STATUS: (30, 60), config.MSG_GET_CHECKPOINT: (10, 60), config.MSG_NEW_BLOCK: (100, 60), config.MSG_NEW_TX: (200, 60), config.MSG_NEW_MOVE: (1200, 60)}
        self.peer_message_counts: bootstrap.Dict[str, bootstrap.Dict[int, bootstrap.List[float]]] = {}
        self._seen_block_hashes: bootstrap.OrderedDict = bootstrap.OrderedDict()
        self._seen_tx_hashes: bootstrap.OrderedDict = bootstrap.OrderedDict()
        self._seen_max = 8192
        self._bootstrap_cooldown_log_ts: bootstrap.Dict[str, float] = {}
        self.peer_subnets: bootstrap.Dict[str, str] = {}
        self.subnet_peer_count: bootstrap.Dict[str, int] = {}
        self.max_peers_per_subnet = int(config.CONFIG.get('p2p', {}).get('max_peers_per_subnet', 64))
        self.max_peers_per_asn = int(config.CONFIG.get('p2p', {}).get('max_peers_per_asn', 16))
        self.asn_cache: bootstrap.Dict[str, str] = {}
        self.peer_asns: bootstrap.Dict[str, str] = {}
        self.asn_peer_count: bootstrap.Dict[str, int] = {}
        self.public_ip = config.EXTERNAL_IP if config.EXTERNAL_IP else None
        self._local_ips: bootstrap.Set[str] = {'127.0.0.1', 'localhost', '::1', '0.0.0.0', '::'}
        if config.BIND_IP and config.BIND_IP not in ('0.0.0.0', '::'):
            self._local_ips.add(config.BIND_IP)
        if self.public_ip:
            self._local_ips.add(self.public_ip)
        try:
            _hname = bootstrap.socket.gethostname()
            self._local_ips.add(bootstrap.socket.gethostbyname(_hname))
            for _ip in bootstrap.socket.gethostbyname_ex(_hname)[2]:
                self._local_ips.add(_ip)
        except Exception:
            pass
        self._pending_handshakes: bootstrap.Dict[str, int] = {}
        self._max_pending_handshakes = 4
        self._conn_per_ip: bootstrap.Dict[str, int] = {}
        self._max_conn_per_ip = 8
        self._handshake_rate_limiter: bootstrap.Dict[str, bootstrap.List[float]] = {}
        self._handshake_rate_limit = (30, 60)
        self._pqe_rate_limiter: bootstrap.Dict[str, bootstrap.List[float]] = {}
        self._pqe_rate_limit = (10, 60)
        self._conn_tasks: set = set()
        self._dial_sem = bootstrap.asyncio.Semaphore(8)
        self.pqc_executor = bootstrap.ThreadPoolExecutor(max_workers=4, thread_name_prefix='pqc-validate')
        self.state_pruning_enabled = config.CONFIG.get('consensus', {}).get('state_pruning', True)
        self.prune_interval = config.CONFIG.get('consensus', {}).get('prune_interval', 86400)
        self.max_state_age = config.CONFIG.get('consensus', {}).get('max_state_age', 2592000)
        self.base_fee_per_gas = 10
        self.target_gas_per_block = 5000000
        self.max_gas_per_block = config.MAX_BLOCK_GAS
        self.fee_history: bootstrap.deque = bootstrap.deque(maxlen=100)
        self.finality_epoch_length = config.FINALITY_EPOCH_LENGTH
        self.checkpoint_interval = config.CONFIG.get('consensus', {}).get('checkpoint_interval', 100)
        p2p_cfg = getattr(self.node, 'config', {}).get('p2p', {}) if self.node else config.CONFIG.get('p2p', {})
        self.genesis_node, self.dns_seeds, self.bootstrap_nodes, self.dht_bootstrap_nodes = resolve_seed_lists(p2p_cfg)
        self.registry_url = str(p2p_cfg.get('registry_url', config.REGISTRY_URL_DEFAULT)).strip()
        self.registry_enabled = config._strict_bool('p2p.registry_enabled', p2p_cfg.get('registry_enabled', True))
        self.registry_interval = max(60, int(p2p_cfg.get('registry_interval', 300) or 300))
        self._registry_last_fetch = 0.0
        self._registry_cached_peers = []
        self.fallback_nodes = list(p2p_cfg.get('fallback_nodes', []))
        self.dht_port = int(p2p_cfg.get('dht_port', config.DHT_PORT))
        self.allow_private_peers = config._strict_bool('p2p.allow_private_peers', p2p_cfg.get('allow_private_peers', False))
        self._dial_backoff: bootstrap.Dict[str, float] = {}
        self._dial_fails: bootstrap.Dict[str, int] = {}
        self._dial_last_log: bootstrap.Dict[str, float] = {}
        self.max_peers = config.MAX_PEERS
        self.ban_threshold = config.BAN_THRESHOLD
        self.ban_duration = config.BAN_DURATION
        self.gossip_fanout = 3
        self.config_discovery_interval = config.CONFIG.get('p2p', {}).get('discovery_interval', config.DISCOVERY_INTERVAL)

    def _track_task(self, t: 'asyncio.Task') -> 'asyncio.Task':
        self._conn_tasks.add(t)
        t.add_done_callback(self._conn_tasks.discard)
        return t

    async def start(self):
        bind_host = None if config.BIND_IP in ('0.0.0.0', '::', '', 'all') else config.BIND_IP
        _p2p_port = int(self.node.config.get('node', {}).get('p2p_port', config.P2P_PORT))
        self._server = await bootstrap.asyncio.start_server(self._handle_connection, bind_host, _p2p_port, limit=100)
        bootstrap.logger.info(f'[P2P] Encrypted server listening on port {_p2p_port} (dual-stack: {bind_host is None})')
        try:
            now = bootstrap.time.time()
            active_bans = await self.peer_ban_repo.get_active()
            for row in active_bans:
                exp = float(row['expires_at'])
                if exp > now:
                    self.banned_peers[row['address']] = exp
                    if row.get('node_id'):
                        self.banned_node_ids[row['node_id']] = exp
            if active_bans:
                bootstrap.logger.info(f'[P2P] Loaded {len(active_bans)} persisted peer bans')
            await self.peer_ban_repo.delete_expired()
        except Exception as e:
            bootstrap.logger.warning(f'[P2P] Failed to load persisted peer bans: {e}')
        if DHT_AVAILABLE and config.DHT_ENABLED:
            self._dht_task = bootstrap.asyncio.create_task(self._dht_loop())
        self._bg_tasks = [bootstrap.asyncio.create_task(self._discovery_loop()), bootstrap.asyncio.create_task(self._heartbeat_loop()), bootstrap.asyncio.create_task(self._sync_loop()), bootstrap.asyncio.create_task(self._cache_loop()), bootstrap.asyncio.create_task(self._score_decay_loop()), bootstrap.asyncio.create_task(self._peer_rotation_loop())]
        await self.start_pruning()

    async def shutdown(self):
        self._discovery_stop.set()
        if self._dht_server is not None:
            try:
                self._dht_server.stop()
            except Exception as e:
                bootstrap.logger.debug(f'[DHT] Stop error: {e}')
        if self._dht_task:
            self._dht_task.cancel()
            try:
                await self._dht_task
            except bootstrap.asyncio.CancelledError:
                pass
        to_cancel = list(getattr(self, '_bg_tasks', [])) + list(self._conn_tasks)
        prune = getattr(self, '_prune_task', None)
        if prune is not None:
            to_cancel.append(prune)
        for t in to_cancel:
            if not t.done():
                t.cancel()
        for t in to_cancel:
            try:
                await t
            except bootstrap.asyncio.CancelledError:
                pass
            except Exception:
                pass
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        for peer in list(self.peers.values()):
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
        bootstrap.logger.debug('[P2P] Shutdown complete')

    async def _handle_connection(self, reader: bootstrap.asyncio.StreamReader, writer: bootstrap.asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        if not addr:
            writer.close()
            await writer.wait_closed()
            return
        sock = writer.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(bootstrap.socket.IPPROTO_TCP, bootstrap.socket.TCP_NODELAY, 1)
                sock.setsockopt(bootstrap.socket.SOL_SOCKET, bootstrap.socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
        addr_str = f'[{addr[0]}]:{addr[1]}' if ':' in str(addr[0]) else f'{addr[0]}:{addr[1]}'
        if self._is_banned(address=addr_str):
            writer.close()
            await writer.wait_closed()
            return
        ip_only = addr[0]
        pending = self._pending_handshakes.get(ip_only, 0)
        if pending >= self._max_pending_handshakes:
            writer.close()
            await writer.wait_closed()
            return
        now_ts = bootstrap.time.time()
        hs_timestamps = self._handshake_rate_limiter.setdefault(ip_only, [])
        hs_timestamps[:] = [t for t in hs_timestamps if now_ts - t < 60]
        if len(hs_timestamps) >= self._handshake_rate_limit[0]:
            writer.close()
            await writer.wait_closed()
            return
        hs_timestamps.append(now_ts)
        self._pending_handshakes[ip_only] = pending + 1
        try:
            peer = await bootstrap.asyncio.wait_for(perform_handshake(reader, writer, self.node.node_id, self.node.height, config.VERSION, self.node.priv, self.node.pub, allow_genesis_learn=False), timeout=10.0)
        except Exception:
            peer = None
        finally:
            self._pending_handshakes[ip_only] = max(0, self._pending_handshakes.get(ip_only, 1) - 1)
            if self._pending_handshakes[ip_only] == 0:
                self._pending_handshakes.pop(ip_only, None)
        if peer is None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        if peer.node_id == self.node.node_id:
            bootstrap.logger.debug(f'[P2P] Rejecting self-connection from {peer.address}')
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return
        if self._is_banned(node_id=peer.node_id):
            bootstrap.logger.info(f'[P2P] Rejecting inbound peer {peer.address}: node_id {peer.node_id[:16]} is banned')
            writer.close()
            await writer.wait_closed()
            return
        async with self._lock:
            existing = [p for p in self.peers.values() if p.node_id == peer.node_id]
            if existing:
                _lb = parse_ip_port(peer.address, config.P2P_PORT)[0] in ('127.0.0.1', 'localhost', '::1')
                if _dial_dup_action(self.node.node_id, peer.node_id, 'in', _lb, True) != 'replace_existing':
                    bootstrap.logger.debug(f'[P2P] Already connected to node {peer.node_id[:16]}, closing inbound duplicate')
                    writer.close()
                    await writer.wait_closed()
                    return
                bootstrap.logger.debug(f'[P2P] DIAL-KEEPER-1 replacing duplicate socket to node {peer.node_id[:16]} with inbound keeper')
                for _old in existing:
                    try:
                        if _old.writer is not None:
                            _old.writer.close()
                    except Exception:
                        pass
                    if self.peers.get(_old.address) is _old:
                        del self.peers[_old.address]
            peer_ip = parse_ip_port(peer.address, config.P2P_PORT)[0]
            ip_conns = self._conn_per_ip.get(peer_ip, 0)
            is_bootstrap = any((peer_ip in b for b in self.bootstrap_nodes)) or peer_ip == self.genesis_node
            if not is_bootstrap and ip_conns >= self._max_conn_per_ip:
                bootstrap.logger.info(f'[P2P] Rejecting inbound peer {peer.address}: per-IP cap ({ip_conns}/{self._max_conn_per_ip})')
                writer.close()
                await writer.wait_closed()
                return
            if not self._track_peer_subnet(peer):
                bootstrap.logger.info(f'[P2P] Rejecting inbound peer {peer.address}: subnet diversity cap reached')
                writer.close()
                await writer.wait_closed()
                return
            self._conn_per_ip[peer_ip] = ip_conns + 1
            if len(self.peers) >= self.max_peers:
                oldest = min(self.peers.values(), key=lambda p: p.last_seen)
                try:
                    if oldest.writer is not None:
                        oldest.writer.close()
                except Exception as _ev_e:
                    bootstrap.logger.debug(f'[P2P] evict close failed for {oldest.address}: {_ev_e}')
                del self.peers[oldest.address]
            self.peers[peer.address] = peer
            self._metrics['connections'] += 1
            self._metrics['peers_discovered'] += 1
        bootstrap.logger.info(f'[P2P] New encrypted peer: {peer.address} (node {peer.node_id[:16]})')
        self._track_task(bootstrap.asyncio.create_task(self._send_message(peer, config.MSG_GET_STATUS, b'{}')))
        self.tip_push(peer)
        self._track_task(bootstrap.asyncio.create_task(self._peer_loop(peer)))

    async def _peer_loop(self, peer: EncryptedPeer):
        writer_task = self._track_task(bootstrap.asyncio.create_task(self._peer_writer(peer)))
        try:
            while True:
                try:
                    len_data = await peer.reader.readexactly(4)
                except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                    break
                msg_len = bootstrap.struct.unpack('>I', len_data)[0]
                if msg_len > 4000000:
                    self._ban_peer(peer.address, 'message too large', node_id=peer.node_id)
                    break
                try:
                    encrypted_payload = await peer.reader.readexactly(msg_len)
                except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                    break
                plaintext = peer.decrypt_message(encrypted_payload)
                if plaintext is None:
                    self._ban_peer(peer.address, 'decryption failed', node_id=peer.node_id)
                    break
                if len(plaintext) < 1:
                    continue
                msg_type = plaintext[0]
                data = plaintext[1:]
                self._metrics['messages_received'] += 1
                self._metrics['bytes_received'] += len(plaintext)
                await self._process_message(peer, msg_type, data)
                peer.last_seen = bootstrap.time.time()
        except (bootstrap.asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            bootstrap.logger.error(f'[P2P] Error in peer loop {peer.address}: {e}')
        finally:
            writer_task.cancel()
            try:
                await writer_task
            except (bootstrap.asyncio.CancelledError, Exception):
                pass
            async with self._lock:
                if self.peers.get(peer.address) is peer:
                    del self.peers[peer.address]
                subnet = self.peer_subnets.pop(peer.address, None)
                if subnet and subnet in self.subnet_peer_count:
                    self.subnet_peer_count[subnet] = max(0, self.subnet_peer_count[subnet] - 1)
                    if self.subnet_peer_count[subnet] <= 0:
                        self.subnet_peer_count.pop(subnet, None)
                _asn = self.peer_asns.pop(peer.address, None)
                if _asn and _asn in self.asn_peer_count:
                    self.asn_peer_count[_asn] = max(0, self.asn_peer_count[_asn] - 1)
                    if self.asn_peer_count[_asn] <= 0:
                        self.asn_peer_count.pop(_asn, None)
                peer_ip = parse_ip_port(peer.address, config.P2P_PORT)[0]
                if peer_ip in self._conn_per_ip:
                    self._conn_per_ip[peer_ip] = max(0, self._conn_per_ip[peer_ip] - 1)
                    if self._conn_per_ip[peer_ip] <= 0:
                        self._conn_per_ip.pop(peer_ip, None)
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
            bootstrap.logger.info(f'[P2P] Peer disconnected: {peer.address}')

    def _bound_peer_height(self, claimed: int) -> int:
        try:
            claimed = int(claimed)
        except (TypeError, ValueError):
            return 0
        if claimed > self.node.height + 100:
            return self.node.height
        return max(0, claimed)

    async def _process_message(self, peer: EncryptedPeer, msg_type: int, data: bytes):
        peer.last_seen = bootstrap.time.time()
        if not self._check_rate_limit(peer, msg_type):
            return
        if msg_type in (config.MSG_NEW_BLOCK, config.MSG_GET_BLOCKS, config.MSG_BLOCKS, config.MSG_NEW_TX, config.MSG_GET_PEERS, config.MSG_PEERS, config.MSG_GET_STATUS, config.MSG_STATUS):
            if not await self._validate_payload(peer, msg_type, data):
                self._update_reputation(peer, 'protocol_violation')
                return
        try:
            if msg_type == config.MSG_PING:
                try:
                    if data:
                        info = bootstrap.json.loads(data.decode())
                        if 'height' in info:
                            peer.height = max(peer.height, self._bound_peer_height(info['height']))
                except Exception:
                    pass
                pong_payload = bootstrap.json.dumps({'height': self.node.height}).encode()
                await self._send_message(peer, config.MSG_PONG, pong_payload)
                peer.last_seen = bootstrap.time.time()
            elif msg_type == config.MSG_PONG:
                try:
                    if data:
                        info = bootstrap.json.loads(data.decode())
                        if 'height' in info:
                            peer.height = max(peer.height, self._bound_peer_height(info['height']))
                except Exception:
                    pass
                peer.last_seen = bootstrap.time.time()
            elif msg_type == config.MSG_GET_PEERS:
                async with self._lock:
                    peers_list = []
                    for p in self.peers.values():
                        h = parse_ip_port(p.address)[0]
                        peers_list.append(f'[{h}]:{p.p2p_port}' if ':' in str(h) else f'{h}:{p.p2p_port}')
                payload = bootstrap.json.dumps({'peers': peers_list[:100]}).encode()
                await self._send_message(peer, config.MSG_PEERS, payload)
            elif msg_type == config.MSG_PEERS:
                try:
                    data_json = bootstrap.json.loads(data.decode())
                    _seen_eps = set()
                    _spawned = 0
                    for addr in data_json.get('peers', []):
                        if not isinstance(addr, str) or not addr:
                            continue
                        if addr in _seen_eps:
                            continue
                        _seen_eps.add(addr)
                        if addr not in self.peers and (not self._is_banned(address=addr)):
                            if _spawned >= 32:
                                break
                            _spawned += 1
                            self._track_task(bootstrap.asyncio.create_task(self._connect_to_peer(addr)))
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_PEERS error from {peer.address}: {e}')
            elif msg_type == config.MSG_GET_BLOCKS:
                try:
                    req = bootstrap.json.loads(data.decode())
                    start = req.get('start', 0)
                    end = req.get('end', self.node.height)
                    if end - start > 500:
                        end = start + 500
                    blocks = await self.node.get_blocks_range(start, end)
                    payload = bootstrap.json.dumps({'blocks': blocks}).encode()
                    await self._send_message(peer, config.MSG_BLOCKS, payload)
                    bootstrap.logger.info(f'[P2P] Served GET_BLOCKS [{start},{end}] -> {len(blocks)} blocks to {peer.address}')
                except Exception as e:
                    bootstrap.logger.warning(f'[P2P] MSG_GET_BLOCKS error from {peer.address}: {e}', exc_info=True)
            elif msg_type == config.MSG_BLOCKS:
                try:
                    req = bootstrap.json.loads(data.decode())
                    blocks = req.get('blocks', [])
                    await self.node.import_blocks(blocks)
                    if blocks:
                        try:
                            peer.height = max(peer.height, self._bound_peer_height(int(blocks[-1].get('id', 0)) + 1))
                        except Exception:
                            pass
                    bootstrap.logger.info(f'[P2P] MSG_BLOCKS from {peer.address}: {len(blocks)} blocks processed')
                    try:
                        if int(getattr(peer, 'height', 0) or 0) > int(getattr(self.node, 'height', 0) or 0):
                            _task = getattr(self.node, '_stale_sync_task', None)
                            if _task is None or getattr(_task, 'done', lambda: True)():
                                self.node._last_stale_sync_ts = bootstrap.time.time()
                                self.node._stale_sync_task = bootstrap.asyncio.create_task(self.sync_with_peers())
                    except Exception as _cu:
                        bootstrap.logger.debug(f'[P2P] catch-up follow-up sync deferred: {_cu}')
                except Exception as e:
                    bootstrap.logger.warning(f'[P2P] MSG_BLOCKS error from {peer.address}: {e}', exc_info=True)
            elif msg_type == config.MSG_NEW_BLOCK:
                try:
                    block_data = bootstrap.json.loads(data.decode())
                    try:
                        peer.height = max(peer.height, self._bound_peer_height(int(block_data.get('id', 0)) + 1))
                    except Exception:
                        pass
                    if not self._mark_seen_block(str(block_data.get('hash', ''))):
                        return
                    _status = await self.node.receive_block(block_data)
                    if _status == 'rejected':
                        self._unmark_seen_block(str(block_data.get('hash', '')))
                    if _status == 'ok':
                        bootstrap.asyncio.create_task(self.broadcast_block(block_data, force=True))
                    if _status in ('disconnected', 'ignored'):
                        _bid = int(block_data.get('id', 0) or 0)
                        _start = max(0, _bid - 100)
                        _peer_tail = int(getattr(peer, 'height', 0) or 0) - 1
                        _end = max(_bid, _peer_tail)
                        if _end < _bid:
                            _end = _bid
                        _fp = bootstrap.json.dumps({'start': _start, 'end': _end}).encode()
                        await self._send_message(peer, config.MSG_GET_BLOCKS, _fp)
                    if peer.height > self.node.height:
                        bootstrap.asyncio.create_task(self.sync_with_peers())
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_NEW_BLOCK error from {peer.address}: {e}')
            elif msg_type == config.MSG_NEW_TX:
                try:
                    tx_data = bootstrap.json.loads(data.decode())
                    _tx_key = tx_data.get('tx_hash') or tx_data.get('hash', '')
                    if not _tx_key:
                        return
                    if not self._mark_seen_tx(str(_tx_key)):
                        return
                    if not await self.node.receive_transaction(tx_data):
                        self._unmark_seen_tx(str(_tx_key))
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_NEW_TX error from {peer.address}: {e}')
            elif msg_type == config.MSG_SLASH:
                try:
                    req = bootstrap.json.loads(data.decode())
                    bootstrap.logger.info(f'[P2P] Unverified slash report for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (slashing is local-only)')
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_SLASH parse error from {peer.address}: {e}')
            elif msg_type == config.MSG_GET_STATUS:
                status = {'height': self.node.height, 'peers': len(self.peers), 'miners': len(self.node.miners), 'version': config.VERSION, 'last_hash': getattr(self.node, 'last_hash', '')}
                payload = bootstrap.json.dumps(status).encode()
                await self._send_message(peer, config.MSG_STATUS, payload)
            elif msg_type == config.MSG_STATUS:
                try:
                    status = bootstrap.json.loads(data.decode())
                    new_h = int(status.get('height', 0))
                    peer.height = max(peer.height, self._bound_peer_height(new_h))
                    peer.version = status.get('version', 'unknown')
                    bootstrap.logger.debug(f'[P2P] Peer {peer.address} status: height={peer.height}, version={peer.version}')
                    if peer.height > self.node.height:
                        bootstrap.asyncio.create_task(self.sync_with_peers())
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] Error handling MSG_STATUS from {peer.address}: {e}')
            elif msg_type == config.MSG_GET_CHECKPOINT:
                checkpoint = await self.node.finality_repo.get_latest()
                resp = {'block_id': checkpoint['block_id'] if checkpoint else 0, 'hash': checkpoint['hash'] if checkpoint else self.node.blocks[0]['hash'] if self.node.blocks else '', 'epoch': checkpoint['epoch'] if checkpoint else 0}
                await self._send_message(peer, config.MSG_CHECKPOINT, bootstrap.json.dumps(resp).encode())
            elif msg_type == config.MSG_CHECKPOINT:
                try:
                    resp = bootstrap.json.loads(data.decode())
                    fut = self._pending_checkpoint_requests.get(peer.address)
                    if fut and (not fut.done()):
                        fut.set_result(resp)
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_CHECKPOINT error from {peer.address}: {e}')
            elif msg_type == config.MSG_BAN:
                try:
                    req = bootstrap.json.loads(data.decode())
                    bootstrap.logger.info(f'[P2P] Unverified ban request for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (ban/unban is local-only)')
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_BAN/UNBAN parse error from {peer.address}: {e}')
            elif msg_type == config.MSG_UNBAN:
                try:
                    req = bootstrap.json.loads(data.decode())
                    bootstrap.logger.info(f'[P2P] Unverified unban request for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (ban/unban is local-only)')
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_UNBAN parse error from {peer.address}: {e}')
            elif msg_type == config.MSG_NEW_MOVE:
                try:
                    req = bootstrap.json.loads(data.decode())
                    g_miner = req.get('miner_id')
                    g_maze = req.get('maze_id') or g_miner
                    g_dir = req.get('direction')
                    g_sig = req.get('signature')
                    g_snap = req.get('row')
                    if g_miner and g_dir and g_sig and getattr(self.node, 'consensus', None):
                        g_applied = False
                        if g_snap and req.get('move_nonce') is not None:
                            g_local = await self.node.maze_repo.get_by_maze_id(g_maze)
                            g_mrow = await self.node.miner_repo.get(g_miner) if g_miner else None
                            g_pub = None
                            if g_mrow and g_mrow.get('pub'):
                                g_pub = g_mrow['pub']
                                if req.get('pub') and str(req['pub']).lower() != str(g_pub).lower():
                                    g_pub = None
                            elif req.get('pub') and str(g_miner).startswith('PC_'):
                                try:
                                    _g_der = 'PC_' + bootstrap.hashlib.sha256(f'{util.pubkey_to_address(str(req['pub']))}_mcx_miner'.encode()).hexdigest()[:32].upper()
                                    if _g_der == g_miner:
                                        g_pub = str(req['pub'])
                                except Exception:
                                    g_pub = None
                            if g_local and g_pub:
                                g_auth = self.node.consensus._move_auth_bytes(g_miner, g_local.get('maze_id') or g_miner, int(req.get('growthcount', g_local.get('growthcount', 0))), int(req['move_nonce']), g_dir)
                                if crypto.verify_signature_bytes(g_pub, g_auth, g_sig):
                                    try:
                                        if int(g_snap.get('movenonce', -1)) >= int(g_local.get('movenonce', -1)):
                                            if 'maze_id' in g_snap and str(g_snap['maze_id']) != str(g_local.get('maze_id')) or ('minerid' in g_snap and str(g_snap['minerid']) != str(g_local.get('minerid'))):
                                                raise ValueError('move-gossip row identity mismatch; legacy path')
                                            g_merged = dict(g_local)
                                            for g_k, g_v in g_snap.items():
                                                if g_k in maze.MAZE_ROW_COLS and g_k in maze._MOVE_ROW_SAFE_COLS:
                                                    g_merged[g_k] = g_v
                                            g_merged['lastactiveheight'] = max(int(g_local.get('lastactiveheight', 0) or 0), int(g_merged.get('lastactiveheight', 0) or 0))
                                            await self.node.maze_repo.upsert(g_merged)
                                            g_ph = req.get('pos_hist') or []
                                            if g_ph:
                                                g_hist = bootstrap.deque(maxlen=6)
                                                for g_p in g_ph:
                                                    g_hist.append(tuple((int(g_x) for g_x in g_p)))
                                                self.node.consensus._pos_history[g_maze] = g_hist
                                            else:
                                                self.node.consensus._pos_history.pop(g_maze, None)
                                            if req.get('oscillating'):
                                                self.node.consensus._oscillating_mazes.add(g_maze)
                                            else:
                                                self.node.consensus._oscillating_mazes.discard(g_maze)
                                            g_applied = True
                                    except Exception as _ge:
                                        bootstrap.logger.debug(f'[P2P] move-gossip snapshot apply error: {_ge}')
                                else:
                                    bootstrap.logger.debug(f'[P2P] move-gossip signature invalid for {str(g_miner)[:16]}')
                            else:
                                bootstrap.logger.debug(f'[P2P] move-gossip snapshot missing local row or pub binding for {str(g_miner)[:16]}')
                        if not g_applied:
                            before_n = len(self.node.consensus._pending_maze_updates)
                            g_ok, g_msg, _g_state = await self.node.consensus.process_move(g_miner, g_maze, g_dir, g_sig, None)
                            if g_ok:
                                del self.node.consensus._pending_maze_updates[before_n:]
                                try:
                                    g_row = await self.node.maze_repo.get_by_maze_id(g_maze)
                                    if g_row and int(req.get('height', 0) or 0) > int(g_row.get('lastactiveheight', -1000000) or -1000000):
                                        g_row['lastactiveheight'] = int(req['height'])
                                        await self.node.maze_repo.upsert({**dict(g_row), 'updatedat': int(bootstrap.time.time())})
                                except Exception:
                                    pass
                            else:
                                bootstrap.logger.debug(f'[P2P] move-gossip skipped for {str(g_miner)[:16]}: {g_msg}')
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_NEW_MOVE apply error: {e}')
            else:
                bootstrap.logger.warning(f'[P2P] Unknown message type: {msg_type}')
        except Exception as e:
            bootstrap.logger.error(f'[P2P] Error processing message: {e}')
            self._update_reputation(peer, 'invalid_message')

    @staticmethod
    def _msg_priority(msg_type: int) -> int:
        if msg_type in (config.MSG_BLOCKS, config.MSG_NEW_BLOCK, config.MSG_CHECKPOINT, config.MSG_GET_CHECKPOINT):
            return 0
        if msg_type in (config.MSG_PING, config.MSG_PONG, config.MSG_STATUS, config.MSG_GET_STATUS):
            return 1
        if msg_type in (config.MSG_NEW_TX, config.MSG_GET_BLOCKS):
            return 2
        return 3

    async def _peer_writer(self, peer: EncryptedPeer):
        try:
            while True:
                _prio, _ctr, msg_type, payload = await peer.send_queue.get()
                if peer.banned:
                    continue
                plaintext = bytes([msg_type]) + payload
                async with peer.write_lock:
                    try:
                        encrypted = peer.encrypt_message(plaintext)
                        peer.writer.write(bootstrap.struct.pack('>I', len(encrypted)) + encrypted)
                        await peer.writer.drain()
                        self._metrics['messages_sent'] += 1
                        self._metrics['bytes_sent'] += len(plaintext)
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        bootstrap.logger.info(f'[P2P] Writer to {peer.address} reset: {e}')
                        break
                    except Exception as e:
                        bootstrap.logger.debug(f'[P2P] Writer to {peer.address} unexpected: {e}')
                        break
        except bootstrap.asyncio.CancelledError:
            pass
        finally:
            try:
                peer.writer.close()
            except Exception:
                pass

    async def _send_message(self, peer: EncryptedPeer, msg_type: int, payload: bytes):
        if peer.banned:
            return
        prio = self._msg_priority(msg_type)
        peer._send_counter += 1
        try:
            peer.send_queue.put_nowait((prio, peer._send_counter, msg_type, payload))
        except bootstrap.asyncio.QueueFull:
            bootstrap.logger.debug(f'[P2P] Send queue full for {peer.address}, dropping type={msg_type}')
            self._update_reputation(peer, 'invalid_message')

    async def broadcast_message(self, msg_type: int, payload: bytes, exclude: bootstrap.Set[str]=None):
        if exclude is None:
            exclude = set()
        async with self._lock:
            peers_list = list(self.peers.values())
        peers_list = [p for p in peers_list if p.address not in exclude and (not p.banned)]
        if not peers_list:
            return
        if len(peers_list) <= self.gossip_fanout:
            selected = peers_list
        else:
            selected = bootstrap.random.sample(peers_list, self.gossip_fanout)
        for peer in selected:
            self._track_task(bootstrap.asyncio.create_task(self._send_message(peer, msg_type, payload)))

    def _check_rate_limit(self, peer: EncryptedPeer, msg_type: int) -> bool:
        now = bootstrap.time.time()
        addr = peer.address
        if addr not in self.peer_message_counts:
            self.peer_message_counts[addr] = {}
        if msg_type not in self.peer_message_counts[addr]:
            self.peer_message_counts[addr][msg_type] = []
        limit, window = self.rate_limits.get(msg_type, (100, 60))
        cutoff = now - window
        self.peer_message_counts[addr][msg_type] = [ts for ts in self.peer_message_counts[addr][msg_type] if ts > cutoff]
        if len(self.peer_message_counts[addr][msg_type]) >= limit:
            self._update_reputation(peer, 'invalid_message')
            bootstrap.logger.warning(f'[P2P] Rate limit exceeded: {addr} msg_type={msg_type}')
            return False
        self.peer_message_counts[addr][msg_type].append(now)
        return True

    def _update_reputation(self, peer: EncryptedPeer, action: str):
        if action not in self.reputation_weights:
            return
        delta = self.reputation_weights[action]
        old_score = peer.score
        peer.score = max(-1000, min(self.max_positive_score, peer.score + delta))
        if peer.address not in self.peer_scores:
            self.peer_scores[peer.address] = {'score': 0, 'breakdown': bootstrap.defaultdict(int), 'last_update': bootstrap.time.time()}
        self.peer_scores[peer.address]['score'] = peer.score
        self.peer_scores[peer.address]['breakdown'][action] += 1
        self.peer_scores[peer.address]['last_update'] = bootstrap.time.time()
        if delta < 0:
            bootstrap.logger.debug(f'[P2P] Reputation decrease: {peer.address} {action} ({old_score} -> {peer.score})')
        else:
            bootstrap.logger.debug(f'[P2P] Reputation increase: {peer.address} {action} ({old_score} -> {peer.score})')
        if peer.score <= self.min_score_for_ban:
            self._ban_peer(peer.address, f'score {peer.score} below threshold', node_id=peer.node_id)

    def _get_subnet(self, address: str) -> str:
        try:
            host = parse_ip_port(address)[0]
            ip_obj = bootstrap.ipaddress.ip_address(host)
            if ip_obj.version == 4:
                parts = host.split('.')
                return f'{parts[0]}.{parts[1]}.{parts[2]}.0/24'
            else:
                return str(bootstrap.ipaddress.IPv6Network(f'{host}/48', strict=False))
        except Exception:
            pass
        return 'unknown'

    def _get_asn(self, ip_str: str) -> str:
        if ip_str in self.asn_cache:
            return self.asn_cache[ip_str]
        asn = 'unknown'
        try:
            ip_obj = bootstrap.ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, bootstrap.ipaddress.IPv4Address):
                for net_str, label in config.ASN_STATIC_MAP:
                    try:
                        if ip_obj in bootstrap.ipaddress.ip_network(net_str):
                            asn = label
                            break
                    except ValueError:
                        continue
                if asn == 'unknown':
                    parts = ip_str.split('.')
                    asn = f'AS-{parts[0]}.{parts[1]}.0.0/16'
            else:
                asn = f'AS-IPv6-{str(ip_obj)[:12]}'
        except ValueError:
            pass
        self.asn_cache[ip_str] = asn
        return asn

    def _track_peer_subnet(self, peer: EncryptedPeer) -> bool:
        host = parse_ip_port(peer.address)[0]
        subnet = self._get_subnet(peer.address)
        asn = self._get_asn(host)
        current = self.subnet_peer_count.get(subnet, 0)
        if current >= self.max_peers_per_subnet:
            return False
        try:
            ip_obj = bootstrap.ipaddress.ip_address(host)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            is_private = True
        if not is_private:
            asn_current = self.asn_peer_count.get(asn, 0)
            if asn_current >= self.max_peers_per_asn:
                return False
            self.peer_asns[peer.address] = asn
            self.asn_peer_count[asn] = asn_current + 1
        self.peer_subnets[peer.address] = subnet
        self.subnet_peer_count[subnet] = current + 1
        return True

    def _check_eclipse_resistance(self) -> bootstrap.Dict[str, int]:
        return dict(self.subnet_peer_count)

    async def _validate_payload(self, peer: EncryptedPeer, msg_type: int, data: bytes) -> bool:
        try:
            if msg_type in (config.MSG_NEW_BLOCK, config.MSG_GET_BLOCKS, config.MSG_BLOCKS):
                payload = bootstrap.json.loads(data.decode())
                if 'blocks' in payload:
                    for blk in payload['blocks']:
                        if not isinstance(blk, dict) or 'id' not in blk or 'hash' not in blk:
                            return False
                if 'start' in payload and (not isinstance(payload['start'], int)):
                    return False
                if 'end' in payload and (not isinstance(payload['end'], int)):
                    return False
            elif msg_type in (config.MSG_NEW_TX,):
                payload = bootstrap.json.loads(data.decode())
                if not isinstance(payload, dict) or 'tx_hash' not in payload:
                    return False
            elif msg_type == config.MSG_GET_PEERS:
                if not data or data == b'{}':
                    return True
                payload = bootstrap.json.loads(data.decode())
                return isinstance(payload, dict)
            elif msg_type == config.MSG_PEERS:
                payload = bootstrap.json.loads(data.decode())
                if not isinstance(payload, dict) or ('peers' in payload and (not isinstance(payload['peers'], list))):
                    return False
                if 'peers' in payload:
                    if len(payload['peers']) > 128:
                        return False
                    for _ep in payload['peers']:
                        if not isinstance(_ep, str) or len(_ep) > 256 or (not _ep):
                            return False
            elif msg_type == config.MSG_GET_STATUS:
                if not data or data == b'{}':
                    return True
                payload = bootstrap.json.loads(data.decode())
                return isinstance(payload, dict)
            elif msg_type == config.MSG_STATUS:
                payload = bootstrap.json.loads(data.decode())
                if not isinstance(payload, dict) or ('height' in payload and (not isinstance(payload['height'], int))):
                    return False
            return True
        except Exception as e:
            bootstrap.logger.debug(f'[P2P] Payload validation failed for {peer.address} type={msg_type}: {e}')
            return False

    async def _peer_rotation_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(600)
            try:
                async with self._lock:
                    snapshot = list(self.peers.values())
                if len(snapshot) < max(4, self.max_peers // 2):
                    continue
                now = bootstrap.time.time()
                at_cap = len(self.peers) >= self.max_peers
                rotated = 0
                candidates = sorted(snapshot, key=lambda p: (p.score, p.last_seen))
                for peer in candidates:
                    peer_ip = parse_ip_port(peer.address, config.P2P_PORT)[0]
                    is_bootstrap = any((peer_ip in b for b in self.bootstrap_nodes)) or peer_ip == self.genesis_node
                    if is_bootstrap:
                        continue
                    stale = now - peer.last_seen > 300
                    bad_score = peer.score < 0
                    if stale or (at_cap and bad_score):
                        try:
                            peer.writer.close()
                        except Exception:
                            pass
                        rotated += 1
                        if rotated >= 3:
                            break
                if rotated:
                    bootstrap.logger.info(f'[P2P] Peer rotation: dropped {rotated} stale/low-score peers')
            except Exception as e:
                bootstrap.logger.debug(f'[P2P] Rotation loop error: {e}')

    async def _score_decay_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(self.score_decay_interval)
            try:
                now = bootstrap.time.time()
                async with self._lock:
                    for peer in self.peers.values():
                        if peer.score > 0:
                            peer.score = max(0, peer.score - 1)
                        elif peer.score < 0:
                            peer.score = min(0, peer.score + 1)
                        if peer.address in self.peer_scores:
                            self.peer_scores[peer.address]['score'] = peer.score
                    for addr in list(self.peer_message_counts.keys()):
                        if addr not in self.peers:
                            del self.peer_message_counts[addr]
                            continue
                        for msg_type in list(self.peer_message_counts[addr].keys()):
                            limit, window = self.rate_limits.get(msg_type, (100, 60))
                            cutoff = now - window
                            self.peer_message_counts[addr][msg_type] = [ts for ts in self.peer_message_counts[addr][msg_type] if ts > cutoff]
                            if not self.peer_message_counts[addr][msg_type]:
                                del self.peer_message_counts[addr][msg_type]
                        if not self.peer_message_counts[addr]:
                            del self.peer_message_counts[addr]
                    for addr in list(self.peer_scores.keys()):
                        if addr not in self.peers and now - self.peer_scores[addr].get('last_update', 0) > 86400:
                            del self.peer_scores[addr]
            except Exception as e:
                bootstrap.logger.error(f'[P2P] Score decay error: {e}')

    def calculate_base_fee(self) -> int:
        if len(self.fee_history) < 2:
            return self.base_fee_per_gas
        recent_avg = sum(self.fee_history) / len(self.fee_history)
        if recent_avg > self.target_gas_per_block:
            return int(self.base_fee_per_gas * 1.125)
        elif recent_avg < self.target_gas_per_block:
            return int(self.base_fee_per_gas * 0.875)
        return self.base_fee_per_gas

    def record_gas_usage(self, gas_used: int):
        self.fee_history.append(gas_used)

    def estimate_fee(self, gas_limit: int, priority_fee: int=0) -> int:
        base = self.calculate_base_fee()
        return gas_limit * (base + priority_fee)

    async def _prune_state_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(self.prune_interval)
            if not self.state_pruning_enabled:
                continue
            try:
                cutoff_height = self.node.height - 10000
                if cutoff_height > 0:
                    await self.db.execute_dml('DELETE FROM state_trie_nodes WHERE ref_count <= 0 AND node_hash NOT IN (SELECT state_root FROM block_state_roots WHERE block_id > ?)', cutoff_height)
                cutoff = bootstrap.time.time() - self.max_state_age
                await self.db.execute_dml('DELETE FROM transaction_receipts WHERE block_id IN (SELECT id FROM blocks WHERE ts < ?)', cutoff)
                await self.db.execute_dml('DELETE FROM contract_events WHERE timestamp < ?', cutoff)
                await self.db.execute_dml('DELETE FROM slashing_events WHERE timestamp < ?', cutoff)
                bootstrap.logger.info(f'[P2P] State pruning complete (cutoff: {bootstrap.datetime.fromtimestamp(cutoff)})')
            except Exception as e:
                bootstrap.logger.error(f'[P2P] State pruning error: {e}')

    async def start_pruning(self):
        if self.state_pruning_enabled:
            self._prune_task = bootstrap.asyncio.create_task(self._prune_state_loop())

    def _mark_seen_block(self, block_hash: str) -> bool:
        if not block_hash:
            return True
        if block_hash in self._seen_block_hashes:
            self._seen_block_hashes.move_to_end(block_hash)
            return False
        self._seen_block_hashes[block_hash] = True
        while len(self._seen_block_hashes) > self._seen_max:
            self._seen_block_hashes.popitem(last=False)
        return True

    def _mark_seen_tx(self, tx_hash: str) -> bool:
        if not tx_hash:
            return True
        if tx_hash in self._seen_tx_hashes:
            self._seen_tx_hashes.move_to_end(tx_hash)
            return False
        self._seen_tx_hashes[tx_hash] = True
        while len(self._seen_tx_hashes) > self._seen_max:
            self._seen_tx_hashes.popitem(last=False)
        return True

    def _unmark_seen_block(self, block_hash: str):
        try:
            self._seen_block_hashes.pop(block_hash, None)
        except Exception:
            pass

    def _unmark_seen_tx(self, tx_hash: str):
        try:
            self._seen_tx_hashes.pop(tx_hash, None)
        except Exception:
            pass

    async def broadcast_block(self, block_data: dict, force: bool=False):
        if not force and (not self._mark_seen_block(str(block_data.get('hash', '')))):
            return
        payload = bootstrap.json.dumps(block_data).encode()
        await self.broadcast_message(config.MSG_NEW_BLOCK, payload)

    async def rebroadcast_block_later(self, block_data: dict, delay: float):
        try:
            await bootstrap.asyncio.sleep(delay)
            await self.broadcast_block(block_data, force=True)
        except Exception:
            pass

    def tip_push(self, peer: EncryptedPeer):
        try:
            for _b in self.node.blocks[-3:]:
                self._track_task(bootstrap.asyncio.create_task(self._send_message(peer, config.MSG_NEW_BLOCK, bootstrap.json.dumps(_b).encode())))
        except Exception:
            pass

    async def broadcast_transaction(self, tx_data: dict):
        _tx_key = tx_data.get('tx_hash') or tx_data.get('hash', '')
        if not self._mark_seen_tx(str(_tx_key)):
            return
        payload = bootstrap.json.dumps(tx_data).encode()
        await self.broadcast_message(config.MSG_NEW_TX, payload)

    def _ban_peer(self, address: str, reason: str, node_id: bootstrap.Optional[str]=None):
        h, _ = parse_ip_port(address)
        if h == config.GENESIS_NODE_HOST or any((h in b for b in self.bootstrap_nodes)):
            now_ts = bootstrap.time.time()
            last_log = self._bootstrap_cooldown_log_ts.get(address, 0.0)
            if now_ts - last_log >= 60.0:
                self._bootstrap_cooldown_log_ts[address] = now_ts
                bootstrap.logger.warning(f'[P2P] Disconnecting bootstrap peer {address}: {reason} (cooldown only, not banning)')
            if address in self.peers:
                del self.peers[address]
            self.banned_peers[address] = bootstrap.time.time() + 15.0
            return
        self.banned_peers[address] = bootstrap.time.time() + self.ban_duration
        if node_id:
            self.banned_node_ids[node_id] = bootstrap.time.time() + self.ban_duration
        if address in self.peers:
            del self.peers[address]
        bootstrap.logger.warning(f'[P2P] Banned peer {address}{(f' (node {node_id[:16]})' if node_id else '')}: {reason}')
        try:
            exp = self.banned_peers.get(address, bootstrap.time.time() + self.ban_duration)
            bootstrap.asyncio.get_running_loop().create_task(self.peer_ban_repo.upsert(address, node_id, reason, exp))
        except RuntimeError:
            pass
        except Exception as e:
            bootstrap.logger.debug(f'[P2P] Persist ban failed for {address}: {e}')

    def _decrease_score(self, peer: EncryptedPeer):
        peer.score -= 1
        if peer.score <= -self.ban_threshold:
            self._ban_peer(peer.address, 'score below threshold', node_id=peer.node_id)

    def _is_banned(self, address: str=None, node_id: str=None) -> bool:
        now = bootstrap.time.time()
        if address and address in self.banned_peers and (now < self.banned_peers[address]):
            return True
        if node_id and node_id in self.banned_node_ids and (now < self.banned_node_ids[node_id]):
            return True
        return False

    def _is_peer_connected(self, addr: str) -> bool:
        host, port = parse_ip_port(addr, config.P2P_PORT)
        for p in list(self.peers.values()):
            if p.address == addr:
                return True
            ph, pp = parse_ip_port(p.address, config.P2P_PORT)
            if pp == port:
                if ph == host:
                    return True
                if host in ('101.127.80.48', config.GENESIS_NODE_HOST) and ph in ('101.127.80.48', config.GENESIS_NODE_HOST):
                    return True
            if ph == host and int(p.p2p_port or 0) == int(port):
                return True
        return False

    async def _is_self_endpoint(self, host: str, port: int) -> bool:
        import socket as _sock
        learned = self.__dict__.setdefault('_self_endpoints', set())
        if (str(host), int(port)) in learned:
            return True
        if int(port) != int(config.P2P_PORT):
            return False
        local = {'127.0.0.1', '::1', '0.0.0.0', '::'}
        if config.EXTERNAL_IP:
            local.add(str(config.EXTERNAL_IP))
        if getattr(self, 'public_ip', None):
            local.add(str(self.public_ip))
        try:
            for _info in _sock.getaddrinfo(_sock.gethostname(), None):
                local.add(_info[4][0])
        except OSError:
            pass
        try:
            _loop = bootstrap.asyncio.get_running_loop()
            _infos = await _loop.getaddrinfo(str(host), int(port))
            _ips = {_i[4][0] for _i in _infos}
        except (OSError, ValueError):
            _ips = set()
        return bool(_ips & local)

    async def _connect_to_peer(self, addr: str):
        if '101.127.80.48' in addr:
            addr = addr.replace('101.127.80.48', config.GENESIS_NODE_HOST)
        if self._is_peer_connected(addr) or self._is_banned(address=addr):
            return
        try:
            if bootstrap.time.time() < float(self._dial_backoff.get(addr, 0.0)):
                return
        except (TypeError, ValueError, AttributeError):
            pass
        h, p = parse_ip_port(addr, config.P2P_PORT)
        if await self._is_self_endpoint(h, p):
            bootstrap.logger.debug(f'[P2P] Skipping {addr}: it is this node')
            self._dial_backoff[addr] = bootstrap.time.time() + 86400.0
            return
        if h == '101.127.80.48':
            h = config.GENESIS_NODE_HOST
        _ssrf_ok, _ssrf_why, _ssrf_ip = await _ssrf_allows_dial(h, p, self._local_ips, self.public_ip, allow_private=bool(getattr(self, 'allow_private_peers', False)))
        if not _ssrf_ok:
            bootstrap.logger.info(f'[P2P] R4-ssrf-filter: refusing dial {addr}: {_ssrf_why}')
            return
        if (h in self._local_ips or (self.public_ip and h == self.public_ip)) and p == config.P2P_PORT:
            bootstrap.logger.debug(f'[P2P] SELF-DIAL-1: refusing own endpoint {addr}')
            return
        bootstrap.logger.info(f'[P2P] Attempting connection to {addr}')
        try:
            async with self._lock:
                for existing_peer in self.peers.values():
                    eh, ep = parse_ip_port(existing_peer.address, config.P2P_PORT)
                    if (h == eh or addr == existing_peer.address) and (p == ep or p == int(existing_peer.p2p_port or 0)):
                        return
            reader, writer = (None, None)
            async with self._dial_sem:
                reader, writer = await bootstrap.asyncio.wait_for(bootstrap.asyncio.open_connection(_ssrf_ip, p), timeout=5.0)
                sock = writer.get_extra_info('socket')
                if sock:
                    try:
                        sock.setsockopt(bootstrap.socket.IPPROTO_TCP, bootstrap.socket.TCP_NODELAY, 1)
                        sock.setsockopt(bootstrap.socket.SOL_SOCKET, bootstrap.socket.SO_KEEPALIVE, 1)
                    except Exception:
                        pass
                is_bootstrap = any((addr == b for b in self.bootstrap_nodes)) or any((h == parse_ip_port(b, config.P2P_PORT)[0] for b in self.dns_seeds)) or h == self.genesis_node
                peer = await bootstrap.asyncio.wait_for(perform_handshake(reader, writer, self.node.node_id, self.node.height, config.VERSION, self.node.priv, self.node.pub, allow_genesis_learn=self.node.height == 0), timeout=10.0)
            if peer is None:
                writer.close()
                await writer.wait_closed()
                self._dial_note_result(addr, False)
                return
            if peer.node_id == self.node.node_id:
                bootstrap.logger.debug(f'[P2P] Rejecting self-connection to {addr}')
                self.__dict__.setdefault('_self_endpoints', set()).add((str(h), int(p)))
                self._dial_backoff[addr] = bootstrap.time.time() + 86400.0
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            if self._is_banned(node_id=peer.node_id):
                bootstrap.logger.info(f'[P2P] Rejecting outbound peer {addr}: node_id {peer.node_id[:16]} is banned')
                writer.close()
                await writer.wait_closed()
                return
            async with self._lock:
                existing = [p for p in self.peers.values() if p.node_id == peer.node_id]
                if existing:
                    _lb = h in ('127.0.0.1', 'localhost', '::1')
                    if _dial_dup_action(self.node.node_id, peer.node_id, 'out', _lb, True) != 'replace_existing':
                        bootstrap.logger.debug(f'[P2P] Already connected to node {peer.node_id[:16]}, closing outbound duplicate')
                        writer.close()
                        await writer.wait_closed()
                        return
                    bootstrap.logger.debug(f'[P2P] DIAL-KEEPER-1 replacing duplicate socket to node {peer.node_id[:16]} with outbound keeper')
                    for _old in existing:
                        try:
                            if _old.writer is not None:
                                _old.writer.close()
                        except Exception:
                            pass
                        if self.peers.get(_old.address) is _old:
                            del self.peers[_old.address]
                peer_ip = h
                ip_conns = self._conn_per_ip.get(peer_ip, 0)
                is_bootstrap = any((peer_ip in b for b in self.bootstrap_nodes)) or peer_ip == self.genesis_node
                if not is_bootstrap and ip_conns >= self._max_conn_per_ip:
                    bootstrap.logger.info(f'[P2P] Rejecting outbound peer {addr}: per-IP cap ({ip_conns}/{self._max_conn_per_ip})')
                    writer.close()
                    await writer.wait_closed()
                    return
                if not self._track_peer_subnet(peer):
                    bootstrap.logger.info(f'[P2P] Rejecting outbound peer {addr}: subnet diversity cap reached')
                    writer.close()
                    await writer.wait_closed()
                    return
                self._conn_per_ip[peer_ip] = ip_conns + 1
                if len(self.peers) >= self.max_peers:
                    oldest = min(self.peers.values(), key=lambda p: p.last_seen)
                    try:
                        if oldest.writer is not None:
                            oldest.writer.close()
                    except Exception as _ev_e:
                        bootstrap.logger.debug(f'[P2P] evict close failed for {oldest.address}: {_ev_e}')
                    del self.peers[oldest.address]
                self.peers[peer.address] = peer
                self._metrics['connections'] += 1
                self._metrics['peers_discovered'] += 1
                self._dial_note_result(addr, True)
            self._track_task(bootstrap.asyncio.create_task(self._send_message(peer, config.MSG_GET_STATUS, b'{}')))
            self.tip_push(peer)
            self._track_task(bootstrap.asyncio.create_task(self._peer_loop(peer)))
            bootstrap.logger.info(f'[P2P] Connected to peer: {peer.address} (node {peer.node_id[:16]})')
        except Exception as e:
            _wait = self._dial_note_result(addr, False)
            self._dial_log_failure(addr, f'[P2P] Failed to connect to {addr}: {type(e).__name__}: {e} (retry in {_wait:.0f}s)')

    def _dial_note_result(self, addr: str, ok: bool) -> float:
        now = bootstrap.time.time()
        try:
            if ok:
                self._dial_fails.pop(addr, None)
                self._dial_backoff.pop(addr, None)
                return 0.0
            fails = int(self._dial_fails.get(addr, 0)) + 1
            self._dial_fails[addr] = fails
            wait = min(300.0, 5.0 * 2.0 ** min(fails - 1, 6)) + bootstrap.random.uniform(0, 2.0)
            self._dial_backoff[addr] = now + wait
            if len(self._dial_fails) > 5000:
                _oldest = next(iter(self._dial_fails))
                self._dial_fails.pop(_oldest, None)
                self._dial_backoff.pop(_oldest, None)
            return wait
        except Exception:
            return 0.0

    def _dial_log_failure(self, addr: str, msg: str) -> None:
        try:
            now = bootstrap.time.time()
            last = float(self._dial_last_log.get(addr, 0.0))
            if now - last > 60.0:
                self._dial_last_log[addr] = now
                if len(self._dial_last_log) > 5000:
                    self._dial_last_log.pop(next(iter(self._dial_last_log)), None)
                bootstrap.logger.info(msg)
            else:
                bootstrap.logger.debug(msg)
        except Exception:
            bootstrap.logger.debug(msg)

    def _fetch_registry_peers_sync(self):
        req = bootstrap.urllib.request.Request(self.registry_url, headers={'User-Agent': 'munex-node/11', 'Accept': 'application/json'})
        try:
            with bootstrap.urllib.request.urlopen(req, timeout=10) as res:
                if res.status != 200:
                    return []
                data = bootstrap.json.loads(res.read().decode('utf-8', 'replace'))
        except Exception as e:
            bootstrap.logger.debug(f'[REGISTRY] fetch failed: {e}')
            return []
        endpoints = []
        if isinstance(data, dict) and isinstance(data.get('nodes'), list):
            for n in data['nodes']:
                if not isinstance(n, dict):
                    continue
                p2p = n.get('p2p') or ''
                host, port = parse_ip_port(str(p2p), config.P2P_PORT)
                if not host:
                    continue
                try:
                    ip = bootstrap.ipaddress.ip_address(host)
                except ValueError:
                    continue
                if not self.allow_private_peers and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
                    continue
                endpoints.append(f'{host}:{port}' if ':' not in str(host) else f'[{host}]:{port}')
        return list(dict.fromkeys(endpoints))

    async def _fetch_registry_peers(self):
        if not self.registry_enabled or not self.registry_url:
            return []
        now = bootstrap.time.time()
        if now - self._registry_last_fetch < self.registry_interval:
            return list(self._registry_cached_peers)
        self._registry_last_fetch = now
        try:
            loop = bootstrap.asyncio.get_running_loop()
            peers = await loop.run_in_executor(None, self._fetch_registry_peers_sync)
        except Exception as e:
            bootstrap.logger.debug(f'[REGISTRY] fetch failed: {e}')
            return list(self._registry_cached_peers)
        self._registry_cached_peers = list(peers)
        return list(peers)

    async def _resolve_dns_seeds(self) -> bootstrap.List[str]:
        loop = bootstrap.asyncio.get_running_loop()
        seeds = self.dns_seeds
        discovered_peers = []
        for seed in seeds:
            host, port = parse_ip_port(seed, config.GENESIS_NODE_P2P_PORT)
            try:
                addr_info = await loop.getaddrinfo(host, port, proto=bootstrap.socket.IPPROTO_TCP)
                for item in addr_info:
                    sockaddr = item[4]
                    ip = sockaddr[0]
                    if ip not in (self.public_ip, '127.0.0.1', '::1', '0.0.0.0', '::'):
                        endpoint = f'{host}:{port}' if host and (not host.replace('.', '').isdigit()) else f'[{ip}]:{port}' if ':' in str(ip) else f'{ip}:{port}'
                        if '101.127.80.48' in endpoint:
                            endpoint = endpoint.replace('101.127.80.48', config.GENESIS_NODE_HOST)
                        discovered_peers.append(endpoint)
            except Exception as e:
                bootstrap.logger.debug(f"[DNS] Failed to resolve DNS seed '{seed}': {e}")
        unique_peers = list(dict.fromkeys(discovered_peers))
        bootstrap.random.shuffle(unique_peers)
        if unique_peers:
            bootstrap.logger.info(f'[DNS] Resolved {len(unique_peers)} peer endpoints from {len(seeds)} DNS seeds')
        return unique_peers

    async def _dht_loop(self):
        if not DHT_AVAILABLE:
            return
        try:
            self._dht_server = Server(storage=ForgetfulStorage())
            dht_listen_port = getattr(self, 'dht_port', config.DHT_PORT)
            await self._dht_server.listen(dht_listen_port)
            bootstrap.logger.info(f'[DHT] Server listening on port {dht_listen_port}')
            dht_seeds = getattr(self, 'dht_bootstrap_nodes', config.DHT_BOOTSTRAP_NODES)
            dht_bootstrap_ok = 0
            for ip, port in dht_seeds:
                try:
                    await self._dht_server.bootstrap([(ip, port)])
                    dht_bootstrap_ok += 1
                    bootstrap.logger.info(f'[DHT] Bootstrapped from {ip}:{port} ({dht_bootstrap_ok}/{len(dht_seeds)})')
                except Exception as e:
                    bootstrap.logger.debug(f'[DHT] Bootstrap to {ip}:{port} failed: {e}')
            if dht_bootstrap_ok == 0:
                bootstrap.logger.warning(f'[DHT] All {len(dht_seeds)} bootstrap attempts failed; will retry next cycle')
            my_shard_base = int(bootstrap.hashlib.sha256(self.node.node_id.encode()).hexdigest(), 16) % config.DHT_SHARD_COUNT
            dht_cycle = 0
            while not self._discovery_stop.is_set():
                if not self.public_ip:
                    await bootstrap.asyncio.sleep(30)
                    continue
                p2p_addr = f'{self.public_ip}:{config.P2P_PORT}'
                my_shard = (my_shard_base + dht_cycle) % config.DHT_SHARD_COUNT
                dht_cycle += 1
                try:
                    shard_key = f'{config.DHT_PEERS_KEY_PREFIX}{my_shard}'.encode()
                    raw = await self._dht_server.get(shard_key)
                    entries = []
                    if raw:
                        try:
                            entries = bootstrap.json.loads(raw.decode())
                        except (bootstrap.json.JSONDecodeError, UnicodeDecodeError):
                            entries = []
                    now = bootstrap.time.time()
                    entries = [e for e in entries if isinstance(e, dict) and now - e.get('ts', 0) < config.DHT_ENTRY_TTL and (e.get('node_id') != self.node.node_id)]
                    entries.append({'addr': p2p_addr, 'node_id': self.node.node_id, 'ts': now})
                    entries = entries[-config.DHT_MAX_ENTRIES_PER_SHARD:]
                    await self._dht_server.set(shard_key, bootstrap.json.dumps(entries).encode())
                    if len(self.peers) == 0:
                        for ip, port in dht_seeds:
                            try:
                                await self._dht_server.bootstrap([(ip, port)])
                                bootstrap.logger.info(f'[DHT] Re-bootstrapped from {ip}:{port}')
                                break
                            except Exception:
                                continue
                    for shard_i in range(config.DHT_SHARD_COUNT):
                        try:
                            raw_s = await self._dht_server.get(f'{config.DHT_PEERS_KEY_PREFIX}{shard_i}'.encode())
                        except Exception:
                            continue
                        if not raw_s:
                            continue
                        try:
                            shard_entries = bootstrap.json.loads(raw_s.decode())
                        except (bootstrap.json.JSONDecodeError, UnicodeDecodeError):
                            continue
                        for e in shard_entries:
                            if not isinstance(e, dict):
                                continue
                            addr = e.get('addr')
                            node_id = e.get('node_id')
                            if not addr or addr == p2p_addr:
                                continue
                            if now - e.get('ts', 0) >= config.DHT_ENTRY_TTL:
                                continue
                            if addr in self.peers or self._is_banned(address=addr, node_id=node_id):
                                continue
                            self._track_task(bootstrap.asyncio.create_task(self._connect_to_peer(addr)))
                except Exception as e:
                    bootstrap.logger.debug(f'[DHT] Error: {e}')
                await bootstrap.asyncio.sleep(30)
        except Exception as e:
            bootstrap.logger.error(f'[DHT] DHT failed: {e}')

    async def _discovery_loop(self):
        while not self._discovery_stop.is_set():
            registry_peers = await self._fetch_registry_peers()
            for addr in registry_peers:
                if not self._is_peer_connected(addr) and (not self._is_banned(address=addr)):
                    await self._connect_to_peer(addr)
                    if len(self.peers) >= self.max_peers:
                        break
            dns_peers = await self._resolve_dns_seeds()
            for addr in dns_peers:
                if not self._is_peer_connected(addr) and (not self._is_banned(address=addr)):
                    await self._connect_to_peer(addr)
                    if len(self.peers) >= self.max_peers:
                        break
            for addr in self.bootstrap_nodes:
                if not self._is_peer_connected(addr) and (not self._is_banned(address=addr)):
                    await self._connect_to_peer(addr)
            cached = util.load_peers_from_cache()
            for addr in cached:
                if not self._is_peer_connected(addr) and (not self._is_banned(address=addr)):
                    await self._connect_to_peer(addr)
            if len(self.peers) < 3 and self.fallback_nodes:
                for addr in self.fallback_nodes:
                    if not self._is_peer_connected(addr) and (not self._is_banned(address=addr)):
                        await self._connect_to_peer(addr)
            async with self._lock:
                peers_copy = list(self.peers.values())
            for peer in peers_copy:
                try:
                    await self._send_message(peer, config.MSG_GET_PEERS, b'{}')
                except Exception:
                    pass
            if len(self.peers) == 0:
                await bootstrap.asyncio.sleep(5.0 + bootstrap.random.uniform(0.5, 2.0))
            else:
                interval = self.config_discovery_interval if hasattr(self, 'config_discovery_interval') else config.DISCOVERY_INTERVAL
                await bootstrap.asyncio.sleep(interval)

    async def _heartbeat_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(config.HEARTBEAT_INTERVAL)
            if self.node and self.node.node_id:
                try:
                    await self.node.node_repo.update_height(self.node.node_id, self.node.height)
                except Exception as error:
                    bootstrap.logger.debug(f'[P2P] Local node heartbeat failed: {error}')
            async with self._lock:
                peers_copy = list(self.peers.values())
            now = bootstrap.time.time()
            ping_payload = bootstrap.json.dumps({'height': self.node.height}).encode()
            for peer in peers_copy:
                if now - peer.last_seen > 90:
                    bootstrap.logger.info(f'[P2P] Peer {peer.address} timed out (no activity for >90s) - closing')
                    try:
                        peer.writer.close()
                    except Exception:
                        pass
                    async with self._lock:
                        if self.peers.get(peer.address) is peer:
                            del self.peers[peer.address]
                    continue
                try:
                    await self._send_message(peer, config.MSG_PING, ping_payload)
                except Exception:
                    pass

    async def _request_checkpoints(self, peers: bootstrap.List[EncryptedPeer], timeout: float=5.0) -> bootstrap.Optional[bootstrap.Dict]:
        futures = {}
        for peer in peers:
            fut = bootstrap.asyncio.get_event_loop().create_future()
            self._pending_checkpoint_requests[peer.address] = fut
            futures[peer.address] = fut
            try:
                await self._send_message(peer, config.MSG_GET_CHECKPOINT, b'')
            except Exception:
                pass
        try:
            await bootstrap.asyncio.wait(futures.values(), timeout=timeout)
        finally:
            for addr in futures:
                self._pending_checkpoint_requests.pop(addr, None)
        responses = []
        for addr, fut in futures.items():
            if fut.done() and (not fut.cancelled()):
                try:
                    resp = fut.result()
                    if resp and resp.get('block_id', 0) > 0:
                        responses.append((resp['block_id'], resp.get('hash', '')))
                except Exception:
                    pass
        if not responses:
            return None
        if len(responses) == 1:
            bootstrap.logger.warning('[Sync] Only one peer answered a checkpoint request — using it, but quorum could not be established.')
            block_id, chash = responses[0]
            return {'block_id': block_id, 'hash': chash}
        tally = {}
        for r in responses:
            tally[r] = tally.get(r, 0) + 1
        best, count = max(tally.items(), key=lambda kv: kv[1])
        if count * 2 > len(responses):
            return {'block_id': best[0], 'hash': best[1]}
        bootstrap.logger.warning(f'[Sync] No majority agreement on latest checkpoint among {len(responses)} peers — falling back to single-peer sync.')
        return None

    async def _sync_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(config.SYNC_INTERVAL)
            if bootstrap.time.time() < getattr(self, '_sync_paused_until', 0.0):
                continue
            async with self._lock:
                peer_list = list(self.peers.values())
            if not peer_list:
                continue
            stuck_peer = getattr(self, '_stuck_peer', None)
            candidates = [p for p in peer_list if getattr(p, 'address', None) != stuck_peer] or peer_list
            best_peer = max(candidates, key=lambda p: p.height)
            best_height = best_peer.height
            if best_height == self.node.height:
                _fh_start = max(0, self.node.height - 51)
                _fh_payload = bootstrap.json.dumps({'start': _fh_start, 'end': self.node.height + 1}).encode()
                await self._send_message(best_peer, config.MSG_GET_BLOCKS, _fh_payload)
                continue
            if best_height < self.node.height:
                continue
            gap = best_height - self.node.height
            bootstrap.logger.info(f'[P2P] Syncing from {best_peer.address}: local={self.node.height}, remote={best_height}')
            if gap > config.CHECKPOINT_SYNC_THRESHOLD:
                sample_peers = sorted(peer_list, key=lambda p: -p.height)[:5]
                checkpoint = await self._request_checkpoints(sample_peers)
                if checkpoint:
                    bootstrap.logger.info(f'[Sync] Quorum-agreed checkpoint at block {checkpoint['block_id']} — anchoring catch-up sync on it')
            max_chunks_this_cycle = 25
            rewound_this_stall = False
            for _ in range(max_chunks_this_cycle):
                if self.node.height >= best_height:
                    break
                start = self.node.height
                end = min(best_height, start + 500)
                payload = bootstrap.json.dumps({'start': start, 'end': end}).encode()
                await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
                waited = 0.0
                while self.node.height <= start and waited < 8.0:
                    await bootstrap.asyncio.sleep(0.25)
                    waited += 0.25
                if self.node.height <= start and (not rewound_this_stall):
                    rewound_this_stall = True
                    rewind_start = max(0, start - 100)
                    bootstrap.logger.info(f'[Sync] No progress on [{start},{end}); rewinding fetch to [{rewind_start},{end}) to locate fork point')
                    payload = bootstrap.json.dumps({'start': rewind_start, 'end': end}).encode()
                    await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
                    waited = 0.0
                    while self.node.height <= start and waited < 30.0:
                        await bootstrap.asyncio.sleep(0.25)
                        waited += 0.25
                if self.node.height <= start:
                    bootstrap.logger.warning(f'[Sync] Stuck at height {self.node.height} — no progress importing [{start},{end}) from {best_peer.address}. Tip is likely below a rejected block. Check logs above for [Verify] rejections; the loop will rotate to another peer and auto-retry after a cooldown.')
                    self._stuck_cycles = getattr(self, '_stuck_cycles', 0) + 1
                    self._stuck_peer = best_peer.address
                    if self._stuck_cycles >= 3:
                        self._sync_paused_until = bootstrap.time.time() + config.SYNC_STUCK_TRIP_COOLDOWN
                        self.node._producing_enabled = False
                        bootstrap.logger.error(f'[Sync] Three consecutive stuck cycles — pausing GET_BLOCKS and block production for {config.SYNC_STUCK_TRIP_COOLDOWN}s (auto-retry with peer rotation; production re-enables once sync progress resumes). A restart also clears this state.')
                    break
                self._stuck_cycles = 0
                self._stuck_peer = None
                if not self.node._producing_enabled and (not self.node._shutdown_flag):
                    self._sync_paused_until = 0.0
                    self.node._producing_enabled = True
                    bootstrap.logger.info('[Sync] Progress resumed after stuck-cycle trip — re-enabling block production.')
                rewound_this_stall = False

    async def _cache_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(300)
            async with self._lock:
                peers = list(self.peers.keys())
            util.save_peers_to_cache(peers)

    def get_peer_count(self) -> int:
        return len(self.peers)

    def get_metrics(self) -> dict:
        return {'peers': len(self.peers), 'banned': len(self.banned_peers), 'messages_sent': self._metrics['messages_sent'], 'messages_received': self._metrics['messages_received'], 'bytes_sent': self._metrics['bytes_sent'], 'bytes_received': self._metrics['bytes_received'], 'connections': self._metrics['connections'], 'errors': self._metrics['errors']}

    async def sync_with_peers(self):
        if not self.peers:
            return
        best_peer = max(self.peers.values(), key=lambda p: p.height)
        latest = await self.node.block_repo.get_latest()
        if latest is None:
            batch_end = min(best_peer.height, 500)
            bootstrap.logger.info(f'[SYNC] Requesting genesis/initial blocks from {best_peer.address} (0 -> {batch_end} of {best_peer.height})')
            payload = bootstrap.json.dumps({'start': 0, 'end': batch_end}).encode()
            await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
            await bootstrap.asyncio.sleep(2)
            return
        if best_peer.height <= self.node.height:
            return
        batch_end = min(best_peer.height, self.node.height + 500)
        bootstrap.logger.info(f'[SYNC] Starting sync from {best_peer.address} (height {self.node.height} -> {batch_end} of {best_peer.height})')
        payload = bootstrap.json.dumps({'start': self.node.height, 'end': batch_end}).encode()
        await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
        await bootstrap.asyncio.sleep(2)
