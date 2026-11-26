import bootstrap
import config
import crypto
import util
import maze
import svf_keys
import svf
import genesis
import db
import db as _db
import repos
import tunnel
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
    transport: str = 'tcp'
    p2p_ws: str = ''
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

class _WSByteReader:

    def __init__(self):
        self._buf = bytearray()
        self._need = bootstrap.asyncio.Event()
        self._closed = False

    def feed(self, data: bytes):
        if data:
            self._buf += data
            self._need.set()

    def set_closed(self):
        self._closed = True
        self._need.set()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buf) < n:
            if self._closed:
                raise bootstrap.asyncio.IncompleteReadError(partial=bytes(self._buf), expected=n)
            self._need.clear()
            if len(self._buf) >= n or self._closed:
                continue
            await self._need.wait()
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

class _WSByteWriter:

    def __init__(self, send_bytes, close_ws, peername):
        self._send_bytes = send_bytes
        self._close_ws = close_ws
        self._peername = peername
        self._buf = bytearray()
        self._closed = False
        self._close_task = None
        self._close_event = bootstrap.asyncio.Event()

    def write(self, data: bytes):
        if not self._closed:
            self._buf += data

    async def drain(self):
        if self._buf:
            chunk = bytes(self._buf)
            self._buf.clear()
            await self._send_bytes(chunk)

    def get_extra_info(self, name):
        if name == 'peername':
            return self._peername
        return None

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            loop = bootstrap.asyncio.get_running_loop()
        except RuntimeError:
            self._close_event.set()
            return

        async def _do_close():
            try:
                r = self._close_ws()
                if bootstrap.asyncio.iscoroutine(r):
                    await r
            except Exception:
                pass
            finally:
                self._close_event.set()
        self._close_task = loop.create_task(_do_close())

    async def wait_closed(self):
        if not self._closed:
            return
        if self._close_task is not None:
            try:
                await bootstrap.asyncio.wait_for(bootstrap.asyncio.shield(self._close_task), timeout=5)
            except Exception:
                pass
        try:
            await bootstrap.asyncio.wait_for(self._close_event.wait(), timeout=5)
        except Exception:
            pass

def _p2p_ws_from_ws_url(ws_url):
    try:
        text = str(ws_url or '').strip()
        if not text:
            return ''
        u = bootstrap.urlparse(text)
        if not u.scheme:
            u = bootstrap.urlparse('ws://' + text)
        scheme = {'http': 'ws', 'https': 'wss'}.get(u.scheme, u.scheme) or 'ws'
        host = u.hostname or ''
        if not host:
            return ''
        port = u.port
        default = 443 if scheme == 'wss' else 80
        if port and port != default:
            netloc = f'[{host}]:{port}' if ':' in host else f'{host}:{port}'
        elif ':' in host:
            netloc = f'[{host}]'
        else:
            netloc = host
        return f'{scheme}://{netloc}/p2p'
    except Exception:
        return ''

def _ws_client_close(ws, session):

    async def _close():
        try:
            await ws.close()
        except Exception:
            pass
        try:
            await session.close()
        except Exception:
            pass
    return _close

async def _pump_ws_into_reader(ws, reader):
    from aiohttp import WSMsgType as _WMT
    try:
        async for _msg in ws:
            if _msg.type == _WMT.BINARY:
                reader.feed(_msg.data)
            elif _msg.type in (_WMT.CLOSE, _WMT.CLOSED, _WMT.ERROR):
                break
    except Exception:
        pass
    finally:
        reader.set_closed()

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
        self._pending_snapshot_requests: bootstrap.Dict[str, bootstrap.asyncio.Future] = {}
        self._pending_snapshot_history: bootstrap.Dict[str, bootstrap.Tuple[int, int, bootstrap.asyncio.Future]] = {}
        self._pending_tip_requests: bootstrap.Dict[str, bootstrap.asyncio.Future] = {}
        self._snapshot_cache = None
        self._snapshot_last_attempt = 0.0
        self._snapshot_sync_running = False
        self._snapshot_consec_failures = 0
        self._lock = bootstrap.asyncio.Lock()
        self._server = None
        self._dht_server = None
        self._dht_task = None
        self._discovery_stop = bootstrap.asyncio.Event()
        self._metrics = {'messages_sent': 0, 'messages_received': 0, 'bytes_sent': 0, 'bytes_received': 0, 'connections': 0, 'errors': 0, 'peers_discovered': 0}
        self.peer_scores: bootstrap.Dict[str, bootstrap.Dict] = {}
        self.reputation_weights = {'valid_block': 2, 'valid_tx': 1, 'valid_peer_list': 1, 'ping_response': 1, 'invalid_message': -2, 'decrypt_failed': -5, 'oversized_message': -10, 'protocol_violation': -2, 'invalid_block': -2, 'invalid_tx': -15}
        self.score_decay_interval = 3600
        self.max_positive_score = 100
        self.min_score_for_ban = -config.BAN_THRESHOLD
        self.rate_limits = {config.MSG_PING: (30, 60), config.MSG_GET_PEERS: (10, 60), config.MSG_GET_BLOCKS: (60, 60), config.MSG_GET_STATUS: (60, 60), config.MSG_GET_CHECKPOINT: (10, 60), config.MSG_GET_SNAPSHOT: (5, 60), config.MSG_NEW_BLOCK: (100, 60), config.MSG_NEW_TX: (200, 60), config.MSG_NEW_MOVE: (1200, 60)}
        self.peer_message_counts: bootstrap.Dict[str, bootstrap.Dict[int, bootstrap.List[float]]] = {}
        self._seen_block_hashes: bootstrap.OrderedDict = bootstrap.OrderedDict()
        self._seen_tx_hashes: bootstrap.OrderedDict = bootstrap.OrderedDict()
        self._seen_max = 8192
        self._rejected_block_hashes: bootstrap.Dict[str, float] = {}
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
        self._bootstrap_ips = set()
        for _b in list(self.bootstrap_nodes) + [self.genesis_node]:
            try:
                _bh, _ = parse_ip_port(str(_b), config.P2P_PORT)
            except Exception:
                continue
            self._bootstrap_ips.add(_bh)
            try:
                for _fam, _typ, _proto, _canon, _sa in bootstrap.socket.getaddrinfo(_bh, None):
                    if _sa and _sa[0]:
                        self._bootstrap_ips.add(str(_sa[0]))
            except Exception:
                pass
        self.registry_url = str(p2p_cfg.get('registry_url', config.REGISTRY_URL_DEFAULT)).strip()
        self.registry_enabled = config._strict_bool('p2p.registry_enabled', p2p_cfg.get('registry_enabled', True))
        self.registry_interval = max(60, int(p2p_cfg.get('registry_interval', 300) or 300))
        self._registry_last_fetch = 0.0
        self._registry_cached_peers = []
        self._registry_tunnel_peers = []
        self._tunnel_host = self._resolve_tunnel_host(p2p_cfg)
        self._tunnel_last_register = 0.0
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
            bootstrap.logger.info(f'[P2P] Rejecting inbound peer {addr_str}: too many pending handshakes ({pending}/{self._max_pending_handshakes})')
            writer.close()
            await writer.wait_closed()
            return
        now_ts = bootstrap.time.time()
        hs_timestamps = self._handshake_rate_limiter.setdefault(ip_only, [])
        hs_timestamps[:] = [t for t in hs_timestamps if now_ts - t < 60]
        if len(hs_timestamps) >= self._handshake_rate_limit[0]:
            bootstrap.logger.info(f'[P2P] Rejecting inbound peer {addr_str}: handshake rate limit ({len(hs_timestamps)}/{self._handshake_rate_limit[0]} per 60 s)')
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
            is_bootstrap = peer_ip in self._bootstrap_ips or peer_ip == self.genesis_node
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
                peer.last_seen = bootstrap.time.time()
                self._track_task(bootstrap.asyncio.create_task(self._process_message_safe(peer, msg_type, data)))
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
            return self.node.height + 101
        return max(0, claimed)

    async def _process_message_safe(self, peer: EncryptedPeer, msg_type: int, data: bytes):
        try:
            await self._process_message(peer, msg_type, data)
        except Exception as _e:
            bootstrap.logger.error(f'[P2P] _process_message failed for {peer.address}: {_e}', exc_info=True)

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
                    tunnel_list = []
                    for p in self.peers.values():
                        if getattr(p, 'transport', 'tcp') == 'ws':
                            if getattr(p, 'p2p_ws', ''):
                                tunnel_list.append({'host': parse_ip_port(p.address)[0], 'p2p_ws': p.p2p_ws, 'height': int(getattr(p, 'height', 0) or 0)})
                            continue
                        h = parse_ip_port(p.address)[0]
                        peers_list.append(f'[{h}]:{p.p2p_port}' if ':' in str(h) else f'{h}:{p.p2p_port}')
                    for _tp in list(self._registry_tunnel_peers):
                        _pw = str(_tp.get('p2p_ws') or '')
                        if _pw and all((_pw != str(_t.get('p2p_ws') or '') for _t in tunnel_list)):
                            tunnel_list.append({'host': str(_tp.get('host') or ''), 'ws_url': str(_tp.get('ws_url') or ''), 'p2p_ws': _pw, 'height': _tp.get('height')})
                payload = bootstrap.json.dumps({'peers': peers_list[:100], 'tunnel_peers': tunnel_list[:100]}).encode()
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
                    for _tp in data_json.get('tunnel_peers', []) or []:
                        if not isinstance(_tp, dict):
                            continue
                        _pw = str(_tp.get('p2p_ws') or '')
                        if not _pw:
                            _wu = str(_tp.get('ws_url') or '')
                            _pw = _p2p_ws_from_ws_url(_wu) if _wu else ''
                        if not _pw or _pw in _seen_eps:
                            continue
                        _seen_eps.add(_pw)
                        if _spawned >= 32:
                            break
                        _spawned += 1
                        self._track_task(bootstrap.asyncio.create_task(self._connect_to_peer_ws(_pw)))
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_PEERS error from {peer.address}: {e}')
            elif msg_type == config.MSG_GET_BLOCKS:
                try:
                    req = bootstrap.json.loads(data.decode())
                    start = req.get('start', 0)
                    end = req.get('end', self.node.height)
                    if end - start + 1 > config.SYNC_BATCH_BLOCKS:
                        end = start + config.SYNC_BATCH_BLOCKS - 1
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
                    hist_entry = self._pending_snapshot_history.get(peer.address)
                    hist_fut = None
                    if hist_entry is not None:
                        hist_start, hist_end, hist_fut = hist_entry
                        if hist_fut.done():
                            hist_fut = None
                        elif not blocks:
                            hist_fut = None
                        else:
                            try:
                                _ids = [int(b['id']) for b in blocks if isinstance(b, dict) and 'id' in b]
                            except Exception:
                                _ids = []
                            if not _ids or min(_ids) < hist_start or max(_ids) > hist_end:
                                hist_fut = None
                    _r35_ids = [int(b.get('id', -1)) for b in blocks if isinstance(b, dict)]
                    bootstrap.logger.info(f'[R35] MSG_BLOCKS from {peer.address}: {len(blocks)} blocks ids={_r35_ids} received; importing')
                    if hist_fut is not None:
                        hist_fut.set_result(blocks)
                    else:
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
                    _bh = str(block_data.get('hash', ''))
                    _rej_until = self._rejected_block_hashes.get(_bh, 0.0)
                    if _rej_until and bootstrap.time.time() < _rej_until:
                        return
                    bootstrap.logger.info(f'[R35] MSG_NEW_BLOCK from {peer.address}: block {block_data.get('id')} hash={str(block_data.get('hash', ''))[:16]} received')
                    _status = await self.node.receive_block(block_data)
                    if _status == 'ok':
                        self._update_reputation(peer, 'valid_block')
                    if _status == 'rejected':
                        self._update_reputation(peer, 'invalid_block')
                        self._rejected_block_hashes[str(block_data.get('hash', ''))] = bootstrap.time.time() + 60.0
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
                    fut = self._pending_tip_requests.get(peer.address)
                    if fut and (not fut.done()):
                        fut.set_result({'height': new_h, 'last_hash': status.get('last_hash', ''), 'version': peer.version})
                    if peer.height > self.node.height:
                        bootstrap.asyncio.create_task(self.sync_with_peers())
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] Error handling MSG_STATUS from {peer.address}: {e}')
            elif msg_type == config.MSG_GET_SNAPSHOT:
                try:
                    latest = await self.node.block_repo.get_latest()
                    if latest is None:
                        bootstrap.logger.warning('[Sync] Snapshot requested but this node has no blocks yet')
                    else:
                        tip_id = int(latest['id'])
                        tip_hash = str(latest.get('hash', ''))
                        payload = None
                        if self._snapshot_cache and self._snapshot_cache[0] == tip_id and (self._snapshot_cache[1] == tip_hash):
                            payload = self._snapshot_cache[2]
                            bootstrap.logger.debug(f'[Sync] Serving cached snapshot at height {tip_id}')
                        if payload is None:
                            async with await self.node.db.transaction():
                                latest2 = await self.node.block_repo.get_latest()
                                if latest2 is None:
                                    raise RuntimeError('no tip block')
                                tip2 = int(latest2['id'])
                                snapshot = None
                                _sealed = getattr(self.node, '_sealed_snapshot', None)
                                if isinstance(_sealed, dict) and int(_sealed.get('height', -1)) == tip2 and (str(_sealed.get('state_root', '')) == str(latest2.get('state_root', ''))):
                                    snapshot = _sealed.get('snapshot')
                                if snapshot is None:
                                    try:
                                        _row = await self.node.db.fetchrow('SELECT state_root, snapshot_data FROM state_snapshots WHERE block_id = ?' if self.node.db.db_type == 'sqlite' else 'SELECT state_root, snapshot_data FROM state_snapshots WHERE block_id = $1', tip2)
                                    except Exception:
                                        _row = None
                                    if _row is not None and str(_row.get('state_root', '')) == str(latest2.get('state_root', '')):
                                        try:
                                            snapshot = bootstrap.json.loads(_row.get('snapshot_data') or '{}')
                                        except Exception:
                                            snapshot = None
                                root = db._state_root_from_snapshot(snapshot) if snapshot is not None else ''
                                if snapshot is None:
                                    bootstrap.logger.warning(f'[Sync] Snapshot at height {tip2}: no cached seal-time snapshot for the tip — refusing to serve')
                                elif root != str(latest2.get('state_root', '')):
                                    bootstrap.logger.warning(f'[Sync] Snapshot at height {tip2}: cached root {root[:16]}... != tip state_root {str(latest2.get('state_root', ''))[:16]}... — refusing to serve')
                                else:
                                    genesis_row = await self.node.block_repo.get_by_id(0)
                                    genesis_hash = genesis_row['hash'] if genesis_row else getattr(self.node, 'genesis_hash', '') or genesis._node_genesis_hash or ''
                                    resp = {'height': tip2, 'genesis_hash': genesis_hash, 'state_root': root, 'snapshot': snapshot, 'tip_block': latest2}
                                    payload = bootstrap.json.dumps(resp).encode()
                                    if len(payload) >= 4000000:
                                        bootstrap.logger.warning(f'[Sync] Snapshot at height {tip2} is {len(payload)} bytes — over the 4MB P2P limit, refusing to send')
                                        payload = None
                                    else:
                                        self._snapshot_cache = (tip2, str(latest2.get('hash', '')), payload)
                                        bootstrap.logger.info(f'[Sync] Served seal-time snapshot at height {tip2}: {len(payload)} bytes, state_root={root[:16]}...')
                        if payload is not None:
                            await self._send_message(peer, config.MSG_SNAPSHOT, payload)
                except Exception as e:
                    bootstrap.logger.warning(f'[Sync] Snapshot build failed for {peer.address}: {e}')
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
            elif msg_type == config.MSG_SNAPSHOT:
                try:
                    resp = bootstrap.json.loads(data.decode())
                    fut = self._pending_snapshot_requests.get(peer.address)
                    if fut and (not fut.done()):
                        fut.set_result(resp)
                except Exception as e:
                    bootstrap.logger.debug(f'[P2P] MSG_SNAPSHOT error from {peer.address}: {e}')
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
        if msg_type in (config.MSG_BLOCKS, config.MSG_NEW_BLOCK, config.MSG_CHECKPOINT, config.MSG_GET_CHECKPOINT, config.MSG_SNAPSHOT):
            return 0
        if msg_type in (config.MSG_PING, config.MSG_PONG, config.MSG_STATUS, config.MSG_GET_STATUS, config.MSG_GET_SNAPSHOT):
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
                        await bootstrap.asyncio.wait_for(peer.writer.drain(), timeout=10)
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
            bootstrap.logger.debug(f'[P2P] Rate limit exceeded: {addr} msg_type={msg_type}')
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
                if 'tunnel_peers' in payload:
                    if not isinstance(payload['tunnel_peers'], list) or len(payload['tunnel_peers']) > 128:
                        return False
                    for _tp in payload['tunnel_peers']:
                        if not isinstance(_tp, dict):
                            return False
                        _pw = str(_tp.get('p2p_ws') or _tp.get('ws_url') or '')
                        if not _pw or len(_pw) > 512:
                            return False
                        if 'height' in _tp and _tp.get('height') is not None and (not isinstance(_tp.get('height'), int)):
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
            await self.broadcast_block(block_data, force=False)
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
        if h == config.GENESIS_NODE_HOST or h in self._bootstrap_ips:
            now_ts = bootstrap.time.time()
            last_log = self._bootstrap_cooldown_log_ts.get(address, 0.0)
            if now_ts - last_log >= 60.0:
                self._bootstrap_cooldown_log_ts[address] = now_ts
                bootstrap.logger.warning(f'[P2P] Disconnecting bootstrap peer {address}: {reason} (cooldown only, not banning)')
            if address in self.peers:
                del self.peers[address]
            self.banned_peers[address] = bootstrap.time.time() + 15.0
            return
        _now = bootstrap.time.time()
        _already = address in self.banned_peers and _now < self.banned_peers[address]
        if not _already:
            self.banned_peers[address] = _now + self.ban_duration
        if node_id:
            _nid_already = node_id in self.banned_node_ids and _now < self.banned_node_ids[node_id]
            if not _nid_already:
                self.banned_node_ids[node_id] = _now + self.ban_duration
        _peer = self.peers.get(address)
        if _peer is not None:
            _peer.banned = True
            try:
                if _peer.writer is not None:
                    _peer.writer.close()
            except Exception:
                pass
        if address in self.peers:
            del self.peers[address]
        if not _already:
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
        if address:
            _h, _ = parse_ip_port(address)
            for _banned_addr, _exp in list(self.banned_peers.items()):
                if now < _exp:
                    _bh, _ = parse_ip_port(_banned_addr)
                    if _bh == _h:
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
                is_bootstrap = h in self._bootstrap_ips or h == self.genesis_node
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
                is_bootstrap = peer_ip in self._bootstrap_ips or peer_ip == self.genesis_node
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

    def _resolve_tunnel_host(self, p2p_cfg) -> str:
        try:
            for _src in (p2p_cfg.get('tunnel_host', ''), (getattr(self.node, 'config', {}) or {}).get('node', {}).get('tunnel_host', ''), bootstrap.os.environ.get('MCX_TUNNEL_HOST', '')):
                if _src and str(_src).strip():
                    return str(_src).strip().lower()
        except Exception:
            pass
        try:
            with open(bootstrap.os.path.join(bootstrap.os.getcwd(), 'munex_tunnel.json'), 'r', encoding='utf-8') as _fh:
                _st = bootstrap.json.load(_fh)
            if isinstance(_st, dict):
                for _key in ('hosts', 'hostnames'):
                    _m = _st.get(_key)
                    if isinstance(_m, dict) and str(_m.get('8080') or '').strip():
                        return str(_m.get('8080')).strip().lower()
        except Exception:
            pass
        return ''

    async def _ws_dial_allowed(self, host: str):
        try:
            bootstrap.ipaddress.ip_address(host)
            _ips = [host]
        except ValueError:
            try:
                loop = bootstrap.asyncio.get_running_loop()
                _res = await loop.run_in_executor(None, bootstrap.socket.gethostbyname_ex, host)
                _ips = list(_res[2]) if isinstance(_res, tuple) else list(_res)
            except Exception:
                return (False, f'unresolvable host {host}')
            if not _ips:
                return (False, f'unresolvable host {host}')
        for _ip in _ips:
            if _ssrf_ip_blocked(_ip):
                if self.allow_private_peers and _lan_dialable(_ip):
                    return (True, 'private-lan')
                continue
            return (True, 'public')
        return (False, f'no dialable address for {host}')

    def _is_ws_peer_connected(self, ws_url: str) -> bool:
        for p in list(self.peers.values()):
            if getattr(p, 'transport', 'tcp') == 'ws' and getattr(p, 'p2p_ws', '') == ws_url:
                return True
        return False

    async def _register_ws_peer(self, peer: EncryptedPeer, direction: str) -> bool:
        if peer.node_id == self.node.node_id:
            bootstrap.logger.debug(f'[P2P-WS] Rejecting self-connection via WS {peer.p2p_ws}')
            self._dial_backoff[peer.p2p_ws] = bootstrap.time.time() + 86400.0
            return False
        if self._is_banned(node_id=peer.node_id) or self._is_banned(address=peer.address):
            bootstrap.logger.info(f'[P2P-WS] Rejecting WS peer {peer.address}: banned')
            return False
        async with self._lock:
            existing = [p for p in self.peers.values() if p.node_id == peer.node_id]
            if existing:
                _lb = parse_ip_port(peer.address, config.P2P_PORT)[0] in ('127.0.0.1', 'localhost', '::1')
                if _dial_dup_action(self.node.node_id, peer.node_id, direction, _lb, True) != 'replace_existing':
                    bootstrap.logger.debug(f'[P2P-WS] Already connected to node {peer.node_id[:16]}, closing WS duplicate')
                    return False
                bootstrap.logger.debug(f'[P2P-WS] DIAL-KEEPER-1 replacing duplicate socket to node {peer.node_id[:16]} with WS keeper')
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
            is_bootstrap = peer_ip in self._bootstrap_ips or peer_ip == self.genesis_node
            if not is_bootstrap and ip_conns >= self._max_conn_per_ip:
                bootstrap.logger.info(f'[P2P-WS] Rejecting WS peer {peer.address}: per-IP cap ({ip_conns}/{self._max_conn_per_ip})')
                return False
            if not self._track_peer_subnet(peer):
                bootstrap.logger.info(f'[P2P-WS] Rejecting WS peer {peer.address}: subnet diversity cap reached')
                return False
            self._conn_per_ip[peer_ip] = ip_conns + 1
            if len(self.peers) >= self.max_peers:
                oldest = min(self.peers.values(), key=lambda p: p.last_seen)
                try:
                    if oldest.writer is not None:
                        oldest.writer.close()
                except Exception as _ev_e:
                    bootstrap.logger.debug(f'[P2P-WS] evict close failed for {oldest.address}: {_ev_e}')
                del self.peers[oldest.address]
            self.peers[peer.address] = peer
            self._metrics['connections'] += 1
            self._metrics['peers_discovered'] += 1
            self._dial_note_result(peer.p2p_ws, True)
        self._track_task(bootstrap.asyncio.create_task(self._send_message(peer, config.MSG_GET_STATUS, b'{}')))
        self.tip_push(peer)
        self._track_task(bootstrap.asyncio.create_task(self._peer_loop(peer)))
        return True

    async def _connect_to_peer_ws(self, ws_url: str):
        ws_url = str(ws_url or '').strip()
        if not ws_url:
            return
        if '://' not in ws_url:
            ws_url = 'ws://' + ws_url.strip('/') + '/p2p'
        try:
            _u = bootstrap.urlparse(ws_url)
        except Exception:
            return
        if _u.scheme not in ('ws', 'wss'):
            bootstrap.logger.info(f'[P2P-WS] Refusing dial {ws_url}: scheme must be ws/wss')
            return
        if not _u.hostname:
            return
        if self._is_ws_peer_connected(ws_url):
            return
        try:
            if bootstrap.time.time() < float(self._dial_backoff.get(ws_url, 0.0)):
                return
        except (TypeError, ValueError, AttributeError):
            pass
        _host = _u.hostname
        _port = _u.port or (443 if _u.scheme == 'wss' else 80)
        _self_hit = False
        try:
            _own_ws = int(self.node.config.get('node', {}).get('ws_port', config.WS_PORT))
            if _port == _own_ws:
                _ips = bootstrap.socket.gethostbyname_ex(_host)[2]
                if set(_ips) & set(self._local_ips):
                    _self_hit = True
        except Exception:
            _self_hit = False
        if _self_hit:
            bootstrap.logger.debug(f'[P2P-WS] Skipping {ws_url}: it is this node')
            self._dial_backoff[ws_url] = bootstrap.time.time() + 86400.0
            return
        _ok, _why = await self._ws_dial_allowed(_host)
        if not _ok:
            bootstrap.logger.info(f'[P2P-WS] R4-ssrf-filter: refusing dial {ws_url}: {_why}')
            return
        bootstrap.logger.info(f'[P2P-WS] Attempting WS connection to {ws_url}')
        session = None
        ws = None
        try:
            async with self._dial_sem:
                session = bootstrap.aiohttp.ClientSession()
                try:
                    ws = await bootstrap.asyncio.wait_for(session.ws_connect(ws_url, heartbeat=30, timeout=bootstrap.aiohttp.ClientTimeout(total=10)), timeout=12.0)
                except Exception:
                    try:
                        await session.close()
                    except Exception:
                        pass
                    raise
                reader = _WSByteReader()
                writer = _WSByteWriter(ws.send_bytes, _ws_client_close(ws, session), (_host, _port))
                pump_task = self._track_task(bootstrap.asyncio.create_task(_pump_ws_into_reader(ws, reader)))
                try:
                    peer = await bootstrap.asyncio.wait_for(perform_handshake(reader, writer, self.node.node_id, self.node.height, config.VERSION, self.node.priv, self.node.pub, allow_genesis_learn=self.node.height == 0), timeout=10.0)
                except Exception:
                    peer = None
                if peer is None:
                    pump_task.cancel()
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                    self._dial_note_result(ws_url, False)
                    return
            peer.transport = 'ws'
            peer.p2p_ws = ws_url
            if not await self._register_ws_peer(peer, 'out'):
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return
            bootstrap.logger.info(f'[P2P-WS] Connected to peer: {peer.address} (node {peer.node_id[:16]}) via WS {ws_url}')
        except Exception as e:
            _wait = self._dial_note_result(ws_url, False)
            self._dial_log_failure(ws_url, f'[P2P-WS] Failed to connect to {ws_url}: {type(e).__name__}: {e} (retry in {_wait:.0f}s)')
            if ws is not None:
                try:
                    await ws.close()
                except Exception:
                    pass
            if session is not None:
                try:
                    await session.close()
                except Exception:
                    pass

    async def _dial_tunnel_peers(self):
        todo = []
        seen = set()
        for tp in list(self._registry_tunnel_peers):
            if not isinstance(tp, dict):
                continue
            url = str(tp.get('p2p_ws') or '')
            if not url:
                url = _p2p_ws_from_ws_url(str(tp.get('ws_url') or ''))
            if not url or url in seen:
                continue
            seen.add(url)
            if self._is_ws_peer_connected(url):
                continue
            try:
                if bootstrap.time.time() < float(self._dial_backoff.get(url, 0.0)):
                    continue
            except (TypeError, ValueError, AttributeError):
                pass
            todo.append(url)
        if todo:
            await bootstrap.asyncio.gather(*[self._connect_to_peer_ws(u) for u in todo], return_exceptions=True)

    async def _maybe_reregister_tunnel(self):
        host = getattr(self, '_tunnel_host', '')
        if not host:
            return
        now = bootstrap.time.time()
        if now - float(getattr(self, '_tunnel_last_register', 0.0)) < self.registry_interval:
            return
        self._tunnel_last_register = now
        try:
            loop = bootstrap.asyncio.get_running_loop()
            ok, status, body = await loop.run_in_executor(None, lambda: tunnel.tunnel_register_host(host, self.registry_url, height=int(self.node.height)))
        except Exception as e:
            bootstrap.logger.debug(f'[TUNNEL] re-register {host} failed: {e}')
            return
        if ok:
            bootstrap.logger.debug(f'[TUNNEL] re-registered {host} height={self.node.height} (status {status})')
        else:
            bootstrap.logger.info(f'[TUNNEL] re-register {host} failed (status {status}): {str(body)[:200]}')

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
        tunnel_peers = []
        if isinstance(data, dict) and isinstance(data.get('nodes'), list):
            for n in data['nodes']:
                if not isinstance(n, dict):
                    continue
                if n.get('tunnel'):
                    host = str(n.get('host') or '').strip().lower()
                    ws_url = str(n.get('ws_url') or '').strip()
                    p2p_ws = str(n.get('p2p_ws') or '').strip()
                    if not p2p_ws and ws_url:
                        p2p_ws = _p2p_ws_from_ws_url(ws_url)
                    try:
                        _h = int(n.get('height')) if n.get('height') is not None else None
                    except (TypeError, ValueError):
                        _h = None
                    if host:
                        tunnel_peers.append({'host': host, 'ws_url': ws_url, 'p2p_ws': p2p_ws, 'height': _h})
                        bootstrap.logger.info(f'[REGISTRY] tunnel peer {host} (WS P2P via {p2p_ws or 'ws_url /p2p fallback'})')
                    continue
                p2p = n.get('p2p') or ''
                host, port = parse_ip_port(str(p2p), config.P2P_PORT)
                if not host:
                    continue
                try:
                    ip = bootstrap.ipaddress.ip_address(host)
                except ValueError:
                    try:
                        resolved = bootstrap.socket.gethostbyname(host)
                    except Exception:
                        continue
                    try:
                        ip = bootstrap.ipaddress.ip_address(resolved)
                    except ValueError:
                        continue
                    host = resolved
                if not self.allow_private_peers and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast):
                    continue
                endpoints.append(f'{host}:{port}' if ':' not in str(host) else f'[{host}]:{port}')
        _seen = set()
        _deduped = []
        for _tp in tunnel_peers:
            if _tp['host'] not in _seen:
                _seen.add(_tp['host'])
                _deduped.append(_tp)
        return (list(dict.fromkeys(endpoints)), _deduped)

    async def _fetch_registry_peers(self):
        if not self.registry_enabled or not self.registry_url:
            return []
        now = bootstrap.time.time()
        if now - self._registry_last_fetch < self.registry_interval:
            return list(self._registry_cached_peers)
        self._registry_last_fetch = now
        try:
            loop = bootstrap.asyncio.get_running_loop()
            peers, tunnel_peers = await loop.run_in_executor(None, self._fetch_registry_peers_sync)
        except Exception as e:
            bootstrap.logger.debug(f'[REGISTRY] fetch failed: {e}')
            return list(self._registry_cached_peers)
        self._registry_cached_peers = list(peers)
        self._registry_tunnel_peers = list(tunnel_peers)
        bootstrap.logger.debug(f'[REGISTRY] tunnel peers: {[t.get('host', '') for t in tunnel_peers]}')
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

    async def _dial_addrs(self, addrs):
        _todo = []
        _seen = set()
        for _a in addrs:
            if _a and _a not in _seen:
                _seen.add(_a)
                if not self._is_peer_connected(_a) and (not self._is_banned(address=_a)):
                    _todo.append(_a)
        if _todo:
            await bootstrap.asyncio.gather(*[self._connect_to_peer(_a) for _a in _todo], return_exceptions=True)

    async def _discovery_loop(self):
        while not self._discovery_stop.is_set():
            registry_peers = await self._fetch_registry_peers()
            await self._dial_addrs(registry_peers)
            await self._dial_tunnel_peers()
            await self._maybe_reregister_tunnel()
            dns_peers = await self._resolve_dns_seeds()
            await self._dial_addrs(dns_peers)
            await self._dial_addrs(self.bootstrap_nodes)
            cached = util.load_peers_from_cache()
            await self._dial_addrs(cached)
            if len(self.peers) < 3 and self.fallback_nodes:
                await self._dial_addrs(self.fallback_nodes)
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

    async def _request_snapshot(self, peer: EncryptedPeer, timeout: float=maze.SNAPSHOT_REQUEST_TIMEOUT) -> bootstrap.Optional[bootstrap.Dict]:
        loop = bootstrap.asyncio.get_running_loop()
        fut = loop.create_future()
        self._pending_snapshot_requests[peer.address] = fut
        try:
            await self._send_message(peer, config.MSG_GET_SNAPSHOT, b'')
            await bootstrap.asyncio.wait({fut}, timeout=timeout)
        except Exception as e:
            bootstrap.logger.warning(f'[Sync] Snapshot request to {peer.address} failed: {e}')
            return None
        finally:
            self._pending_snapshot_requests.pop(peer.address, None)
        if fut.done() and (not fut.cancelled()) and (not fut.exception()):
            return fut.result()
        bootstrap.logger.warning(f'[Sync] Snapshot request to {peer.address} timed out after {timeout}s')
        return None

    async def _request_tip_quorum(self, peers: bootstrap.List[EncryptedPeer], timeout: float=5.0) -> bootstrap.Optional[bootstrap.Dict]:
        if not peers:
            return None
        loop = bootstrap.asyncio.get_running_loop()
        futures = {}
        for p in peers:
            fut = loop.create_future()
            self._pending_tip_requests[p.address] = fut
            futures[p.address] = fut
        try:
            for p in peers:
                try:
                    await self._send_message(p, config.MSG_GET_STATUS, b'')
                except Exception as e:
                    bootstrap.logger.debug(f'[Sync] Tip request to {p.address} failed: {e}')
            await bootstrap.asyncio.wait(set(futures.values()), timeout=timeout)
        except Exception as e:
            bootstrap.logger.debug(f'[Sync] Tip quorum error: {e}')
        finally:
            for addr in futures:
                self._pending_tip_requests.pop(addr, None)
        votes = {}
        for addr, fut in futures.items():
            if fut.done() and (not fut.cancelled()) and (not fut.exception()):
                r = fut.result()
                h = int(r.get('height', 0))
                if h > 0:
                    key = (h - 1, str(r.get('last_hash', '')))
                    votes[key] = votes.get(key, 0) + 1
        if not votes:
            return None
        if len(peers) == 1:
            (bid, hsh), _c = next(iter(votes.items()))
            bootstrap.logger.warning('[Sync] Only one peer available for tip cross-check — using its tip with a warning')
            return {'block_id': bid, 'hash': hsh}
        if len(votes) == 1:
            (bid, hsh), _c = next(iter(votes.items()))
            bootstrap.logger.warning('[Sync] Only one peer answered the tip cross-check — using its tip with a warning')
            return {'block_id': bid, 'hash': hsh}
        total = sum(votes.values())
        for (bid, hsh), count in votes.items():
            if count * 2 > total:
                return {'block_id': bid, 'hash': hsh}
        bootstrap.logger.warning(f'[Sync] Tip cross-check: no majority among {total} answering peers (votes={votes})')
        return None

    async def _fetch_snapshot_history(self, H: int, tip: bootstrap.Dict, peer: EncryptedPeer) -> bootstrap.Optional[bootstrap.List[bootstrap.Dict]]:
        start = max(1, H - maze.SNAPSHOT_WINDOW + 1)
        end = H - 1
        if end < start:
            return []
        missing = []
        for bid in range(start, end + 1):
            row = await self.node.block_repo.get_by_id(bid)
            if row is None:
                missing.append(bid)
        if not missing:
            return []
        ranges = []
        r0 = missing[0]
        r1 = missing[0]
        for bid in missing[1:]:
            if bid == r1 + 1:
                r1 = bid
            else:
                ranges.append((r0, r1))
                r0 = bid
                r1 = bid
        ranges.append((r0, r1))
        fetched = {}
        for s, e in ranges:
            cur = s
            while cur <= e:
                chunk_end = min(e, cur + 49)
                loop = bootstrap.asyncio.get_running_loop()
                fut = loop.create_future()
                self._pending_snapshot_history[peer.address] = (cur, chunk_end, fut)
                try:
                    payload = bootstrap.json.dumps({'start': cur, 'end': chunk_end}).encode()
                    await self._send_message(peer, config.MSG_GET_BLOCKS, payload)
                    await bootstrap.asyncio.wait({fut}, timeout=maze.SNAPSHOT_REQUEST_TIMEOUT)
                except Exception as ex:
                    bootstrap.logger.warning(f'[Sync] Snapshot history fetch [{cur},{chunk_end}] from {peer.address} failed: {ex}')
                    return None
                finally:
                    self._pending_snapshot_history.pop(peer.address, None)
                if not (fut.done() and (not fut.cancelled()) and (not fut.exception())):
                    bootstrap.logger.warning(f'[Sync] Snapshot history fetch [{cur},{chunk_end}] from {peer.address} timed out')
                    return None
                blocks = fut.result() or []
                for b in blocks:
                    if isinstance(b, dict) and 'id' in b:
                        try:
                            _bid = int(b['id'])
                        except Exception:
                            bootstrap.logger.warning(f'[Sync] Snapshot history fetch [{cur},{chunk_end}] from {peer.address} got a block with a bad id — rejecting snapshot')
                            return None
                        if _bid < cur or _bid > chunk_end:
                            bootstrap.logger.warning(f'[Sync] Snapshot history fetch [{cur},{chunk_end}] from {peer.address} got out-of-range block {_bid} — rejecting snapshot')
                            return None
                for b in blocks:
                    if isinstance(b, dict) and 'id' in b:
                        fetched[int(b['id'])] = b
                cur = chunk_end + 1
        got = [fetched[i] for i in sorted(fetched.keys()) if start <= i <= end]
        for b in got:
            try:
                if b.get('hash') != crypto.calculate_block_hash(b):
                    bootstrap.logger.warning(f'[Sync] Snapshot history: block {b.get('id')} hash mismatch — rejecting snapshot')
                    return None
            except Exception as ex:
                bootstrap.logger.warning(f'[Sync] Snapshot history: block {b.get('id')} hash check failed ({ex}) — rejecting snapshot')
                return None
        by_id = {int(b['id']): b for b in got}
        for bid in sorted(by_id.keys()):
            if bid == start:
                continue
            b = by_id[bid]
            prev = by_id.get(bid - 1)
            if prev is None:
                prev = await self.node.block_repo.get_by_id(bid - 1)
            if prev is None:
                bootstrap.logger.warning(f'[Sync] Snapshot history: block {bid} has no predecessor — rejecting snapshot')
                return None
            if b.get('phash') != prev.get('hash'):
                bootstrap.logger.warning(f'[Sync] Snapshot history: block {bid} phash does not match block {bid - 1} hash — rejecting snapshot')
                return None
        prev_tip = by_id.get(H - 1)
        if prev_tip is None:
            prev_tip = await self.node.block_repo.get_by_id(H - 1)
        if prev_tip is not None and tip.get('phash') != prev_tip.get('hash'):
            bootstrap.logger.warning('[Sync] Snapshot history: tip phash does not match block H-1 hash — rejecting snapshot')
            return None
        return got

    async def _load_state_snapshot(self, snapshot: bootstrap.Dict, height: int) -> bool:
        db = self.node.db
        now = int(bootstrap.time.time())
        bals = {}
        toks = {}
        cst = {}
        cst2 = {}
        htlcs = {}
        mazes = {}
        tokis = {}
        convs = {}
        mazeatts = {}
        svfregs = {}
        svfepochs = {}
        svfcerts = {}
        for k, v in snapshot.items():
            if k.startswith('bal:'):
                bals[k[4:]] = v
            elif k.startswith('tok:'):
                rest = k[4:]
                t, _, w = rest.partition(':')
                toks[t, w] = v
            elif k.startswith('cst:'):
                rest = k[4:]
                c, _, kk = rest.partition(':')
                cst[c, kk] = v
            elif k.startswith('cst2:'):
                rest = k[5:]
                c, _, kk = rest.partition(':')
                cst2[c, kk] = v
            elif k.startswith('htlc:'):
                htlcs[k[5:]] = v
            elif k.startswith('maze:'):
                mazes[k[5:]] = v
            elif k.startswith('toki:'):
                tokis[k[5:]] = v
            elif k.startswith('conv:'):
                convs[k[5:]] = v
            elif k.startswith('mazeatt:'):
                mazeatts[k[8:]] = v
            elif k.startswith('svfreg:'):
                svfregs[k[7:]] = v
            elif k.startswith('svfepoch:'):
                svfepochs[k[9:]] = v
            elif k.startswith('svfcert:'):
                svfcerts[k[8:]] = v
            elif k.startswith('height:'):
                pass
            else:
                bootstrap.logger.warning(f'[Sync] Snapshot load: unknown snapshot key {str(k)[:32]} — ignoring')

        def _ins(table, cols):
            n = len(cols)
            if db.db_type == 'sqlite':
                ph = ', '.join(['?'] * n)
            else:
                ph = ', '.join(('$%d' % (i + 1) for i in range(n)))
            return 'INSERT INTO %s (%s) VALUES (%s)' % (table, ', '.join(cols), ph)
        try:
            async with await db.transaction():
                await db.execute_dml('DELETE FROM balances')
                for wallet, bal in bals.items():
                    await db.execute_dml(_ins('balances', ['wallet', 'bal']), wallet, int(bal))
                await db.execute_dml('DELETE FROM token_balances')
                for (t, w), bal in toks.items():
                    await db.execute_dml(_ins('token_balances', ['token_address', 'wallet', 'balance']), t, w, int(bal))
                await db.execute_dml('DELETE FROM contract_state')
                for (c, kk), val in cst.items():
                    await db.execute_dml(_ins('contract_state', ['contract_address', 'key', 'value']), c, kk, str(val))
                await db.execute_dml('DELETE FROM contract_storage_v2')
                for (c, kk), val in cst2.items():
                    await db.execute_dml(_ins('contract_storage_v2', ['contract_address', 'key', 'value']), c, kk, str(val))
                await db.execute_dml('DELETE FROM htlc_contracts')
                for hid, h in htlcs.items():
                    await db.execute_dml(_ins('htlc_contracts', ['id', 'sender', 'receiver', 'hashlock', 'timelock', 'amount', 'token_address', 'status', 'created_at', 'claimed_at', 'refunded_at']), hid, h.get('sender', ''), h.get('receiver', ''), h.get('hashlock', ''), int(h.get('timelock', 0)), int(h.get('amount', 0)), h.get('token_address', ''), h.get('status', ''), now, None, None)
                await db.execute_dml('DELETE FROM tokens')
                for addr, t in tokis.items():
                    await db.execute_dml(_ins('tokens', ['address', 'name', 'symbol', 'owner', 'total_supply', 'decimals', 'created_at', 'fee_paid', 'mintable', 'burnable', 'mining_type', 'mining_reward', 'mining_interval', 'mining_difficulty', 'stake_threshold', 'last_mined_block', 'total_mined', 'max_mineable_supply']), addr, t.get('name', ''), t.get('symbol', ''), t.get('owner', ''), int(t.get('total_supply', 0)), int(t.get('decimals', 0)), now, 0, int(t.get('mintable', 0)), int(t.get('burnable', 0)), t.get('mining_type', ''), int(t.get('mining_reward', 0)), int(t.get('mining_interval', 0)), int(t.get('mining_difficulty', 0)), int(t.get('stake_threshold', 0)), int(t.get('last_mined_block', 0)), int(t.get('total_mined', 0)), int(t.get('max_mineable_supply', 0)))
                await db.execute_dml('DELETE FROM contract_v2')
                for addr, c in convs.items():
                    await db.execute_dml(_ins('contract_v2', ['address', 'owner', 'bytecode', 'abi', 'created_at', 'tx_hash', 'storage_root', 'code_hash']), addr, c.get('owner', ''), '', '{}', now, '', '', c.get('code_hash', ''))
                await db.execute_dml('DELETE FROM maze_attestations')
                for mid, a in mazeatts.items():
                    await db.execute_dml(_ins('maze_attestations', ['maze_id', 'last_size', 'last_block', 'last_block_hash', 'pubkey']), mid, int(a.get('last_size', 5)), int(a.get('last_block', 0)), a.get('last_block_hash', ''), a.get('pubkey', ''))
                await db.execute_dml('DELETE FROM minermazes')
                maze_cols = ['maze_id', 'minerid', 'size', 'walldensityppm', 'seed', 'posx', 'posy', 'posz', 'goalx', 'goaly', 'goalz', 'movenonce', 'consecutivewallhits', 'turbulenceppm', 'growthcount', 'knowledge', 'lastgoalheight', 'lastactiveheight', 'mazeroot', 'invitedguest', 'guestlock', 'lastknowledgeheight', 'createdat', 'updatedat', 'ghostx', 'ghosty', 'ghostz']
                for mid, m in mazes.items():
                    att = mazeatts.get(mid, {})
                    size = int(att.get('last_size', 5)) if att else 5
                    await db.execute_dml(_ins('minermazes', maze_cols), mid, m.get('minerid', ''), size, int(m.get('walldensityppm', 0)), str(m.get('seed', '')), 0, 0, 0, int(m.get('goalx', 0)), int(m.get('goaly', 0)), int(m.get('goalz', 0)), 0, 0, 0, 0, 0, 0, height, '', '', '', 0, now, now, 0, 0, 0)
                await db.execute_dml('DELETE FROM svf_profiles')
                for tok, reg in svfregs.items():
                    profile = {'schema_version': svf.SVF_PROFILE_SCHEMA_VERSION, 'family_id': svf.SVF_PROFILE_FAMILY_ID, 'sample_blocks': int(reg.get('sample_blocks', 0)), 'min_distinct_winners': int(reg.get('min_distinct_winners', 0)), 'min_growth_blocks': int(reg.get('min_growth_blocks', 0)), 'min_total_attestation_weight': int(reg.get('min_total_attestation_weight', 0))}
                    canonical = svf.svf_profile_bytes(profile)
                    phash = reg.get('profile_hash', '')
                    await db.execute_dml(_ins('svf_profiles', ['token_address', 'chain_id', 'runtime_code_hash', 'template_id', 'profile_schema_version', 'canonical_profile_bytes', 'profile_hash', 'registrant', 'registration_tx_hash', 'registration_block_height', 'effective_epoch', 'status']), tok, int(reg.get('chain_id', config.CHAIN_ID)), '', '', svf.SVF_PROFILE_SCHEMA_VERSION, canonical.hex(), phash, '', '', 0, 0, 'ACTIVE')
                await db.execute_dml('DELETE FROM svf_epoch_roots')
                for epoch_id, e in svfepochs.items():
                    await db.execute_dml(_ins('svf_epoch_roots', ['epoch_id', 'root_hash', 'record_count', 'complete']), int(epoch_id), e.get('root', ''), int(e.get('count', 0)), 1 if int(e.get('count', 0)) == svf.SVF_EPOCH_BLOCKS else 0)
                await db.execute_dml('DELETE FROM svf_certificates')
                for epoch_id, c in svfcerts.items():
                    ep = int(epoch_id)
                    ws = ep * svf.SVF_EPOCH_BLOCKS
                    await db.execute_dml(_ins('svf_certificates', ['evidence_epoch', 'chain_id', 'committee_epoch', 'window_start_height', 'window_end_height', 'anchor_block_hash', 'evidence_root', 'group_public_key_id', 'threshold_signature', 'inclusion_block', 'usable_from']), ep, config.CHAIN_ID, svf_keys.SVF_COMMITTEE_EPOCH, ws, ws + svf.SVF_EPOCH_BLOCKS - 1, c.get('anchor_block_hash', ''), c.get('evidence_root', ''), '', '', int(c.get('inclusion_block', 0)), int(c.get('usable_from', 0)))
                if db.db_type == 'sqlite':
                    await db.execute_dml('INSERT OR REPLACE INTO state_snapshots (block_id, state_root, receipt_root, snapshot_data, created_at) VALUES (?, ?, ?, ?, ?)', height, _db._state_root_from_snapshot(snapshot), '', bootstrap.json.dumps(snapshot), now)
                else:
                    await db.execute_dml('INSERT INTO state_snapshots (block_id, state_root, receipt_root, snapshot_data, created_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (block_id) DO UPDATE SET state_root = EXCLUDED.state_root, receipt_root = EXCLUDED.receipt_root, snapshot_data = EXCLUDED.snapshot_data, created_at = EXCLUDED.created_at', height, _db._state_root_from_snapshot(snapshot), '', bootstrap.json.dumps(snapshot), now)
            return True
        except Exception as e:
            bootstrap.logger.warning(f'[Sync] Snapshot state load failed at height {height}: {e}')
            return False

    async def _verify_snapshot_response(self, resp: bootstrap.Dict, peer_list: bootstrap.List[EncryptedPeer]) -> bootstrap.Optional[str]:
        if not isinstance(resp, dict):
            return 'response is not a dict'
        H = resp.get('height')
        snapshot = resp.get('snapshot')
        tip = resp.get('tip_block')
        genesis_hash = str(resp.get('genesis_hash') or '')
        state_root = str(resp.get('state_root') or '')
        if not isinstance(H, int) or H < 0:
            return 'bad height in snapshot response'
        if not isinstance(snapshot, dict) or not isinstance(tip, dict):
            return 'snapshot or tip_block missing'
        if int(tip.get('id', -1)) != H:
            return f'tip block id {tip.get('id')} != snapshot height {H}'
        try:
            recomputed = db._state_root_from_snapshot(snapshot)
        except Exception as e:
            return f'snapshot root recompute failed: {e}'
        if recomputed != state_root or recomputed != str(tip.get('state_root', '')):
            return 'snapshot state root does not match tip block state_root'
        if not genesis_hash or len(genesis_hash) != 64:
            return 'genesis_hash missing or not 64 hex chars'
        pinned = getattr(self.node, 'genesis_hash', '') or ''
        if pinned and pinned != genesis_hash:
            return 'genesis_hash does not match pinned genesis'
        quorum = await self._request_tip_quorum(peer_list)
        if quorum is None:
            return 'tip cross-check: no quorum (peers disagree or did not answer)'
        _qh = int(quorum['block_id'])
        if _qh < H:
            return f'tip cross-check: quorum tip {_qh} is behind snapshot tip {H}'
        if _qh == H and str(quorum['hash']) != str(tip.get('hash', '')):
            return f'tip cross-check: quorum tip {_qh}/{str(quorum['hash'])[:16]}... != snapshot tip {H}/{str(tip.get('hash', ''))[:16]}...'
        if _qh - H > maze.SNAPSHOT_WINDOW:
            return f'tip cross-check: snapshot tip {H} is {_qh - H} blocks behind quorum tip {_qh} (stale)'
        return None

    async def _apply_snapshot_response(self, resp: bootstrap.Dict, peer: EncryptedPeer) -> bool:
        H = int(resp['height'])
        snapshot = resp['snapshot']
        tip = resp['tip_block']
        genesis_hash = str(resp.get('genesis_hash') or '')
        hist = await self._fetch_snapshot_history(H, tip, peer)
        if hist is None:
            bootstrap.logger.warning('[Sync] Snapshot sync rejected: last-100 history fetch/verify failed')
            return False
        added = []
        try:
            for b in hist:
                if await self.node.block_repo.get_by_id(int(b['id'])) is None:
                    await self.node.block_repo.create(b)
                    added.append(int(b['id']))
            if await self.node.block_repo.get_by_id(H) is None:
                await self.node.block_repo.create(tip)
                added.append(H)
        except Exception as e:
            bootstrap.logger.warning(f'[Sync] Snapshot sync rejected: storing history/tip failed: {e}')
            for bid in added:
                try:
                    await self.node.db.execute_dml('DELETE FROM blocks WHERE id = ?' if self.node.db.db_type == 'sqlite' else 'DELETE FROM blocks WHERE id = $1', bid)
                except Exception:
                    pass
            return False
        _snap_att = {k[8:]: int(v.get('last_size', 5)) for k, v in (snapshot or {}).items() if isinstance(k, str) and k.startswith('mazeatt:') and isinstance(v, dict)}
        _pw0 = bootstrap.time.time()
        await self.node.consensus._prewarm_mazes(self.node.consensus._maze_keys_for_block(tip))
        bootstrap.logger.info(f'[Verify] pre-warm snapshot tip block {H}: {bootstrap.time.time() - _pw0:.1f}s')
        _tv0 = bootstrap.time.time()
        ok = await self.node.verify_block_proof(tip, _snap_att=_snap_att)
        bootstrap.logger.info(f'[Sync] tip verify block {H} took {bootstrap.time.time() - _tv0:.1f}s')
        if not ok:
            bootstrap.logger.warning(f'[Sync] Snapshot sync rejected: tip block {H} failed verify_block_proof')
            for bid in added:
                try:
                    await self.node.db.execute_dml('DELETE FROM blocks WHERE id = ?' if self.node.db.db_type == 'sqlite' else 'DELETE FROM blocks WHERE id = $1', bid)
                except Exception:
                    pass
            return False
        if not getattr(self.node, 'genesis_hash', ''):
            self.node.genesis_hash = genesis_hash
        if not await self._load_state_snapshot(snapshot, H):
            bootstrap.logger.warning('[Sync] Snapshot sync rejected: state load failed')
            for bid in added:
                try:
                    await self.node.db.execute_dml('DELETE FROM blocks WHERE id = ?' if self.node.db.db_type == 'sqlite' else 'DELETE FROM blocks WHERE id = $1', bid)
                except Exception:
                    pass
            return False
        _tip_att = tip.get('maze_attestation') if isinstance(tip, dict) else None
        if isinstance(_tip_att, dict) and _tip_att.get('maze_id') and (_tip_att.get('size') is not None) and (H > 0):
            try:
                await self.node.maze_attestation_repo.upsert({'maze_id': str(_tip_att['maze_id']), 'last_size': int(_tip_att['size']), 'last_block': H, 'last_block_hash': str(tip.get('hash', '')), 'pubkey': str(_tip_att.get('pubkey', ''))})
            except Exception as _e:
                bootstrap.logger.warning(f'[Sync] Snapshot tip attestation upsert failed for block {H}: {_e}')
        try:
            await self.node.network_state_repo.set('genesis_alloc_applied', '1')
            _tot = 0
            _brows = await self.node.db.fetch('SELECT bal FROM balances')
            for _br in _brows or []:
                try:
                    _tot += int(_br['bal'])
                except Exception:
                    continue
            _burned = await self.node.network_state_repo.get('burned_total')
            if _burned:
                try:
                    _tot += int(_burned)
                except Exception:
                    pass
            try:
                _burned_i = int(_burned) if _burned else 0
            except Exception:
                _burned_i = 0
            await self.node.network_state_repo.set('burned_total', str(_burned_i))
            await self.node.network_state_repo.set('total_minted', str(_tot))
            self.node.total_minted = _tot
            bootstrap.logger.info(f'[Sync] Snapshot genesis alloc marked applied; total_minted recomputed to {_tot // config.SUBS} MCX')
        except Exception as _e:
            bootstrap.logger.warning(f'[Sync] Snapshot genesis marker/total_minted recompute failed: {_e}')
        try:
            _ev_n = 0
            _ev_skip = 0
            _ev_start = max(1, H - maze.SNAPSHOT_WINDOW + 1)
            for _hid in range(_ev_start, H + 1):
                _hb = await self.node.block_repo.get_by_id(_hid)
                if not isinstance(_hb, dict):
                    continue
                try:
                    _ev = svf.compute_block_evidence(_hb, _hid)
                except svf.SVFReject:
                    _ev_skip += 1
                    continue
                except Exception as _ee:
                    bootstrap.logger.warning(f'[Sync] Snapshot SVF evidence rebuild: block {_hid} extraction failed: {_ee}')
                    continue
                _ev_epoch = _hid // svf.SVF_EPOCH_BLOCKS
                _ev_rec = {'epoch_id': _ev_epoch, 'height': _ev.block_id, 'block_hash': _ev.block_hash, 'winner_pubkey': _ev.winner_pubkey, 'attested_size': _ev.attested_size, 'attestation_weight': str(_ev.attestation_weight), 'growth_present': 1 if _ev.growth_present else 0, 'record_hash': _ev.record_hash.hex()}
                try:
                    if self.node.db.db_type == 'sqlite':
                        await self.node.db.execute_dml('INSERT OR REPLACE INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES (?,?,?,?,?,?,?,?)', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                    else:
                        await self.node.db.execute_dml('INSERT INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (epoch_id, height) DO UPDATE SET block_hash=$3, winner_pubkey=$4, attested_size=$5, attestation_weight=$6, growth_present=$7, record_hash=$8', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                    _ev_n += 1
                except Exception as _ee:
                    bootstrap.logger.warning(f'[Sync] Snapshot SVF evidence rebuild: persist failed for block {_hid}: {_ee}')
            bootstrap.logger.info(f'[Sync] Snapshot SVF evidence rebuilt: {_ev_n} records persisted, {_ev_skip} skipped (no evidence)')
        except Exception as _e:
            bootstrap.logger.warning(f'[Sync] Snapshot SVF evidence rebuild failed: {_e}')
        await self.node._load_state()
        bootstrap.logger.info(f'[Sync] Snapshot sync complete: height={self.node.height} (tip block {H}), state root verified, last {maze.SNAPSHOT_WINDOW} blocks present. This node is PRUNED (no full history).')
        return True

    def _alive_peers(self, peer_list):
        now = bootstrap.time.time()
        alive = [p for p in peer_list if now - getattr(p, 'last_seen', 0) <= maze.PEER_ALIVE_WINDOW]
        return alive or list(peer_list)

    async def _try_snapshot_sync(self, best_peer: EncryptedPeer, peer_list: bootstrap.List[EncryptedPeer]) -> bool:
        now = bootstrap.time.time()
        if now - self._snapshot_last_attempt < maze.SNAPSHOT_RETRY_COOLDOWN:
            bootstrap.logger.info(f'[Sync] Snapshot sync on cooldown ({int(maze.SNAPSHOT_RETRY_COOLDOWN - (now - self._snapshot_last_attempt))}s left) — waiting for the cooldown, then retrying snapshot sync')
            return False
        if self._snapshot_sync_running:
            bootstrap.logger.info('[Sync] Snapshot sync already in progress — waiting for the attempt in progress')
            return False
        self._snapshot_sync_running = True
        try:
            self._snapshot_last_attempt = now
            ordered = sorted(self._alive_peers(peer_list), key=lambda p: (-p.height, p.address))
            seen = set()
            for peer in ordered:
                if peer.address in seen:
                    continue
                seen.add(peer.address)
                bootstrap.logger.info(f'[Sync] Snapshot sync: requesting snapshot from {peer.address} (height {peer.height})')
                resp = await self._request_snapshot(peer)
                if resp is None:
                    bootstrap.logger.warning(f'[Sync] Snapshot sync: no snapshot from {peer.address} — trying next peer')
                    continue
                reason = await self._verify_snapshot_response(resp, peer_list)
                if reason is not None:
                    self._snapshot_consec_failures += 1
                    bootstrap.logger.warning(f'[Sync] Snapshot sync REJECTED from {peer.address}: {reason} — trying next peer')
                    continue
                if await self._apply_snapshot_response(resp, peer):
                    self._snapshot_consec_failures = 0
                    return True
                self._snapshot_consec_failures += 1
                bootstrap.logger.warning(f'[Sync] Snapshot sync: apply failed for {peer.address} — will retry snapshot sync next cycle')
                return False
            self._snapshot_consec_failures += 1
            bootstrap.logger.warning('[Sync] Snapshot sync: no peer offered a snapshot — waiting for a snapshot source')
            return False
        finally:
            self._snapshot_sync_running = False

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

    def _r37_import_in_flight(self):
        _lock = getattr(self.node, '_import_lock', None)
        return _lock is not None and _lock.locked()

    async def _sync_loop(self):
        while not self._discovery_stop.is_set():
            await bootstrap.asyncio.sleep(config.SYNC_INTERVAL)
            if bootstrap.time.time() < getattr(self, '_sync_paused_until', 0.0):
                continue
            async with self._lock:
                peer_list = self._alive_peers(list(self.peers.values()))
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
            if gap <= maze.SNAPSHOT_SYNC_THRESHOLD:
                self._snapshot_consec_failures = 0
            bootstrap.logger.info(f'[P2P] Syncing from {best_peer.address}: local={self.node.height}, remote={best_height}')
            if self.node.height == 0 or gap > maze.SNAPSHOT_SYNC_THRESHOLD:
                if await self._try_snapshot_sync(best_peer, peer_list):
                    bootstrap.logger.info('[Sync] Snapshot sync succeeded — resuming normal sync from the new tip')
                    continue
                bootstrap.logger.info('[Sync] Snapshot sync did not complete — waiting for a snapshot source (no full sync while far behind)')
                continue
            max_chunks_this_cycle = 25
            rewound_this_stall = False
            for _ in range(max_chunks_this_cycle):
                if self.node.height >= best_height:
                    break
                start = self.node.height
                end = min(best_height, start + config.SYNC_BATCH_BLOCKS - 1)
                payload = bootstrap.json.dumps({'start': start, 'end': end}).encode()
                await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
                _r37_deferred = 0.0
                _r37_defer_logged = False
                waited = 0.0
                while self.node.height <= start and waited < 8.0 and (_r37_deferred < maze._R37_SYNC_IMPORT_DEFER_CAP_S):
                    _r37_t0 = bootstrap.time.monotonic()
                    await bootstrap.asyncio.sleep(0.25)
                    _r37_dt = bootstrap.time.monotonic() - _r37_t0
                    if self._r37_import_in_flight():
                        _r37_deferred += _r37_dt
                        if not _r37_defer_logged:
                            _r37_defer_logged = True
                            bootstrap.logger.info(f'[R37] sync patience: import in flight for [{start},{end}) (holder={getattr(self.node, '_import_lock_holder', None)}) - lock-held time does not count toward the snapshot budget (cap {maze._R37_SYNC_IMPORT_DEFER_CAP_S:.0f}s)')
                    else:
                        waited += 0.25
                if _r37_deferred >= maze._R37_SYNC_IMPORT_DEFER_CAP_S:
                    bootstrap.logger.warning(f'[R37] sync patience: import in flight for [{start},{end}) held the lock {_r37_deferred:.0f}s (cap reached) - treating the stall as genuine, snapshot fallback proceeds')
                if self.node.height <= start and (not rewound_this_stall):
                    rewound_this_stall = True
                    rewind_start = max(0, start - 100)
                    bootstrap.logger.info(f'[Sync] No progress on [{start},{end}); rewinding fetch to [{rewind_start},{end}) in SYNC_BATCH_BLOCKS chunks to locate fork point')
                    _rw = rewind_start
                    _rw_waited = 0.0
                    while _rw <= end and self.node.height <= start and (_rw_waited < 30.0) and (_r37_deferred < maze._R37_SYNC_IMPORT_DEFER_CAP_S):
                        _chunk_end = min(end, _rw + config.SYNC_BATCH_BLOCKS - 1)
                        payload = bootstrap.json.dumps({'start': _rw, 'end': _chunk_end}).encode()
                        await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
                        _cw = 0.0
                        while self.node.height <= start and _cw < 8.0 and (_rw_waited < 30.0) and (_r37_deferred < maze._R37_SYNC_IMPORT_DEFER_CAP_S):
                            _r37_t0 = bootstrap.time.monotonic()
                            await bootstrap.asyncio.sleep(0.25)
                            _r37_dt = bootstrap.time.monotonic() - _r37_t0
                            if self._r37_import_in_flight():
                                _r37_deferred += _r37_dt
                                if not _r37_defer_logged:
                                    _r37_defer_logged = True
                                    bootstrap.logger.info(f'[R37] sync patience: import in flight for [{start},{end}) (holder={getattr(self.node, '_import_lock_holder', None)}) - lock-held time does not count toward the snapshot budget (cap {maze._R37_SYNC_IMPORT_DEFER_CAP_S:.0f}s)')
                            else:
                                _cw += 0.25
                                _rw_waited += 0.25
                        _rw = _chunk_end + 1
                if self.node.height <= start:
                    if self._r37_import_in_flight() and _r37_deferred < maze._R37_SYNC_IMPORT_DEFER_CAP_S:
                        bootstrap.logger.info(f'[R37] sync patience: import in flight for [{start},{end}) (holder={getattr(self.node, '_import_lock_holder', None)}) after rewind - deferring snapshot to next sync cycle')
                        break
                    if await self._try_snapshot_sync(best_peer, peer_list):
                        self._stuck_cycles = 0
                        self._stuck_peer = None
                        break
                    bootstrap.logger.warning(f'[Sync] Stuck at height {self.node.height} — no progress importing [{start},{end}) from {best_peer.address}. Tip is likely below a rejected block. Check logs above for [Verify] rejections; the loop will rotate to another peer and auto-retry after a cooldown.')
                    self._stuck_cycles = getattr(self, '_stuck_cycles', 0) + 1
                    self._stuck_peer = best_peer.address
                    if self._stuck_cycles >= 3:
                        self._stuck_cycles = 0
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
        _sw_peers = self._alive_peers(list(self.peers.values()))
        best_peer = max(_sw_peers, key=lambda p: p.height)
        if self.node.height == 0 or best_peer.height - self.node.height > maze.SNAPSHOT_SYNC_THRESHOLD:
            await self._try_snapshot_sync(best_peer, _sw_peers)
            return
        latest = await self.node.block_repo.get_latest()
        if latest is None:
            batch_end = min(best_peer.height, config.SYNC_BATCH_BLOCKS - 1)
            bootstrap.logger.info(f'[SYNC] Requesting genesis/initial blocks from {best_peer.address} (0 -> {batch_end} of {best_peer.height})')
            payload = bootstrap.json.dumps({'start': 0, 'end': batch_end}).encode()
            await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
            await bootstrap.asyncio.sleep(2)
            return
        if best_peer.height <= self.node.height:
            return
        batch_end = min(best_peer.height, self.node.height + config.SYNC_BATCH_BLOCKS - 1)
        bootstrap.logger.info(f'[SYNC] Starting sync from {best_peer.address} (height {self.node.height} -> {batch_end} of {best_peer.height})')
        payload = bootstrap.json.dumps({'start': self.node.height, 'end': batch_end}).encode()
        await self._send_message(best_peer, config.MSG_GET_BLOCKS, payload)
        await bootstrap.asyncio.sleep(2)

class AuxStateError(Exception):
    pass
