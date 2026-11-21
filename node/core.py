import bootstrap
import config
import config as _config
import crypto
import util
import maze
import maze as _maze
import gas
import svf_keys
import svf
import wallet
import genesis
import db
import repos
import mempool
import vm_host
import consensus
import P2P

def _ws_health_handler(request):
    from aiohttp import web
    return web.json_response({'status': 'ok', 'service': 'mcx-miner-ws'})

def _ws_app_routes(app, websocket_handler):
    app.router.add_get('/ws', websocket_handler)
    app.router.add_get('/healthz', _ws_health_handler)
    return app

class AuxStateError(Exception):
    pass

class _StageRollback(Exception):
    pass

class MicroCoreNode:

    def __init__(self, config: dict=None):
        self.config = config or _config.load_config()
        self.node_id = None
        self.wallet = None
        self.priv = None
        self.pub = None
        self.password = None
        self.height = 0
        self.last_hash = '0' * 64
        self.blocks = []
        self.total_minted = 0
        self.burned_total = 0
        self.miners: bootstrap.Dict[str, bootstrap.Dict] = {}
        self.nodes: bootstrap.Dict[str, bootstrap.Dict] = {}
        self.balances: bootstrap.Dict[str, int] = {}
        self.tokens: bootstrap.Dict[str, bootstrap.Dict] = {}
        self.token_balances: bootstrap.Dict[bootstrap.Tuple[str, str], int] = {}
        self._shutdown_flag = False
        self._proof_field_hint_shown = False
        self._genesis_handled = False
        self.svf_profiles: bootstrap.Dict[str, dict] = {}
        self.svf_evidence_store: bootstrap.Dict[int, list] = {}
        self.svf_epoch_roots: bootstrap.Dict[int, tuple] = {}
        self.svf_certificates: bootstrap.Dict[int, dict] = {}
        self.svf_activation_height: bootstrap.Optional[int] = None
        _db_cfg = self.config.get('database', self.config.get('db', {}))
        self.db = db.Database(_db_cfg.get('url'), require_postgres=_db_cfg.get('require_postgres', False))
        vm_host.export_vm_sandbox_env(self.config)
        _config.apply_consensus_config(self.config)
        wallet.validate_rpc_security_config(self.config)
        wallet.validate_rpc_startup_token(self.config)
        self.block_repo = repos.BlockRepo(self.db)
        self.tx_repo = repos.TransactionRepo(self.db)
        self.balance_repo = repos.BalanceRepo(self.db)
        self.miner_repo = repos.MinerRepo(self.db)
        self.node_repo = repos.NodeRepo(self.db)
        self.token_repo = repos.TokenRepo(self.db)
        self.token_balance_repo = repos.TokenBalanceRepo(self.db)
        self.contract_state_repo = repos.ContractStateRepo(self.db)
        self.contract_event_repo = repos.ContractEventRepo(self.db)
        self.multisig_repo = repos.MultisigRepo(self.db)
        self.challenge_repo = repos.ChallengeRepo(self.db)
        self.receipt_repo = repos.ReceiptRepo(self.db)
        self.finality_repo = repos.FinalityRepo(self.db)
        self.network_state_repo = repos.NetworkStateRepo(self.db)
        self.contract_v2_repo = repos.ContractV2Repo(self.db)
        self.contract_storage_v2_repo = repos.ContractStorageV2Repo(self.db)
        self.htlc_repo = repos.HTLCRepo(self.db)
        self.maze_repo = repos.MinerMazeRepo(self.db)
        self.maze_attestation_repo = repos.MazeAttestationRepo(self.db)
        self.maze_proof_repo = repos.MazeProofRepo(self.db)
        self.lottery_repo = repos.LotteryRepo(self.db)
        self.slash_repo = repos.SlashRepo(self.db)
        self.automation_repo = repos.AutomationRepo(self.db)
        self._seen_automation_sigs: bootstrap.Dict[str, float] = {}
        self.state_trie = db.StateTrie(self.db)
        self.rate_limiter = mempool.RateLimiter()
        self.subnet_rate_limiter = mempool.RateLimiter(max_requests=300, window_seconds=60)
        self.register_rate_limiter = mempool.RateLimiter(max_requests=6, window_seconds=60)
        self.rpc_rate_limiter = mempool.RateLimiter(max_requests=30, window_seconds=60)
        self.miner_rate_limiters: bootstrap.Dict[str, mempool.RateLimiter] = {}
        self.health_checker = mempool.HealthChecker()
        self._start_time = bootstrap.time.time()
        self._sign_timeout_total = 0
        self.mempool = mempool.Mempool()
        self.memory_mgr = mempool.MemoryChallengeManager()
        self.blockexecutionlock = bootstrap.asyncio.Lock()
        self.ws_sessions = {}
        self.vm_manager = None
        self.p2p = None
        self.consensus = consensus.PoSWConsensus(self)
        self.finality_gadget = repos.FinalityGadget(self)
        self._producing_enabled = False
        self._next_block_time = 0.0
        self.miner_websockets: bootstrap.Dict[str, bootstrap.Any] = {}
        self._block_sign_futures: bootstrap.Dict[str, bootstrap.asyncio.Future] = {}
        self._setup_wallet()
        self.node_id = self.wallet
        self.svf_profiles: bootstrap.Dict[str, dict] = {}
        self.svf_evidence_store: bootstrap.Dict[int, list] = {}
        self.svf_epoch_roots: bootstrap.Dict[int, tuple] = {}
        self.svf_certificates: bootstrap.Dict[int, dict] = {}
        self.svf_activation_height: bootstrap.Optional[int] = None
        bootstrap.logger.info(f'[Node] Node ID: {self.node_id[:16]}..., wallet: {self.wallet[:16]}...')

    def _setup_wallet(self):
        non_interactive = not bootstrap.sys.stdin.isatty()
        configured_wallet = self.config.get('wallet')
        wallet_address = configured_wallet.get('address') if isinstance(configured_wallet, dict) else configured_wallet
        _wf = wallet._read_wallet_file()
        if _wf.get('address'):
            wallet_address = _wf.get('address')
        if self.config.get('private_key_encrypted') and (not _wf.get('private_key_encrypted')) and wallet_address:
            wallet._save_wallet_file(self.config['private_key_encrypted'], wallet_address, self.config.get('public_key', ''))
            self.config.pop('private_key_encrypted', None)
            self.config.pop('public_key', None)
            wallet._strip_wallet_from_config()
            bootstrap.logger.warning(f'[Wallet] Moved the encrypted key from config.yaml to {wallet._wallet_file_path()}.')
            _wf = wallet._read_wallet_file()
        _enc_blob = _wf.get('private_key_encrypted') or ''
        if wallet_address and _enc_blob:
            raw_password = self.config.get('password') or bootstrap.os.environ.get('MCX_PASSWORD')
            if not raw_password:
                if non_interactive:
                    bootstrap.logger.error('[Wallet] Encrypted wallet found but no password available (not running interactively, MCX_PASSWORD is not set). This node does not store the password. Set the MCX_PASSWORD environment variable and restart.')
                    bootstrap.sys.exit(1)
                raw_password = input('Enter password to decrypt private key: ')
            password = raw_password.strip() or raw_password
            candidates = []
            for _p in (password, raw_password, password + ' '):
                if _p and _p not in candidates:
                    candidates.append(_p)
            encrypted = _enc_blob
            try:
                last_pw_err = None
                for _pw in candidates:
                    try:
                        self.priv = crypto.decrypt_private_key(encrypted, _pw)
                        password = _pw
                        break
                    except Exception as _e:
                        last_pw_err = _e
                else:
                    raise last_pw_err or ValueError('Invalid password')
                self.wallet = wallet_address
                self._wallet_blob = encrypted
                self.pub = _wf.get('public_key') or self.config.get('public_key')
                if not self.pub:
                    priv_int = int(self.priv, 16)
                    try:
                        priv_key = bootstrap.ec.derive_private_key(priv_int, bootstrap.ec.SECP256K1())
                    except TypeError:
                        priv_key = bootstrap.ec.derive_private_key(priv_int, bootstrap.ec.SECP256K1)
                    pub = priv_key.public_key()
                    pub_raw = pub.public_bytes(encoding=bootstrap.serialization.Encoding.X962, format=bootstrap.serialization.PublicFormat.UncompressedPoint)
                    self.pub = pub_raw.hex()
                bootstrap.logger.info('[Wallet] Loaded from config.')
                return
            except Exception as e:
                bootstrap.logger.error(f'[Wallet] Failed to decrypt: {e}')
                bootstrap.sys.exit(1)
        if non_interactive and (not (bootstrap.os.environ.get('MCX_PASSWORD', '').strip() or self.password or self.config.get('password'))):
            bootstrap.logger.error('[Wallet] No wallet configured and no MCX_PASSWORD set (not running interactively). This node does not store passwords, so continuing would create a wallet nobody can decrypt. Set MCX_PASSWORD before starting unattended. Nothing was created.')
            bootstrap.sys.exit(1)
        print('\n' + '=' * 60)
        print(f'{bootstrap.CYAN}WALLET SETUP{bootstrap.RESET}')
        print('=' * 60)
        if non_interactive:
            bootstrap.logger.warning('[Wallet] Not running interactively (no TTY) — generating a new wallet non-interactively. Set MCX_WALLET_MODE=classic|seed, MCX_WALLET_USERNAME, and MCX_PASSWORD to control this.')
            choice = bootstrap.os.environ.get('MCX_WALLET_MODE', 'classic').strip().lower()
            choice = '2' if choice in ('2', 'seed', 'mnemonic') else '1'
        else:
            choice = input('Generate wallet using:\n  1) Random private key (classic)\n  2) Seed phrase (12 words)\nEnter 1 or 2: ').strip()
        if choice == '2':
            if non_interactive:
                username = bootstrap.os.environ.get('MCX_WALLET_USERNAME', 'node').strip() or 'node'
            else:
                username = input('Enter a username for this wallet (used in derivation): ').strip() or 'node'
            seed = crypto.generate_mnemonic()
            print(f'\n{bootstrap.YELLOW}Your 12-word seed phrase (SAVE THIS!):{bootstrap.RESET}\n{seed}\n')
            addr, priv_hex, pub_hex = crypto.derive_wallet_from_seed(seed_bytes=crypto.mnemonic_to_seed(seed), path=f"m/44'/60'/0'/0/0")
            self.wallet = addr
            self.priv = priv_hex
            self.pub = pub_hex
        else:
            try:
                priv_key = bootstrap.ec.generate_private_key(bootstrap.ec.SECP256K1())
            except TypeError:
                priv_key = bootstrap.ec.generate_private_key(bootstrap.ec.SECP256K1)
            priv_raw = priv_key.private_numbers().private_value.to_bytes(32, 'big')
            self.priv = priv_raw.hex()
            pub = priv_key.public_key()
            pub_raw = pub.public_bytes(encoding=bootstrap.serialization.Encoding.X962, format=bootstrap.serialization.PublicFormat.UncompressedPoint)
            self.pub = pub_raw.hex()
            self.wallet = util.pubkey_to_address(self.pub)
        self.node_id = self.wallet
        print(f'{bootstrap.GREEN}Wallet address: {self.wallet}{bootstrap.RESET}')
        if not self.password:
            pwd = bootstrap.os.environ.get('MCX_PASSWORD', '').strip()
            if not pwd and (not non_interactive):
                pwd = input('Enter a password to encrypt your private key: ').strip()
            if not pwd:
                bootstrap.logger.error('[Wallet] No password provided (MCX_PASSWORD unset or prompt answered empty). This node does not store passwords; it will not continue without one. Set MCX_PASSWORD and restart. No wallet was kept.')
                bootstrap.sys.exit(1)
            self.password = pwd
        encrypted = crypto.encrypt_private_key(self.priv, self.password)
        wallet_config = self.config.get('wallet')
        if isinstance(wallet_config, dict):
            wallet_config['address'] = self.wallet
            self.config['wallet'] = wallet_config
        else:
            self.config['wallet'] = self.wallet
        self._wallet_blob = encrypted
        _wpath = wallet._save_wallet_file(encrypted, self.wallet, self.pub)
        self.config.pop('private_key_encrypted', None)
        self.config.pop('public_key', None)
        disk_cfg = {}
        if bootstrap.os.path.exists(config.CONFIG_PATH):
            try:
                with open(config.CONFIG_PATH, 'r') as f:
                    disk_cfg = bootstrap.yaml.safe_load(f) or {}
            except Exception:
                disk_cfg = {}
        disk_cfg.update(self.config)
        disk_cfg.pop('private_key_encrypted', None)
        disk_cfg.pop('public_key', None)
        with open(config.CONFIG_PATH, 'w') as f:
            bootstrap.yaml.dump(disk_cfg, f)
        bootstrap.logger.warning(f'[Wallet] Encrypted key saved to {_wpath}. Back up this file AND your wallet password: the node never stores the password, and without both the wallet cannot be recovered.')
        bootstrap.logger.info('[Wallet] Generated and saved.')

    async def _load_state(self):
        latest = await self.block_repo.get_latest()
        if latest:
            self.height = latest['id'] + 1
            self.last_hash = latest['hash']
            latest_ts = latest.get('ts', 0)
            if hasattr(latest_ts, 'timestamp'):
                latest_ts = latest_ts.timestamp()
            self._next_block_time = max(self._next_block_time, float(latest_ts) + config.BLOCK_TIME)
            load_start = max(0, self.height - maze.BLOCK_CACHE_MAX)
            all_blocks = await self.block_repo.get_range(load_start, self.height - 1, limit=maze.BLOCK_CACHE_MAX)
            self.blocks = all_blocks
            bootstrap.logger.info(f'[State] Loaded {len(self.blocks)} blocks (from #{load_start}), height={self.height}')
        miners = await self.miner_repo.get_active()
        for m in miners:
            self.miners[m['miner_id']] = m
        total_minted = await self.network_state_repo.get('total_minted')
        if total_minted:
            self.total_minted = int(total_minted)
        burned = await self.network_state_repo.get('burned_total')
        if burned:
            self.burned_total = int(burned)
        bootstrap.logger.info(f'[State] Loaded {len(self.miners)} miners, total minted: {self.total_minted // config.SUBS} MCX')
        await self.finality_gadget.ensure_loaded()
        await self._ensure_genesis_alloc()
        if svf.svf_active_at(self.height or 0):
            try:
                if self.db.db_type == 'sqlite':
                    rows = await self.db.fetch("SELECT token_address, canonical_profile_bytes FROM svf_profiles WHERE status = 'ACTIVE'")
                else:
                    rows = await self.db.fetch("SELECT token_address, canonical_profile_bytes FROM svf_profiles WHERE status = 'ACTIVE'")
                for r in rows or []:
                    try:
                        prof_bytes = bytes.fromhex(r['canonical_profile_bytes'])
                        profile = svf.svf_parse_profile(prof_bytes)
                        self.svf_profiles[r['token_address'].lower()] = profile
                    except Exception:
                        continue
                bootstrap.logger.debug(f'[SVF] restored {len(self.svf_profiles)} profiles from DB')
                if self.db.db_type == 'sqlite':
                    rows = await self.db.fetch('SELECT epoch_id, root_hash, record_count FROM svf_epoch_roots')
                else:
                    rows = await self.db.fetch('SELECT epoch_id, root_hash, record_count FROM svf_epoch_roots')
                for r in rows or []:
                    try:
                        self.svf_epoch_roots[int(r['epoch_id'])] = (bytes.fromhex(r['root_hash']), int(r['record_count']))
                    except Exception:
                        continue
                bootstrap.logger.debug(f'[SVF] restored {len(self.svf_epoch_roots)} epoch roots from DB')
                if self.db.db_type == 'sqlite':
                    rows = await self.db.fetch('SELECT evidence_epoch, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from FROM svf_certificates')
                else:
                    rows = await self.db.fetch('SELECT evidence_epoch, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from FROM svf_certificates')
                for r in rows or []:
                    try:
                        self.svf_certificates[int(r['evidence_epoch'])] = {'evidence_epoch': int(r['evidence_epoch']), 'anchor_block_hash': r['anchor_block_hash'], 'evidence_root': r['evidence_root'], 'group_pubkey': r['group_public_key_id'], 'threshold_signature': r['threshold_signature'], 'inclusion_block': int(r['inclusion_block']), 'usable_from': int(r['usable_from'])}
                    except Exception:
                        continue
                bootstrap.logger.debug(f'[SVF] restored {len(self.svf_certificates)} certificates from DB')
                tip_h = int(self.height or 0)
                earliest_epoch = max(0, (tip_h - config.PRUNE_BLOCKS) // svf.SVF_EPOCH_BLOCKS)
                if self.db.db_type == 'sqlite':
                    rows = await self.db.fetch('SELECT epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id >= ? ORDER BY epoch_id, height', earliest_epoch)
                else:
                    rows = await self.db.fetch('SELECT epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id >= $1 ORDER BY epoch_id, height', earliest_epoch)
                for r in rows or []:
                    try:
                        _eid = int(r['epoch_id'])
                        self.svf_evidence_store.setdefault(_eid, []).append({'block_id': int(r['height']), 'block_hash': r['block_hash'], 'winner_pubkey': r['winner_pubkey'], 'attested_size': int(r['attested_size']), 'attestation_weight': int(r['attestation_weight']), 'growth_present': bool(int(r['growth_present'])), 'record_hash': bytes.fromhex(r['record_hash']) if r['record_hash'] else b'\x00' * 32})
                    except Exception:
                        continue
                bootstrap.logger.debug(f'[SVF] restored evidence from epoch {earliest_epoch} onward')
            except Exception as _e:
                bootstrap.logger.warning(f'[SVF] state restore from DB failed: {_e}')

    async def _live_mazes(self) -> list:
        rows = await self.maze_repo.get_eligible(self.height)
        out = []
        for r in rows:
            try:
                out.append((str(r['maze_id']), str(r['minerid']), int(r['size'])))
            except Exception:
                continue
        return out

    async def _chain_agreed_maze_sizes(self, at_block: int) -> bootstrap.Dict[str, bootstrap.Tuple[int, int]]:
        out: bootstrap.Dict[str, bootstrap.Tuple[int, int]] = {}
        try:
            _known = {str(r.get('maze_id', '')) for r in await self.maze_attestation_repo.get_all() or []}
            _known.discard('')
        except Exception:
            _known = set()
        if not _known:
            return out
        _remaining = set(_known)
        _q = 'SELECT id, proof FROM blocks WHERE id < ? AND proof IS NOT NULL ORDER BY id DESC LIMIT 500' if self.db.db_type == 'sqlite' else 'SELECT id, proof FROM blocks WHERE id < $1 AND proof IS NOT NULL ORDER BY id DESC LIMIT 500'
        try:
            _rows = await self.db.fetch(_q, int(at_block))
        except Exception:
            return out
        for _r in _rows or []:
            if not _remaining:
                break
            try:
                _bid = int(_r.get('id', 0))
                _rp = _r.get('proof')
                if isinstance(_rp, str):
                    _rp = bootstrap.json.loads(_rp or '{}')
                if not isinstance(_rp, dict):
                    continue
            except Exception:
                continue
            _ra = _rp.get('maze_attestation')
            if isinstance(_ra, dict):
                _rm = str(_ra.get('maze_id', ''))
                if _rm in _remaining:
                    try:
                        out[_rm] = (int(_ra.get('size', config.MIN_MAZE_SIZE)), _bid)
                    except Exception:
                        continue
                    _remaining.discard(_rm)
        return out

    async def _proven_update_size(self, maze_id: str, upto_id: int, _proven_base: dict=None):
        if _proven_base is not None:
            return _proven_base.get(maze_id)
        try:
            _mid = str(maze_id or '')
            if not _mid:
                return None
            _upto = int(upto_id)
        except (TypeError, ValueError):
            return None
        try:
            if self.db.db_type == 'sqlite':
                _rows = await self.db.fetch('SELECT id, proof FROM blocks WHERE id < ? AND proof IS NOT NULL ORDER BY id DESC LIMIT 500', _upto)
            else:
                _rows = await self.db.fetch('SELECT id, proof FROM blocks WHERE id < $1 AND proof IS NOT NULL ORDER BY id DESC LIMIT 500', _upto)
        except Exception:
            return None
        for _r in _rows or []:
            try:
                _rp = _r.get('proof')
                if isinstance(_rp, str):
                    _rp = bootstrap.json.loads(_rp or '{}')
                if not isinstance(_rp, dict):
                    continue
            except Exception:
                continue
            for _u in reversed(list(_rp.get('maze_updates') or [])):
                if not isinstance(_u, dict):
                    continue
                _um = str(_u.get('maze_id') or _u.get('miner_id') or '')
                if _um != _mid:
                    continue
                _sz = maze._valid_maze_size(_u.get('new_size'))
                if _sz is not None:
                    return _sz
        return None

    async def execute_transaction(self, tx_data: bootstrap.Dict, block_id: int, block_ts: float=None) -> bootstrap.Tuple[bool, bootstrap.Dict]:
        if block_ts is None:
            bootstrap.logger.warning('[Execute] execute_transaction called without block_ts; refusing (no clock on the validity path)')
            return (False, {'error': 'block_ts is required'})
        tx_data = bootstrap.copy.deepcopy(tx_data)
        if 'timestamp' not in tx_data:
            tx_data['timestamp'] = bootstrap.time.time()
        if 'fee' not in tx_data:
            tx_data['fee'] = 0
        try:
            tx_data['_fee_charged'] = int(tx_data.get('fee', 0))
        except (TypeError, ValueError):
            tx_data['_fee_charged'] = 0
        if not self._verify_tx_signature(tx_data):
            return (False, {'error': 'Invalid signature'})
        if tx_data.get('tx_type') == 'token_transfer':
            _tt_fee = gas.token_transfer_fee(tx_data)
            if int(tx_data.get('fee', 0) or 0) != _tt_fee:
                return (False, {'error': f'token transfer fee must equal {_tt_fee} (canonical bytes x rate)'})
        if tx_data.get('tx_type') == 'token_burn':
            _tb_fee = gas.token_burn_fee(tx_data)
            if int(tx_data.get('fee', 0) or 0) != _tb_fee:
                return (False, {'error': f'token burn fee must equal {_tb_fee} (canonical bytes x rate)'})
        tx_hash = tx_data.get('tx_hash')
        existing = await self.tx_repo.get_by_hash(tx_hash) if tx_hash else None
        if existing and existing.get('status') != 'pending':
            if existing.get('block_id') == block_id:
                return (True, {'result': 'already executed in failed attempt at this height', 'fee_charged': int(existing.get('_fee_charged', existing.get('fee', 0)) or 0), 'gas_used': int(existing.get('_gas_used', 0) or 0)})
            return (False, {'error': f'Duplicate transaction {tx_hash[:16]}'})
        from_wallet = tx_data.get('from_wallet')
        if from_wallet:
            confirmed_nonce = await self._get_confirmed_nonce(from_wallet)
            if tx_data.get('nonce', 0) != confirmed_nonce:
                return (False, {'error': f'Nonce mismatch: expected {confirmed_nonce}, got {tx_data.get('nonce', 0)}'})
        if svf.svf_active_at(block_id):
            tx_type = tx_data.get('tx_type', 'send')
            if tx_type in ('token_create', 'token_transfer', 'token_burn'):
                token_addr = tx_data.get('token_address') or ''
                if token_addr:
                    tok = token_addr.lower()
                    if tok.startswith('0x'):
                        tok = tok[2:]
                    profile = self.svf_profiles.get(tok)
                    if profile is not None:
                        _mature = (int(block_id) - 100 - 100) // svf.SVF_EPOCH_BLOCKS
                        if _mature < 0:
                            return (False, {'error': f'SVF unavailable for token {token_addr[:16]}... (no mature epoch at block {block_id})'})
                        epoch_id = _mature
                        records = self.svf_evidence_store.get(epoch_id, [])
                        cert = self.svf_certificates.get(epoch_id)
                        epoch_root_entry = self.svf_epoch_roots.get(epoch_id)
                        epoch_root = None
                        if isinstance(epoch_root_entry, (tuple, list)) and len(epoch_root_entry) >= 1:
                            _er = epoch_root_entry[0]
                            epoch_root = _er if isinstance(_er, bytes) else bytes.fromhex(_er)
                        try:
                            _prof_bytes = svf.svf_profile_bytes(profile)
                            _prof_hash = svf.svf_profile_hash(int(config.CHAIN_ID), tok, _prof_bytes)
                        except svf.SVFReject:
                            return (False, {'error': f'SVF profile invalid for token {token_addr[:16]}...'})
                        verdict = svf.evaluate_profile(profile, records, int(block_id), challenge_seed=None, epoch_root=epoch_root, certificate=cert, chain_id=int(config.CHAIN_ID), token_address=tok, profile_hash=_prof_hash, prune_blocks=100)
                        if verdict == 'FAIL':
                            return (False, {'error': f'SVF state root FAIL for token {token_addr[:16]}... in epoch {epoch_id}'})
                        if verdict == 'UNAVAILABLE':
                            return (False, {'error': f'SVF unavailable for token {token_addr[:16]}... in epoch {epoch_id}'})
        val = int(tx_data.get('value', 0))
        fee = int(tx_data.get('fee', 0))
        if val < 0 or fee < 0:
            return (False, {'error': 'Value and fee must be non-negative'})
        tx_type = tx_data.get('tx_type', 'send')
        if tx_type == 'token_create':
            owner = tx_data.get('from_wallet')
            d = tx_data.get('data') or {}
            name = d.get('name')
            symbol = d.get('symbol')
            total_supply = int(d.get('total_supply', 0))
            decimals = int(d.get('decimals', 18))
            burnable = bool(d.get('burnable', True))
            temporal_config = d.get('temporal_config') or {}
            if not gas._temporal_fee_ok(temporal_config):
                return (False, {'error': f'burn_fee_bps must be 0..{gas.MAX_TOKEN_BURN_BPS}'})
            if not name or len(name) < 3 or len(name) > 32:
                return (False, {'error': 'Invalid name length'})
            if not symbol or len(symbol) < 2 or len(symbol) > 10:
                return (False, {'error': 'Invalid symbol length'})
            if total_supply <= 0 or total_supply > config.TOKEN_MAX_SUPPLY:
                return (False, {'error': 'Invalid supply'})
            fee_floor = gas.get_token_creation_fee(0)
            if fee < fee_floor:
                return (False, {'error': f'Insufficient fee: need {fee_floor}'})
            balance = await self.balance_repo.get(owner)
            if balance < fee_floor:
                return (False, {'error': f'Insufficient balance: need {fee_floor // config.SUBS} MCX'})
            try:
                token_address = util._derive_token_address(tx_hash, owner, name, symbol)
            except Exception as _de:
                bootstrap.logger.warning(f'[Execute] token_create address derivation failed for {str(tx_hash or '?')[:16]}: {str(_de or '?')[:16]}')
                return (False, {'error': f'token address derivation failed: {str(_de or '?')[:64]}'})
            await self.balance_repo.subtract(owner, fee_floor)
            tx_data['_fee_charged'] = fee_floor
            tx_data['_gas_used'] = 0
            token = {'address': token_address, 'name': name, 'symbol': symbol, 'owner': owner, 'total_supply': total_supply * config.SUBS, 'decimals': decimals, 'created_at': float(tx_data.get('timestamp', 0)), 'fee_paid': fee_floor, 'mintable': True, 'burnable': burnable, 'mining_type': '', 'mining_reward': 0, 'mining_interval': 1, 'mining_difficulty': 1, 'stake_threshold': 0, 'last_mined_block': 0, 'total_mined': 0, 'max_mineable_supply': config.TOKEN_MAX_MINEABLE_SUPPLY}
            await self.token_repo.create(token)
            await self.token_balance_repo.set(token_address, owner, total_supply * config.SUBS)
            if temporal_config:
                await self.contract_state_repo.set(token_address, 'temporal_config', bootstrap.json.dumps(temporal_config))
            self.tokens[token_address] = token
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = 0
            tx_data['token_address'] = token_address
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': 0, 'logs': [], 'contract_address': token_address, 'result': 'success'}
            await self.receipt_repo.create(receipt)
            return (True, {'result': 'success', 'address': token_address, 'fee_charged': fee_floor, 'gas_used': 0})
        if tx_type == 'send':
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet')
            if not crypto._valid_wallet(from_wallet) or not crypto._valid_wallet(to_wallet):
                return (False, {'error': 'invalid from_wallet or to_wallet'})
            if from_wallet.lower() == to_wallet.lower():
                return (False, {'error': 'self-transfer not allowed'})
            amount = int(tx_data.get('value', 0))
            _send_gas = gas._gas_intrinsic(tx_data)
            _send_gp = gas._gas_price_of(tx_data)
            _send_fee = _send_gas * _send_gp
            if _send_fee > int(tx_data.get('fee', 0)):
                return (False, {'error': f'gas cost {_send_fee} exceeds tx fee cap {int(tx_data.get('fee', 0))}'})
            total = amount + _send_fee
            balance = await self.balance_repo.get(from_wallet)
            if balance < total:
                return (False, {'error': 'Insufficient balance'})
            await self.balance_repo.subtract(from_wallet, total)
            tx_data['_fee_charged'] = _send_fee
            tx_data['_gas_used'] = _send_gas
            if to_wallet and to_wallet.lower() in config.BURN_ADDRESSES:
                self.burned_total += amount
                await self.network_state_repo.set('burned_total', str(self.burned_total))
                bootstrap.logger.info(f'[BURN] {amount // config.SUBS} MCX sent to burn address {to_wallet}. Total burned: {self.burned_total // config.SUBS} MCX')
            else:
                await self.balance_repo.add(to_wallet, amount)
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': _send_gas, 'logs': [], 'contract_address': '', 'result': 'success'}
            await self.receipt_repo.create(receipt)
            return (True, {'result': 'success', 'gas_used': _send_gas, 'fee_charged': _send_fee})
        elif tx_type == 'burn':
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet', config.BURN_ADDRESS_ZERO)
            amount = int(tx_data.get('value', 0))
            _burn_gas = gas._gas_intrinsic(tx_data)
            _burn_gp = gas._gas_price_of(tx_data)
            _burn_fee = _burn_gas * _burn_gp
            if _burn_fee > int(tx_data.get('fee', 0)):
                return (False, {'error': f'gas cost {_burn_fee} exceeds tx fee cap {int(tx_data.get('fee', 0))}'})
            total = amount + _burn_fee
            balance = await self.balance_repo.get(from_wallet)
            if balance < total:
                return (False, {'error': 'Insufficient balance'})
            await self.balance_repo.subtract(from_wallet, total)
            tx_data['_fee_charged'] = _burn_fee
            tx_data['_gas_used'] = _burn_gas
            self.burned_total += amount
            await self.network_state_repo.set('burned_total', str(self.burned_total))
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': _burn_gas, 'logs': [{'event': 'CoinBurned', 'burner': from_wallet, 'amount': amount, 'burned_total': self.burned_total}], 'contract_address': '', 'result': 'burned'}
            await self.receipt_repo.create(receipt)
            bootstrap.logger.info(f'[BURN] {amount // config.SUBS} MCX burned by {from_wallet[:16]}. Total burned: {self.burned_total // config.SUBS} MCX')
            return (True, {'result': 'burned', 'burned_total': self.burned_total, 'gas_used': _burn_gas, 'fee_charged': _burn_fee})
        elif tx_type == 'token_transfer':
            token_addr = tx_data.get('token_address')
            if not token_addr:
                return (False, {'error': 'Missing token address'})
            token = await self.token_repo.get(token_addr)
            if not token:
                return (False, {'error': 'Token not found'})
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet')
            amount = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(from_wallet)
            if mcx_balance < fee:
                return (False, {'error': 'Insufficient balance for fee'})
            now = block_ts
            temporal_config = await self.get_token_temporal_config(token_addr)
            if temporal_config:
                trading_starts_at = temporal_config.get('trading_starts_at', 0)
                if trading_starts_at > 0 and now < trading_starts_at and (from_wallet != token.get('owner')):
                    return (False, {'error': f'Trading locked until timestamp {trading_starts_at} ({int(trading_starts_at - now)}s remaining)'})
                cooldown = temporal_config.get('transfer_cooldown_seconds', 0)
                if cooldown > 0 and from_wallet != token.get('owner'):
                    last_tx_time_str = await self.contract_state_repo.get(token_addr, f'last_tx_{from_wallet}')
                    if last_tx_time_str:
                        elapsed = now - float(last_tx_time_str)
                        if elapsed < cooldown:
                            return (False, {'error': f'Transfer cooldown active: wait {int(cooldown - elapsed)}s'})
                vesting = temporal_config.get('vesting_schedules', {}).get(from_wallet)
                if vesting:
                    v_total = int(vesting.get('total', 0))
                    v_start = float(vesting.get('start', 0))
                    v_dur = float(vesting.get('duration', 1))
                    if now < v_start:
                        locked = v_total
                    elif now >= v_start + v_dur:
                        locked = 0
                    else:
                        unlocked_ratio = (now - v_start) / v_dur
                        locked = int(v_total * (1.0 - unlocked_ratio))
                    from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
                    if from_bal - amount < locked:
                        return (False, {'error': f'Insufficient unlocked tokens: {locked} locked in vesting'})
            from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
            if from_bal < amount:
                return (False, {'error': 'Insufficient token balance'})
            if fee > 0:
                await self.balance_repo.subtract(from_wallet, fee)
            tx_data['_fee_charged'] = fee
            tx_data['_gas_used'] = 0
            burn_bps = temporal_config.get('burn_fee_bps', 0) if temporal_config else 0
            burn_tax = amount * burn_bps // 10000 if burn_bps > 0 else 0
            net_amount = amount - burn_tax
            tx_data['_burn_tax'] = int(burn_tax)
            await self.token_balance_repo.set(token_addr, from_wallet, from_bal - amount)
            to_bal = await self.token_balance_repo.get(token_addr, to_wallet)
            await self.token_balance_repo.set(token_addr, to_wallet, to_bal + net_amount)
            if burn_tax > 0:
                cur_supply = int(token.get('total_supply', 0))
                token['total_supply'] = max(0, cur_supply - burn_tax)
                await self.token_repo.upsert(token)
                cur_burned = int(await self.contract_state_repo.get(token_addr, 'burned_total') or 0) + burn_tax
                _burned_prev_raw = await self.contract_state_repo.get(token_addr, 'burned_total')
                await self._journal_state_row(block_id, token_addr, 'burned_total', _burned_prev_raw, cur_burned)
                await self.contract_state_repo.set(token_addr, 'burned_total', str(cur_burned))
            if temporal_config and temporal_config.get('transfer_cooldown_seconds', 0) > 0:
                _lt_key = f'last_tx_{from_wallet}'
                try:
                    _lt_old = await self.contract_state_repo.get(token_addr, _lt_key)
                except Exception:
                    _lt_old = None
                await self._journal_state_row(block_id, token_addr, _lt_key, _lt_old, str(now))
                await self.contract_state_repo.set(token_addr, _lt_key, str(now))
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': 0, 'logs': [{'event': 'TokenTransfer', 'token': token_addr, 'from': from_wallet, 'to': to_wallet, 'amount': net_amount, 'burn_tax': burn_tax}], 'contract_address': token_addr, 'result': 'success'}
            await self.receipt_repo.create(receipt)
            return (True, {'result': 'success', 'net_amount': net_amount, 'burn_tax': burn_tax, 'fee_charged': fee, 'gas_used': 0})
        elif tx_type == 'token_burn':
            token_addr = tx_data.get('token_address')
            if not token_addr:
                return (False, {'error': 'Missing token address'})
            token = await self.token_repo.get(token_addr)
            if not token:
                return (False, {'error': 'Token not found'})
            from_wallet = tx_data.get('from_wallet')
            amount = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(from_wallet)
            if mcx_balance < fee:
                return (False, {'error': 'Insufficient balance for fee'})
            from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
            if from_bal < amount:
                return (False, {'error': 'Insufficient token balance'})
            if fee > 0:
                await self.balance_repo.subtract(from_wallet, fee)
            tx_data['_fee_charged'] = fee
            tx_data['_gas_used'] = 0
            await self.token_balance_repo.set(token_addr, from_wallet, from_bal - amount)
            new_supply = max(0, int(token.get('total_supply', 0)) - amount)
            token['total_supply'] = new_supply
            await self.token_repo.upsert(token)
            cur_token_burned = int(await self.contract_state_repo.get(token_addr, 'burned_total') or 0) + amount
            await self.contract_state_repo.set(token_addr, 'burned_total', str(cur_token_burned))
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            if not tx_data.get('to_wallet'):
                tx_data['to_wallet'] = config.BURN_ADDRESS_ZERO
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': 0, 'logs': [{'event': 'TokenBurned', 'token': token_addr, 'burner': from_wallet, 'amount': amount}], 'contract_address': token_addr, 'result': 'token_burned'}
            await self.receipt_repo.create(receipt)
            return (True, {'result': 'token_burned', 'token': token_addr, 'burned': amount, 'total_supply': new_supply, 'fee_charged': fee, 'gas_used': 0})
        elif tx_type == 'contract_deploy':
            init_code_hex = util.tx_data_to_hex(tx_data.get('bytecode')) or util.tx_data_to_hex(tx_data.get('data'))
            if init_code_hex.startswith('0x'):
                init_code_hex = init_code_hex[2:]
            abi = tx_data.get('abi', {})
            if not init_code_hex:
                return (False, {'error': 'Missing bytecode'})
            if len(init_code_hex) > config.MAX_BYTECODE * 2:
                return (False, {'error': 'Bytecode too large'})
            nonce = tx_data.get('nonce', 0)
            contract_address = util.compute_contract_address(tx_data['from_wallet'], nonce)
            value = tx_data.get('value', 0)
            gas_limit = gas._gas_ceiling(tx_data.get('gas', config.GAS_LIMIT_DEFAULT))
            _dep_intrinsic = gas._gas_intrinsic(tx_data)
            _dep_gp = gas._gas_price_of(tx_data)
            if _dep_intrinsic > gas_limit:
                return (False, {'error': f'out of gas: intrinsic {_dep_intrinsic} exceeds gas limit {gas_limit}', 'gas_used': gas_limit})
            if self.vm_manager is None:
                return (False, {'error': 'VM manager not initialized'})
            _b3_fee = int(tx_data.get('fee', 0) or 0)
            if _b3_fee > 0:
                try:
                    _b3_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _b3_bal = 0
                if int(_b3_bal or 0) < _b3_fee:
                    return (False, {'error': 'Insufficient balance for fee'})
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_fee)
            _b3_value = int(tx_data.get('value', 0) or 0)
            if _b3_value > 0:
                try:
                    _v_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _v_bal = 0
                if int(_v_bal or 0) < _b3_value:
                    if _b3_fee > 0:
                        await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                    return (False, {'error': 'Insufficient balance for value'})
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_value)
                tx_data['_value_moved'] = _b3_value
            success, return_data, gas_used, logs = await self.vm_manager.execute(contract_address, caller=tx_data['from_wallet'], origin=tx_data['from_wallet'], value=value, gas_limit=gas_limit - _dep_intrinsic, input_data=b'', static=False, init_code_hex=init_code_hex, block_id=block_id, block_ts=block_ts)
            if not success:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                if _b3_fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                return (False, {'error': 'Constructor execution failed', 'result': return_data.hex()})
            runtime_bytecode = return_data.hex() if return_data else ''
            if not runtime_bytecode:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                if _b3_fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                return (False, {'error': 'Constructor did not return runtime bytecode'})
            if len(runtime_bytecode) > config.MAX_BYTECODE * 2:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                if _b3_fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                return (False, {'error': f'Runtime bytecode exceeds MAX_BYTECODE ({config.MAX_BYTECODE} bytes)'})
            _dep_code_deposit = len(runtime_bytecode) // 2 * config.GAS_CODE_DEPOSIT_PER_BYTE
            _dep_total_gas = _dep_intrinsic + int(gas_used) + _dep_code_deposit
            if _dep_total_gas > gas_limit:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                if _b3_fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                return (False, {'error': 'out of gas: code deposit exceeds gas limit', 'gas_used': gas_limit})
            _dep_fee = _dep_total_gas * _dep_gp
            if _dep_fee > _b3_fee:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                if _b3_fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                return (False, {'error': f'gas cost {_dep_fee} exceeds tx fee cap {_b3_fee}'})
            if _b3_fee > _dep_fee:
                await self.balance_repo.add(tx_data['from_wallet'], _b3_fee - _dep_fee)
            tx_data['_fee_charged'] = _dep_fee
            tx_data['_gas_used'] = _dep_total_gas
            if _b3_value > 0:
                await self.balance_repo.add(contract_address, _b3_value)
            code_hash = bootstrap.hashlib.sha256(bytes.fromhex(runtime_bytecode)).hexdigest()
            if not isinstance(abi, str):
                abi = bootstrap.json.dumps(abi)
            await self.contract_v2_repo.create({'address': contract_address, 'owner': tx_data['from_wallet'], 'bytecode': runtime_bytecode, 'abi': abi, 'created_at': bootstrap.time.time(), 'tx_hash': tx_data['tx_hash'], 'storage_root': '', 'code_hash': code_hash})
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            if '_signed_to_wallet' not in tx_data:
                tx_data['_signed_to_wallet'] = str(tx_data.get('to_wallet') or '')
            tx_data['to_wallet'] = contract_address
            tx_data['amount'] = value
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1 if success else 0, 'gas_used': _dep_total_gas, 'logs': logs, 'contract_address': contract_address, 'result': 'deployed'}
            await self.receipt_repo.create(receipt)
            return (True, {'result': 'deployed', 'contract_address': contract_address, 'gas_used': _dep_total_gas, 'fee_charged': _dep_fee})
        elif tx_type == 'contract_call':
            contract_addr = tx_data.get('to_wallet')
            if not contract_addr:
                return (False, {'error': 'Missing contract address'})
            contract = await self.contract_v2_repo.get(contract_addr)
            if not contract:
                return (False, {'error': 'Contract not found'})
            raw_input = tx_data.get('data')
            if raw_input is None:
                raw_input = tx_data.get('input', b'')
            input_data = raw_input if isinstance(raw_input, bytes) else util.tx_data_to_bytes(raw_input)
            value = tx_data.get('value', 0)
            gas_limit = gas._gas_ceiling(tx_data.get('gas', config.GAS_LIMIT_DEFAULT))
            _call_intrinsic = gas._gas_intrinsic(tx_data)
            _call_gp = gas._gas_price_of(tx_data)
            if _call_intrinsic > gas_limit:
                return (False, {'error': f'out of gas: intrinsic {_call_intrinsic} exceeds gas limit {gas_limit}', 'gas_used': gas_limit})
            _b3_fee = int(tx_data.get('fee', 0) or 0)
            if _b3_fee < gas_limit * _call_gp:
                return (False, {'error': 'fee field below gas limit x gasPrice'})
            if _b3_fee > 0:
                try:
                    _b3_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _b3_bal = 0
                if int(_b3_bal or 0) < _b3_fee:
                    return (False, {'error': 'Insufficient balance for fee'})
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_fee)
            _b3_value = int(tx_data.get('value', 0) or 0)
            if _b3_value > 0:
                try:
                    _v_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _v_bal = 0
                if int(_v_bal or 0) < _b3_value:
                    if _b3_fee > 0:
                        await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
                    return (False, {'error': 'Insufficient balance for value'})
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_value)
                tx_data['_value_moved'] = _b3_value
            success, return_data, gas_used, logs = await self.vm_manager.execute(contract_addr, caller=tx_data['from_wallet'], origin=tx_data['from_wallet'], value=value, gas_limit=gas_limit - _call_intrinsic, input_data=input_data, static=False, block_id=block_id, block_ts=block_ts)
            if _b3_value > 0:
                if success:
                    await self.balance_repo.add(contract_addr, _b3_value)
                else:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
            if _b3_fee > 0 and (not success):
                await self.balance_repo.add(tx_data['from_wallet'], _b3_fee)
            _call_total_gas = _call_intrinsic + int(gas_used)
            if _call_total_gas > gas_limit:
                _call_total_gas = gas_limit
            _call_fee = 0
            if success:
                _call_fee = _call_total_gas * _call_gp
                if _b3_fee > _call_fee:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_fee - _call_fee)
            tx_data['_fee_charged'] = _call_fee
            tx_data['_gas_used'] = _call_total_gas
            tx_data['status'] = 'confirmed' if success else 'failed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = value
            raw_data = tx_data.get('data', {})
            if '_signed_data' not in tx_data:
                _d = tx_data.get('data')
                tx_data['_signed_data'] = bootstrap.json.dumps(_d, sort_keys=True) if isinstance(_d, dict) else str(_d or '')
            if not isinstance(raw_data, dict):
                raw_data = {'raw': raw_data}
            raw_data['result'] = return_data.hex()
            raw_data['gas_used'] = gas_used
            tx_data['data'] = raw_data
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1 if success else 0, 'gas_used': _call_total_gas, 'logs': logs, 'contract_address': contract_addr, 'result': return_data.hex()}
            await self.receipt_repo.create(receipt)
            return (success, {'result': return_data.hex(), 'logs': logs, 'gas_used': _call_total_gas, 'fee_charged': _call_fee})
        elif tx_type == 'htlc_create':
            if not config.HTLC_V1_ENABLED:
                return (False, {'error': 'htlc_create disabled in V1 (MCX76-htlc-deferred)'})
            htlc_precompile = '0x0000000000000000000000000000000000000006'
            receiver = tx_data.get('receiver')
            hashlock = tx_data.get('hashlock')
            timelock = tx_data.get('timelock')
            amount = tx_data.get('amount', 0)
            token = tx_data.get('token_address', '0x' + '00' * 20)
            if not all([receiver, hashlock, timelock]):
                return (False, {'error': 'Missing HTLC parameters'})
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(tx_data['from_wallet'])
            if mcx_balance < fee:
                return (False, {'error': 'Insufficient balance for fee'})
            if fee > 0:
                await self.balance_repo.subtract(tx_data['from_wallet'], fee)
            selector = b'\x01\x02\x03\x04'
            receiver_bytes = bytes.fromhex(receiver[2:])
            hashlock_bytes = bytes.fromhex(hashlock[2:]) if hashlock.startswith('0x') else bytes.fromhex(hashlock)
            timelock_bytes = timelock.to_bytes(8, 'big')
            amount_bytes = amount.to_bytes(32, 'big')
            token_bytes = bytes.fromhex(token[2:]) if token.startswith('0x') else bytes.fromhex(token)
            input_data = selector + receiver_bytes + hashlock_bytes + timelock_bytes + amount_bytes + token_bytes
            _htlc_intrinsic = config.GAS_BASE_COST + gas._gas_data_cost(input_data)
            _htlc_gp = gas._gas_price_of(tx_data)
            if _htlc_intrinsic > config.GAS_LIMIT_DEFAULT:
                if fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], fee)
                return (False, {'error': 'out of gas: intrinsic exceeds gas limit', 'gas_used': config.GAS_LIMIT_DEFAULT})
            success, return_data, gas_used, logs = await self.vm_manager.execute(htlc_precompile, caller=tx_data['from_wallet'], origin=tx_data['from_wallet'], value=0, gas_limit=config.GAS_LIMIT_DEFAULT - _htlc_intrinsic, input_data=input_data, static=False, block_id=block_id)
            if success:
                htlc_id = return_data.hex()
                tx_data['status'] = 'confirmed'
                tx_data['block_id'] = block_id
                if '_signed_to_wallet' not in tx_data:
                    tx_data['_signed_to_wallet'] = str(tx_data.get('to_wallet') or '')
                if '_signed_data' not in tx_data:
                    _d = tx_data.get('data')
                    tx_data['_signed_data'] = bootstrap.json.dumps(_d, sort_keys=True) if isinstance(_d, dict) else str(_d or '')
                tx_data['to_wallet'] = htlc_precompile
                tx_data['amount'] = amount
                if not isinstance(tx_data.get('data'), dict):
                    tx_data['data'] = {'raw': tx_data.get('data') or ''}
                tx_data['data']['htlc_id'] = htlc_id
                await self.tx_repo.create(tx_data)
                _htlc_total = _htlc_intrinsic + int(gas_used)
                if _htlc_total > config.GAS_LIMIT_DEFAULT:
                    _htlc_total = config.GAS_LIMIT_DEFAULT
                _htlc_fee = _htlc_total * _htlc_gp
                if _htlc_fee > fee:
                    _htlc_fee = fee
                if fee > _htlc_fee:
                    await self.balance_repo.add(tx_data['from_wallet'], fee - _htlc_fee)
                tx_data['_fee_charged'] = _htlc_fee
                tx_data['_gas_used'] = _htlc_total
                receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': _htlc_total, 'logs': logs, 'contract_address': htlc_precompile, 'result': htlc_id}
                await self.receipt_repo.create(receipt)
                return (True, {'htlc_id': htlc_id, 'gas_used': _htlc_total, 'fee_charged': _htlc_fee})
            else:
                if fee > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], fee)
                return (False, {'error': 'HTLC creation failed'})
        else:
            return (False, {'error': f'Unsupported tx_type: {tx_type}'})

    async def _account_nonce_get(self, wallet: str) -> int:
        if not wallet or self.db is None:
            return 0
        try:
            if self.db.db_type == 'sqlite':
                _v = await self.db.fetchval('SELECT next_nonce FROM account_nonces WHERE wallet = ?', wallet)
            else:
                _v = await self.db.fetchval('SELECT next_nonce FROM account_nonces WHERE wallet = $1', wallet)
            return int(_v) if _v is not None else 0
        except Exception:
            return 0

    async def _account_nonce_note(self, wallet: str, next_nonce: int):
        if not wallet:
            return
        try:
            next_nonce = int(next_nonce)
        except (TypeError, ValueError):
            return
        if next_nonce <= 0:
            return
        try:
            _cur = await self._account_nonce_get(wallet)
            _val = max(_cur, next_nonce)
            if _val == _cur and _cur > 0:
                return
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('INSERT OR REPLACE INTO account_nonces (wallet, next_nonce) VALUES (?, ?)', wallet, _val)
            else:
                await self.db.execute_dml('INSERT INTO account_nonces (wallet, next_nonce) VALUES ($1, $2) ON CONFLICT (wallet) DO UPDATE SET next_nonce = $2', wallet, _val)
        except Exception as _e:
            bootstrap.logger.warning(f'[Nonce] account_nonces store failed for {str(wallet)[:16]}: {_e}')

    async def _account_nonce_rollback(self, wallet: str, nonce: int):
        if not wallet:
            return
        try:
            nonce = int(nonce)
        except (TypeError, ValueError):
            return
        try:
            _cur = await self._account_nonce_get(wallet)
            if _cur <= 0 or _cur <= nonce:
                return
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('INSERT OR REPLACE INTO account_nonces (wallet, next_nonce) VALUES (?, ?)', wallet, nonce)
            else:
                await self.db.execute_dml('INSERT INTO account_nonces (wallet, next_nonce) VALUES ($1, $2) ON CONFLICT (wallet) DO UPDATE SET next_nonce = $2', wallet, nonce)
        except Exception as _e:
            bootstrap.logger.error(f'[Nonce] account_nonces rollback failed for {str(wallet)[:16]} nonce {nonce}: {_e}')

    async def _get_confirmed_nonce(self, wallet: str) -> int:
        _db_nonce = await self._get_confirmed_nonce_at(wallet, None)
        _mem_nonce = 0
        try:
            _mp = getattr(self, 'mempool', None)
            _cn = getattr(_mp, '_confirmed_nonces', None) if _mp is not None else None
            if isinstance(_cn, dict) and wallet:
                _mem_nonce = int(_cn.get(wallet, 0) or 0)
        except Exception:
            _mem_nonce = 0
        _acct_nonce = 0
        try:
            _acct_nonce = int(await self._account_nonce_get(wallet) or 0)
        except Exception:
            _acct_nonce = 0
        return max(int(_db_nonce or 0), int(_mem_nonce or 0), int(_acct_nonce or 0))

    async def _get_confirmed_nonce_at(self, wallet: str, height=None) -> int:
        if self.db.db_type == 'sqlite':
            query = 'SELECT MAX(nonce) FROM transactions WHERE from_wallet = ? AND block_id >= 0'
            params: list = [wallet]
            if height is not None:
                query += ' AND block_id <= ?'
                params.append(int(height))
        else:
            query = 'SELECT COALESCE(MAX(nonce), -1) FROM transactions WHERE from_wallet = $1 AND block_id >= 0'
            params = [wallet]
            if height is not None:
                query += ' AND block_id <= $2'
                params.append(int(height))
        result = await self.db.fetchval(query, *params)
        return (result if result is not None else -1) + 1

    def _verify_tx_signature(self, tx: bootstrap.Dict) -> bool:
        signature = tx.get('signature', '')
        if isinstance(signature, str) and (signature.startswith('0x') or len(signature) > 130):
            try:
                decoded = util.decode_raw_eth_transaction(signature)
                if not util._raw_chain_id_ok(decoded):
                    return False
                if str(decoded.get('from') or '').lower() != str(tx.get('from_wallet', '')).lower() or str(decoded.get('to') or '').lower() != str(tx.get('to_wallet') or '').lower() or int(decoded.get('value', 0) or 0) != int(tx.get('value', 0) or 0) or (int(decoded.get('nonce', 0) or 0) != int(tx.get('nonce', 0) or 0)) or (int(decoded.get('gas', 0) or 0) != int(tx.get('gas', 0) or 0)) or (int(decoded.get('gasPrice', 0) or 0) != int(tx.get('gasPrice', 0) or 0)) or (str(decoded.get('data') or '').lower() != str(tx.get('data') or '').lower()):
                    return False
                if int(tx.get('fee', 0) or 0) != int(decoded.get('gas', 0) or 0) * int(decoded.get('gasPrice', 0) or 0):
                    return False
                _derived_type = 'contract_deploy' if not (decoded.get('to') or '') else 'contract_call' if decoded.get('data') and len(decoded.get('data')) > 0 else 'send'
                if str(tx.get('tx_type', '')) != _derived_type:
                    return False
                if str(decoded.get('hash', '')).lower() != str(tx.get('tx_hash', '')).lower():
                    return False
                recovered = decoded.get('from', '')
                if recovered and recovered.lower() == tx.get('from_wallet', '').lower():
                    return True
            except Exception as e:
                bootstrap.logger.warning(f'[Verify] Signature decode failed for tx={str(tx.get('tx_hash') or '?')[:16]}: {e}')
        fee_use = tx.get('_signed_fee', tx.get('fee', 0))
        to_use = tx.get('_signed_to_wallet', tx.get('to_wallet', ''))
        message_parts_legacy = [tx.get('from_wallet', ''), to_use, str(tx.get('value', 0)), str(fee_use), str(tx.get('nonce', 0)), str(int(tx.get('timestamp', 0)))]
        message_legacy = ':'.join(message_parts_legacy)
        data_val = tx.get('data', '')
        _signed_data = tx.get('_signed_data')
        if _signed_data is not None and tx.get('tx_type') in ('contract_deploy', 'contract_call', 'htlc_create'):
            data_str = _signed_data
        else:
            data_str = bootstrap.json.dumps(data_val, sort_keys=True) if isinstance(data_val, dict) else str(data_val)
        target = tx.get('contract_address') or tx.get('token_address') or ''
        _type_parts = []
        _msg_tx_type = tx.get('tx_type') or 'send'
        _type_parts.append(f'tx_type={_msg_tx_type}')
        if tx.get('tx_type') in ('contract_deploy', 'contract_call'):
            _vm = util._moved_value_of(tx)
            if _vm:
                _type_parts.append(f'_value_moved={_vm}')
            try:
                _type_parts.append(f'gas={int(tx.get('gas', 0) or 0)}')
            except (TypeError, ValueError):
                _type_parts.append('gas=0')
        if tx.get('tx_type') == 'contract_deploy':
            _bc = util.tx_data_to_hex(tx.get('bytecode', '')) if isinstance(tx.get('bytecode', ''), str) else ''
            _type_parts.append(f'bytecode={_bc}')
            _abi = tx.get('abi', {})
            try:
                _type_parts.append(f'abi={(crypto.canonical_json_bytes(_abi).decode('utf-8') if isinstance(_abi, (dict, list)) else str(_abi))}')
            except Exception:
                _type_parts.append(f'abi={str(_abi)}')
        if tx.get('tx_type') == 'htlc_create':
            for _hf in ('receiver', 'hashlock', 'timelock', 'amount'):
                _type_parts.append(f'htlc_{_hf}={tx.get(_hf, '')}')
        message_parts_full = [str(config.CHAIN_ID), tx.get('from_wallet', ''), to_use, str(tx.get('value', 0)), str(fee_use), str(tx.get('nonce', 0)), str(int(tx.get('timestamp', 0))), target, data_str] + _type_parts
        message_full = ':'.join(message_parts_full)
        pub_key = tx.get('pub_key')
        if pub_key:
            try:
                if util.pubkey_to_address(pub_key).lower() != tx.get('from_wallet', '').lower():
                    return False
            except Exception:
                return False
            if tx.get('tx_type') == 'token_create':
                d = tx.get('data') or {}
                _fee = tx.get('_signed_fee', tx.get('fee', 0))
                try:
                    _tc = crypto.canonical_json_bytes(d.get('temporal_config') or {}).decode('utf-8')
                except Exception:
                    _tc = '{}'
                msg_create = f'{config.CHAIN_ID}:create_token:{tx.get('from_wallet', '')}:{d.get('name', '')}:{d.get('symbol', '')}:{d.get('total_supply', 0)}:{d.get('decimals', 18)}:{int(bool(d.get('burnable', True)))}:{int(tx.get('nonce', 0))}:{int(_fee or 0)}:{int(tx.get('timestamp', 0))}:{_tc}'
                return crypto.verify_signature(pub_key, msg_create, signature)
            tx_type = tx.get('tx_type') or 'send'
            allow_legacy = tx_type in ('send', 'burn') and (not tx.get('data')) and (not tx.get('contract_address')) and (not tx.get('token_address'))
            if crypto.verify_signature(pub_key, message_full, signature) or (allow_legacy and crypto.verify_signature(pub_key, message_legacy, signature)):
                return True
        for m in self.miners.values():
            if m.get('wallet') == tx.get('from_wallet'):
                tx_type = tx.get('tx_type') or 'send'
                allow_legacy = tx_type in ('send', 'burn') and (not tx.get('data')) and (not tx.get('contract_address')) and (not tx.get('token_address'))
                if crypto.verify_signature(m['pub'], message_full, signature) or (allow_legacy and crypto.verify_signature(m['pub'], message_legacy, signature)):
                    return True
        return False

    async def _submit_pool_tx(self, tx_data: bootstrap.Dict) -> bootstrap.Tuple[int, bootstrap.Dict]:
        if not self._verify_tx_signature(tx_data):
            return (401, {'success': False, 'error': 'Invalid signature'})
        from_wallet = tx_data.get('from_wallet')
        try:
            _sn, _sf = (int(tx_data.get('nonce', 0)), int(tx_data.get('fee', 0)))
        except (TypeError, ValueError):
            return (400, {'success': False, 'error': 'nonce/fee must be ints'})
        if from_wallet:
            expected = max(await self._get_confirmed_nonce(from_wallet), self.mempool.get_nonce(from_wallet))
            if _sn != expected:
                return (400, {'success': False, 'error': f'Nonce mismatch: expected {expected}, got {tx_data.get('nonce', 0)}'})
        if tx_data.get('tx_type', 'send') == 'send':
            if not crypto._valid_wallet(tx_data.get('from_wallet')) or not crypto._valid_wallet(tx_data.get('to_wallet')):
                return (400, {'success': False, 'error': 'invalid from_wallet or to_wallet'})
            if str(tx_data.get('from_wallet')).lower() == str(tx_data.get('to_wallet')).lower():
                return (400, {'success': False, 'error': 'self-transfer not allowed'})
        if str(tx_data.get('tx_type', 'send')) == 'token_transfer' and int(_sf) != int(gas.token_transfer_fee(tx_data)):
            return (400, {'success': False, 'error': f'token transfer fee must equal {gas.token_transfer_fee(tx_data)}'})
        if str(tx_data.get('tx_type', 'send')) == 'token_burn' and int(_sf) != int(gas.token_burn_fee(tx_data)):
            return (400, {'success': False, 'error': f'token burn fee must equal {gas.token_burn_fee(tx_data)}'})
        if not await self.mempool.add(tx_data):
            return (503, {'success': False, 'error': 'Mempool full or invalid'})
        if self.p2p:
            await self.p2p.broadcast_transaction(tx_data)
        return (200, {'success': True, 'pending': True, 'tx_hash': tx_data.get('tx_hash')})

    async def _replay_transactions(self, tx_list: list, block_id: int=None, block_ts: float=None, _branch_state=None) -> bool:
        if block_ts is None:
            bootstrap.logger.warning('[Verify] _replay_transactions called without block_ts; refusing (no clock on the validity path)')
            return False
        if isinstance(_branch_state, dict):
            shadow_balances = _branch_state.setdefault('balances', {})
            shadow_token_balances = _branch_state.setdefault('token', {})
            shadow_storage = _branch_state.setdefault('storage', {})
        else:
            shadow_balances: bootstrap.Dict[str, int] = {}
            shadow_token_balances: bootstrap.Dict[tuple, int] = {}
            shadow_last_tx: bootstrap.Dict[tuple, float] = {}
            shadow_storage: bootstrap.Dict[str, bootstrap.Dict[str, int]] = {}
        _sp_cache: dict = {}

        async def _get_bal(wallet: str) -> int:
            if wallet in shadow_balances:
                return int(shadow_balances[wallet])
            return int(await self.balance_repo.get(wallet))
        for tx_data in tx_list:
            if tx_data.get('tx_type') == 'token_transfer':
                _rtt = gas.token_transfer_fee(tx_data)
                if int(tx_data.get('fee', 0) or 0) != _rtt:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token transfer fee must be {_rtt} for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                    return False
            if tx_data.get('tx_type') == 'token_burn':
                _rbt = gas.token_burn_fee(tx_data)
                if int(tx_data.get('fee', 0) or 0) != _rbt:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token burn fee must be {_rbt} for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                    return False
            tx_type = tx_data.get('tx_type', 'send')
            val = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            from_w = tx_data.get('from_wallet', '')
            to_w = tx_data.get('to_wallet', '')
            _txh = tx_data.get('tx_hash')
            if _txh:
                _existing = await self.tx_repo.get_by_hash(_txh)
                if _existing and int(_existing.get('block_id', -1)) >= 0:
                    continue
            if tx_type == 'send' and (not crypto._valid_wallet(from_w) or not crypto._valid_wallet(to_w) or from_w.lower() == to_w.lower()):
                bootstrap.logger.warning(f'[Verify] Shadow re-exec: invalid send endpoints for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                return False
            if tx_type in ('send', 'burn'):
                _sh_fee = gas._gas_intrinsic(tx_data) * gas._gas_price_of(tx_data)
                if int(tx_data.get('_fee_charged', tx_data.get('fee', 0)) or 0) != _sh_fee:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: fee mismatch for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                    return False
                total = val + _sh_fee
                current = await _get_bal(from_w)
                if current < total:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance ({current} < {total})')
                    return False
                shadow_balances[from_w] = current - total
                if tx_type == 'send' and to_w:
                    to_current = await _get_bal(to_w)
                    shadow_balances[to_w] = to_current + val
            elif tx_type == 'token_transfer':
                token_addr = tx_data.get('token_address', '')
                amount = val
                if fee > 0:
                    _cb = await _get_bal(from_w)
                    if _cb < fee:
                        bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for token fee')
                        return False
                    shadow_balances[from_w] = _cb - fee
                _tcfg = await self.get_token_temporal_config(token_addr)
                _lt_pending = None
                if _tcfg:
                    _now = block_ts
                    _tstart = _tcfg.get('trading_starts_at', 0)
                    _owner = (await self.token_repo.get(token_addr) or {}).get('owner')
                    if _tstart > 0 and _now < _tstart and (from_w != _owner):
                        bootstrap.logger.warning(f'[Verify] Shadow re-exec: trading locked')
                        return False
                    _cd = _tcfg.get('transfer_cooldown_seconds', 0)
                    _lt_pending = float(_now) if _cd > 0 else None
                    if _cd > 0 and from_w != _owner:
                        _lt = shadow_last_tx[token_addr, from_w] if (token_addr, from_w) in shadow_last_tx else await self.contract_state_repo.get(token_addr, f'last_tx_{from_w}')
                        if _lt and _now - float(_lt) < _cd:
                            bootstrap.logger.warning(f'[Verify] Shadow re-exec: cooldown active')
                            return False
                    _v = (_tcfg.get('vesting_schedules', {}) or {}).get(from_w)
                    if _v:
                        _vt, _vs, _vd = (int(_v.get('total', 0)), float(_v.get('start', 0)), float(_v.get('duration', 1)))
                        _locked = _vt if _now < _vs else 0 if _now >= _vs + _vd else int(_vt * (1.0 - (_now - _vs) / _vd))
                        _fb = shadow_token_balances[token_addr, from_w] if (token_addr, from_w) in shadow_token_balances else await self.token_balance_repo.get(token_addr, from_w)
                        if _fb - amount < _locked:
                            bootstrap.logger.warning(f'[Verify] Shadow re-exec: vesting locked')
                            return False
                try:
                    _bbps = int((_tcfg or {}).get('burn_fee_bps', 0) or 0)
                except (TypeError, ValueError):
                    _bbps = 0
                _btax = amount * _bbps // 10000 if _bbps > 0 else 0
                _net = amount - _btax
                key_from = (token_addr, from_w)
                if key_from in shadow_token_balances:
                    current_from = shadow_token_balances[key_from]
                else:
                    current_from = await self.token_balance_repo.get(token_addr, from_w)
                if current_from < amount:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token transfer insufficient balance')
                    return False
                shadow_token_balances[key_from] = current_from - amount
                key_to = (token_addr, to_w)
                if key_to in shadow_token_balances:
                    current_to = shadow_token_balances[key_to]
                else:
                    current_to = await self.token_balance_repo.get(token_addr, to_w)
                shadow_token_balances[key_to] = current_to + _net
                if _lt_pending is not None:
                    shadow_last_tx[token_addr, from_w] = _lt_pending
            elif tx_type == 'token_burn':
                token_addr = tx_data.get('token_address', '')
                amount = val
                if fee > 0:
                    _cb = await _get_bal(from_w)
                    if _cb < fee:
                        bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for burn fee')
                        return False
                    shadow_balances[from_w] = _cb - fee
                key_from = (token_addr, from_w)
                if key_from in shadow_token_balances:
                    current_from = shadow_token_balances[key_from]
                else:
                    current_from = await self.token_balance_repo.get(token_addr, from_w)
                if current_from < amount:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token burn insufficient balance')
                    return False
                shadow_token_balances[key_from] = current_from - amount
            elif tx_type in ('contract_deploy', 'contract_call', 'htlc_create'):
                if fee > 0:
                    current = await _get_bal(from_w)
                    if current < fee:
                        bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for contract fee')
                        return False
                    shadow_balances[from_w] = current - fee
                if tx_type == 'htlc_create':
                    if not config.HTLC_V1_ENABLED:
                        bootstrap.logger.warning('[Verify] Shadow re-exec: htlc_create disabled')
                        return False
                    continue
                vm = self.vm_manager
                if vm is None:
                    bootstrap.logger.warning('[Verify] VM manager unavailable — contract re-execution skipped')
                    continue
                value = int(tx_data.get('value', 0))
                gas_limit = gas._gas_ceiling(tx_data.get('gas', config.GAS_LIMIT_DEFAULT))
                _sh_intrinsic = gas._gas_intrinsic(tx_data)
                _sh_gp = gas._gas_price_of(tx_data)
                _sh_vm_budget = gas_limit - _sh_intrinsic
                if _sh_vm_budget < 0:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: intrinsic {_sh_intrinsic} exceeds gas limit {gas_limit}')
                    return False
                input_data = util.tx_data_to_bytes(tx_data.get('data'))
                if not input_data and tx_data.get('input') is not None:
                    input_data = util.tx_data_to_bytes(tx_data.get('input'))
                try:
                    if tx_type == 'contract_deploy':
                        exec_addr = util.compute_contract_address(from_w, int(tx_data.get('nonce', 0)))
                        code_hex = util.tx_data_to_hex(tx_data.get('bytecode')) or util.tx_data_to_hex(tx_data.get('data'))
                        if not code_hex:
                            bootstrap.logger.warning(f'[Verify] contract_deploy {tx_data.get('tx_hash', '')[:16]} missing bytecode')
                            return False
                        input_hex = ''
                    else:
                        exec_addr = tx_data.get('to_wallet')
                        contract = await vm.contract_v2_repo.get(exec_addr)
                        if not contract:
                            bootstrap.logger.warning(f'[Verify] contract_call to unknown contract {str(exec_addr)[:16]}')
                            return False
                        code_hex = contract['bytecode']
                        input_hex = input_data.hex()
                    if exec_addr in shadow_storage:
                        storage_cache = dict(shadow_storage[exec_addr])
                    else:
                        storage_rows = await vm.contract_storage_v2_repo.get_all(exec_addr)
                        storage_cache = {key: int(val) for key, val in storage_rows.items()}
                        shadow_storage[exec_addr] = dict(storage_cache)
                    if not vm._code_cache_valid:
                        all_contracts = await vm.contract_v2_repo.get_all()
                        vm._code_cache = {c['address']: bytes.fromhex(c['bytecode']) for c in all_contracts}
                        vm._code_cache_valid = True
                    balance_cache = {}
                    for addr in {from_w, exec_addr}:
                        if addr:
                            balance_cache[addr] = await self.balance_repo.get(addr)
                    _shadow_v = int(value or 0)
                    _shadow_v0 = None
                    if _shadow_v > 0:
                        _shadow_v0 = await _get_bal(from_w)
                        if _shadow_v0 < _shadow_v:
                            bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for value')
                            return False
                        shadow_balances[from_w] = _shadow_v0 - _shadow_v
                        if from_w:
                            balance_cache[from_w] = _shadow_v0 - _shadow_v
                    bootstrap.os.environ['MCX_DB_URL'] = vm.db._pg_target_dsn if vm.db.db_type == 'postgres' else 'sqlite://microcore.db'
                    if svf_keys.SVF_KEY_FILE:
                        bootstrap.os.environ['MCX_SVF_FILE'] = svf_keys.SVF_KEY_FILE
                        bootstrap.os.environ['MCX_PRUNE_BLOCKS'] = str(int(config.PRUNE_BLOCKS))
                    loop = bootstrap.asyncio.get_event_loop()
                    _replay_height = block_id if block_id is not None else int(self.height)
                    result = await vm._run_vm_subprocess((code_hex, from_w, from_w, value, _sh_vm_budget, exec_addr, input_hex, False, storage_cache, vm._code_cache, balance_cache, None, None, _replay_height, block_ts), timeout=config.VM_TIMEOUT)
                    success, ret_hex, gas_used, logs, _new_storage, _new_bal, _new_tok = result[:7]
                    if success:
                        _sh_total = _sh_intrinsic + int(gas_used)
                        if tx_type == 'contract_deploy':
                            _sh_rt = bytes.fromhex(ret_hex) if ret_hex else b''
                            _sh_total += len(_sh_rt) * config.GAS_CODE_DEPOSIT_PER_BYTE
                        if _sh_total > gas_limit:
                            _sh_total = gas_limit
                        _sh_fee = _sh_total * _sh_gp
                        if int(tx_data.get('_fee_charged', tx_data.get('fee', 0)) or 0) != _sh_fee:
                            bootstrap.logger.warning(f'[Verify] Shadow re-exec: fee mismatch for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                            return False
                        try:
                            _sh_gu = int(tx_data.get('_gas_used'))
                        except (TypeError, ValueError):
                            _sh_gu = -1
                        if _sh_gu != _sh_total:
                            bootstrap.logger.warning(f'[Verify] Shadow re-exec: gas_used mismatch for tx {str(tx_data.get('tx_hash') or '?')[:16]}')
                            return False
                    if success and isinstance(_new_bal, dict):
                        for _b_addr, _b_val in _new_bal.items():
                            try:
                                shadow_balances[_b_addr] = int(_b_val)
                            except (TypeError, ValueError) as _le:
                                bootstrap.logger.warning(f'[Verify] shadow balance fold skipped addr {str(_b_addr or '?')[:16]}: {str(_le or '?')[:16]}')
                                continue
                    if success and isinstance(_new_tok, dict):
                        for _tk_key, _tk_val in _new_tok.items():
                            if isinstance(_tk_key, (list, tuple)) and len(_tk_key) == 2:
                                try:
                                    shadow_token_balances[tuple(_tk_key)] = int(_tk_val)
                                except (TypeError, ValueError) as _le:
                                    bootstrap.logger.warning(f'[Verify] shadow token-balance fold skipped {str(_tk_key or '?')[:16]}: {str(_le or '?')[:16]}')
                                    continue
                    if success and isinstance(_new_storage, dict):
                        for _s_addr, _slots in _new_storage.items():
                            if isinstance(_slots, dict):
                                _bucket = shadow_storage.setdefault(_s_addr, {})
                                for _sk, _sv in _slots.items():
                                    try:
                                        _bucket[_sk] = int(_sv)
                                    except (TypeError, ValueError) as _le:
                                        bootstrap.logger.warning(f'[Verify] shadow storage fold skipped {str(_s_addr or '?')[:16]}:{str(_sk or '?')[:16]}: {str(_le or '?')[:16]}')
                                        continue
                    if _shadow_v > 0:
                        if success:
                            shadow_balances[exec_addr] = await _get_bal(exec_addr) + _shadow_v
                        else:
                            shadow_balances[from_w] = _shadow_v0
                    if not success:
                        bootstrap.logger.warning(f'[Verify] Contract {('call' if tx_type == 'contract_call' else 'deploy')} failed: {tx_data.get('tx_hash', '')[:16]}')
                        return False
                except Exception as e:
                    bootstrap.logger.warning(f'[Verify] Contract {('call' if tx_type == 'contract_call' else 'deploy')} re-execution failed: {e}')
                    return False
            elif tx_type == 'token_create':
                d = tx_data.get('data') or {}
                fee_floor = gas.get_token_creation_fee(0)
                if fee < fee_floor:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token_create fee {fee} below floor {fee_floor}')
                    return False
                if int(tx_data.get('_fee_charged', tx_data.get('fee', 0)) or 0) != fee_floor:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token_create _fee_charged must be {fee_floor}')
                    return False
                current = await _get_bal(from_w)
                if current < fee_floor:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for token_create fee ({current} < {fee_floor})')
                    return False
                shadow_balances[from_w] = current - fee_floor
                try:
                    _tc_addr = util._derive_token_address(tx_data.get('tx_hash'), from_w, d.get('name'), d.get('symbol'))
                    _tc_key = (_tc_addr, from_w)
                    shadow_token_balances[_tc_key] = shadow_token_balances.get(_tc_key, 0) + int(d.get('total_supply', 0)) * config.SUBS
                except Exception as _de:
                    bootstrap.logger.warning(f'[Verify] Shadow re-exec: token_create address derivation failed for {str(tx_data.get('tx_hash') or '?')[:16]}: {str(_de or '?')[:16]}')
                    return False
            else:
                bootstrap.logger.warning(f"[Verify] Shadow re-exec: unknown tx_type '{tx_type}'")
                return False
        return True

    async def verify_block_proof(self, block: dict, _att_base: dict=None, _maze_base: dict=None, _branch=None, _proven_base: dict=None) -> bool:
        if block.get('id') == 0:
            if genesis._node_genesis_hash:
                return block.get('phash') == '0' * 64 and block.get('hash') == genesis._node_genesis_hash
            return block.get('phash') == '0' * 64 and bool(block.get('state_root'))
        producer_pub = block.get('producer_pub')
        if not producer_pub:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} missing producer_pub — rejecting')
            return False
        if block.get('transactions') is None or block.get('maze_attestation') is None:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} missing proof fields')
            return False
        unsigned_block = {k: v for k, v in block.items() if k not in maze.CONSENSUS_EXCLUDED_FIELDS}
        expected_hash = crypto.hash_block(unsigned_block)
        if block.get('hash') != expected_hash:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} hash mismatch (tampered or corrupt)')
            return False
        if not crypto.verify_signature(producer_pub, bytes.fromhex(block.get('hash', '')), block.get('signature', '')):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} invalid signature')
            return False
        block_ts = block.get('ts', 0)
        if block.get('id', 0) > 0 and (not block_ts):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} missing timestamp')
            return False
        if block_ts:
            if block.get('id', 0) > 0:
                _bid_v = int(block['id'])
                _anc = []
                for _h in range(max(0, _bid_v - util.MEDIAN_WINDOW_BLOCKS), _bid_v):
                    _ar = await self.block_repo.get_by_id(_h)
                    if _ar and _ar.get('ts'):
                        _anc.append(_ar.get('ts'))
                if not util._block_timestamp_ok(block_ts, _anc):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} timestamp {block_ts} outside the median window (M={util._median_ancestor_timestamp(_anc)})')
                    return False
        winner = block.get('winner') or (block.get('miners') or [None])[0]
        att = block.get('maze_attestation') or {}
        if not isinstance(att, dict):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} malformed maze_attestation')
            return False
        att_mid = str(att.get('maze_id', '') or '')
        att_pub = str(att.get('pubkey', '') or '')
        try:
            att_size = int(att.get('size', -1))
        except (TypeError, ValueError, OverflowError):
            att_size = -1
        if not att_mid or not att_pub or att_mid.lower() != att_pub.lower():
            bootstrap.logger.warning(f'[Verify] Block {block['id']} maze_attestation pubkey != maze_id (IDEA5-ATTEST)')
            return False
        _validators = config._effective_validators()
        if _validators and config._normalize_validator_key(att_pub) not in _validators:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation key not in validator set — rejecting')
            return False
        if not producer_pub or producer_pub.lower() != att_pub.lower():
            bootstrap.logger.warning(f'[Verify] Block {block['id']} producer_pub != attestation pubkey (IDEA5-ATTEST)')
            return False
        if not winner:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} has no winner')
            return False
        try:
            _derived = 'PC_' + bootstrap.hashlib.sha256(f'{util.pubkey_to_address(att_pub)}_mcx_miner'.encode()).hexdigest()[:32].upper()
        except Exception as e:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} winner derivation failed: {e}')
            return False
        if not (winner == _derived or (isinstance(winner, str) and winner.startswith(_derived + '_'))):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} winner not derived from attestation key (IDEA5-MAZE-KEY-BINDING-1)')
            return False
        _prior_att = None
        _reorg_mode = isinstance(_att_base, dict)
        if _reorg_mode and att_mid in _att_base:
            _prior_att = _att_base[att_mid]
        elif not _reorg_mode:
            _prior_att = await self.maze_attestation_repo.get(att_mid)
        if _prior_att:
            _pb = int(_prior_att.get('last_block', -1))
            if _pb >= block.get('id', 0):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} growth cap unverifiable (local attestation at {_pb} on competing chain) — rejected (ATTEST-CAP-STRICT)')
                return False
            else:
                _cap = int(_prior_att.get('last_size', config.MIN_MAZE_SIZE)) + config.ATTEST_GROWTH_PER_BLOCK * (int(block.get('id', 0)) - _pb)
                if att_size > _cap:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation growth cap exceeded: {att_size} > {_cap} (IDEA5-ATTEST)')
                    return False
        else:
            _cap = config.MIN_MAZE_SIZE + config.ATTEST_FRESH_BUFFER
            if att_size > _cap:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} first attestation exceeds cap: {att_size} > {_cap} (ATTEST-FRESH-BUFFER-1)')
                return False
        if att_size < config.MIN_MAZE_SIZE:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation size {att_size} below floor (must be >= {config.MIN_MAZE_SIZE})')
            return False
        if True:
            _ld = block.get('lottery_draw')
            if not isinstance(_ld, dict):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} missing lottery_draw - rejecting')
                return False
            _ld_cands = _ld.get('candidates')
            if not isinstance(_ld_cands, list) or not _ld_cands:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw has no candidates - rejecting')
                return False
            _ld_pos = []
            _ld_seen = set()
            for _lc in _ld_cands:
                if not isinstance(_lc, dict):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw candidate not a dict - rejecting')
                    return False
                _lcm = str(_lc.get('maze_id', '') or '')
                try:
                    _lcs = int(_lc.get('size', 0))
                    _lcw = int(_lc.get('weight', -1))
                except (TypeError, ValueError, OverflowError):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw candidate size/weight unparseable - rejecting')
                    return False
                if not _lcm or _lcm.lower() in _ld_seen or _lcs <= config.MIN_MAZE_SIZE or (_lcw != maze._maze_att_weight(_lcs)):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw candidate invalid (dup/size/weight) - rejecting')
                    return False
                _ld_seen.add(_lcm.lower())
                _ld_pos.append((_lcw, {'maze_id': _lcm, 'size': _lcs}))
            try:
                _ld_rank = int(_ld.get('rank'))
                _ld_widx = int(_ld.get('winner_index'))
            except (TypeError, ValueError, OverflowError):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw rank/winner_index unparseable - rejecting')
                return False
            _ld_rem = sorted(_ld_pos, key=lambda p: str(p[1].get('maze_id', '')))
            _ld_rem_w = sum((_w for _w, _ in _ld_rem))
            _ld_passing = []
            _ld_k = 0
            try:
                while _ld_rem:
                    _ld_draw = maze._maze_ticket(str(block.get('phash', '')), int(block.get('id', 0)), f'__draw__{_ld_k}', int(block.get('ts', 0))) % _ld_rem_w
                    _ld_acc = 0
                    _ld_pick = len(_ld_rem) - 1
                    for _li, (_lw, _lr) in enumerate(_ld_rem):
                        _ld_acc += _lw
                        if _ld_draw < _ld_acc:
                            _ld_pick = _li
                            break
                    _lw_pick, _lr_pick = _ld_rem.pop(_ld_pick)
                    _ld_rem_w -= _lw_pick
                    _ld_passing.append((_ld_k, _lr_pick))
                    _ld_k += 1
            except (TypeError, ValueError, OverflowError):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery draw recompute failed - rejecting')
                return False
            _ld_passing.sort(key=lambda p: p[0])
            if not 0 <= _ld_rank < len(_ld_passing) or not 0 <= _ld_widx < len(_ld_passing):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery_draw rank/winner_index out of range - rejecting')
                return False
            _ld_win_maze = str(_ld_passing[_ld_widx][1].get('maze_id', ''))
            if _ld_win_maze.lower() != att_mid.lower():
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery winner maze {_ld_win_maze[:16]} != attestation {att_mid[:16]} - rejecting')
                return False
            _ld_cand_size = None
            for _lw, _lr in _ld_pos:
                if str(_lr.get('maze_id', '')).lower() == att_mid.lower():
                    _ld_cand_size = int(_lr.get('size', 0))
                    break
            if _ld_cand_size is None or att_size > _ld_cand_size:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} attested size {att_size} inconsistent with lottery candidate - rejecting')
                return False
            if _ld_widx != _ld_rank and (not _ld.get('takeover')):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} lottery winner_index != rank without takeover flag - rejecting')
                return False
        if att_size > config.MIN_MAZE_SIZE + config.ATTEST_FRESH_BUFFER:
            _here = False
            for _u in list(block.get('maze_updates') or []) + list(block.get('attestation_proof') or []):
                if not isinstance(_u, dict):
                    continue
                _um = str(_u.get('maze_id') or _u.get('miner_id') or '')
                if _um == att_mid and maze._valid_maze_size(_u.get('new_size')) == att_size:
                    _here = True
                    break
            if not _here:
                if isinstance(_proven_base, dict):
                    _pb_sz = _proven_base.get(att_mid)
                    if _pb_sz is not None and att_size <= int(_pb_sz):
                        _here = True
                elif not _reorg_mode:
                    try:
                        _pa = await self.maze_attestation_repo.get(att_mid)
                    except Exception:
                        _pa = None
                    if _pa is not None and int(_pa.get('last_size', 0) or 0) >= att_size:
                        _here = True
            if not _here:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation size {att_size} not backed by a proven catch')
                return False
        try:
            _gsf = float(block.get('global_shrink_factor', 1.0))
        except (TypeError, ValueError):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} bad global_shrink_factor')
            return False
        if not bootstrap.math.isfinite(_gsf) or not 1.0 <= _gsf <= 64.0:
            bootstrap.logger.warning(f'[Verify] Block {block['id']} global_shrink_factor out of bounds')
            return False
        winner_miner = block.get('winner') or (block.get('miners') or [None])[0]
        block_hash = block.get('hash', '')
        if winner_miner and block_hash:
            if self.db.db_type == 'sqlite':
                existing = await self.db.fetchrow('SELECT block_hash FROM signed_blocks WHERE miner_id = ? AND block_id = ?', winner_miner, block.get('id', 0))
            else:
                existing = await self.db.fetchrow('SELECT block_hash FROM signed_blocks WHERE miner_id = $1 AND block_id = $2', winner_miner, block.get('id', 0))
            if existing and existing.get('block_hash') != block_hash:
                bootstrap.logger.error(f'[Verify] EQUIVOCATION: Miner {winner_miner[:16]} signed two different blocks at height {block.get('id')}: {existing.get('block_hash')[:16]} vs {block_hash[:16]}')
                return False
        if winner:
            winner_miner = await self.miner_repo.get(winner)
            if winner_miner and winner_miner.get('pub'):
                verify_key = winner_miner.get('block_signing_pub') or winner_miner.get('pub')
                if producer_pub != verify_key:
                    bootstrap.logger.warning(f"[Verify] Block {block['id']} producer_pub does not match winner's block_signing_pub")
                    return False
            else:
                valid_producers = {str(k).lower() for k in [winner, att_pub, att_mid] if k}
                if str(producer_pub).lower() not in valid_producers:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} producer_pub does not match attestation key or winner')
                    return False
        maze_updates = block.get('maze_updates', [])
        last_update_by_miner: bootstrap.Dict[str, bootstrap.Dict] = {}
        for update in maze_updates:
            mid = update.get('miner_id')
            if mid:
                last_update_by_miner[mid] = update
        for mid, update in last_update_by_miner.items():
            new_size = update.get('new_size')
            if new_size is None:
                continue
            seed = update.get('seed', '')
            new_density = update.get('new_density', 0)
            new_turbulence = update.get('turbulenceppm', 0)
            _new_size = maze._valid_maze_size(new_size)
            if _new_size is None:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} maze update with invalid size {new_size!r} for {mid[:16]} — rejected')
                return False
            new_size = _new_size
            if seed and new_size > 0:
                try:
                    loop = bootstrap.asyncio.get_event_loop()
                    test_maze = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, seed, new_size, new_density, new_turbulence, self.height)
                    expected_root = self.consensus._calculate_maze_root(test_maze)
                    claimed_root = update.get('mazeroot', '')
                    if claimed_root and expected_root != claimed_root:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} maze root mismatch for {mid[:16]}')
                        return False
                except Exception as e:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} maze replay failed for {mid[:16]}: {e}')
                    return False
            _prior_row = await self.maze_repo.get_by_maze_id(mid)
            _prior_size = int(_prior_row['size']) if _prior_row and _prior_row.get('size') is not None else int(config.MIN_MAZE_SIZE)
            if new_size > _prior_size and update.get('caught_at_nonce') is None:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} grows maze {mid[:16]} ({_prior_size}->{new_size}) without a catch proof — reject')
                return False
            caught_at_nonce = update.get('caught_at_nonce')
            if caught_at_nonce is not None:
                parent_seed = update.get('parent_seed', '')
                parent_size = update.get('parent_size', 0)
                parent_density = update.get('parent_density', 0)
                parent_turbulence = update.get('parent_turbulence', 0)
                parent_mazeroot = update.get('parent_mazeroot', '')
                parent_pos = update.get('parent_pos', [])
                parent_goal = update.get('parent_goal', [])
                caught_by_dir = update.get('caught_by_direction', '')
                parent_pos_attested = update.get('parent_pos_attested')
                parent_movenonce_claimed = update.get('parent_movenonce')
                if not all([parent_seed, parent_size > 0, caught_by_dir, len(parent_pos) == 3, len(parent_goal) == 3]):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} maze growth missing provenance fields for {mid[:16]}')
                    return False
                _parent_size = maze._valid_maze_size(parent_size)
                if _parent_size is None:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} maze growth with invalid parent size {parent_size!r} for {mid[:16]} — rejected')
                    return False
                parent_size = _parent_size
                if caught_by_dir not in self.consensus.DIRS:
                    bootstrap.logger.warning(f"[Verify] Block {block['id']} maze growth invalid direction '{caught_by_dir}' for {mid[:16]}")
                    return False
                if new_size != parent_size + 1:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} maze growth size jump {parent_size} -> {new_size} != +1 for {mid[:16]}')
                    return False
                try:
                    loop = bootstrap.asyncio.get_event_loop()
                    parent_maze = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, parent_seed, parent_size, parent_density, parent_turbulence, self.height)
                    actual_parent_root = self.consensus._calculate_maze_root(parent_maze)
                    if parent_mazeroot and actual_parent_root != parent_mazeroot:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} parent maze root mismatch for {mid[:16]}')
                        return False
                    px, py, pz = parent_pos
                    if not (0 <= px < parent_size and 0 <= py < parent_size and (0 <= pz < parent_size)):
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} parent_pos out of bounds for {mid[:16]}')
                        return False
                    dx, dy, dz = self.consensus.DIRS[caught_by_dir]
                    dest_x, dest_y, dest_z = (px + dx, py + dy, pz + dz)
                    gx, gy, gz = parent_goal
                    if (dest_x, dest_y, dest_z) != (gx, gy, gz):
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} goal mismatch for {mid[:16]}: step to ({dest_x},{dest_y},{dest_z}) != goal ({gx},{gy},{gz})')
                        return False
                    if isinstance(_maze_base, dict):
                        db_row = _maze_base.get(mid)
                    else:
                        db_row = await self.maze_repo.get_by_maze_id(mid)
                    if db_row:
                        db_pos = [int(db_row['posx']), int(db_row['posy']), int(db_row['posz'])]
                        if parent_pos_attested is not None and parent_pos_attested != db_pos:
                            bootstrap.logger.warning(f'[Verify] Block {block['id']} parent_pos_attested mismatch for {mid[:16]}: block says {parent_pos_attested}, DB has {db_pos}')
                            return False
                        if parent_movenonce_claimed is not None and parent_movenonce_claimed != int(db_row['movenonce']):
                            bootstrap.logger.warning(f'[Verify] Block {block['id']} parent_movenonce mismatch for {mid[:16]}: block says {parent_movenonce_claimed}, DB has {db_row['movenonce']}')
                            return False
                    else:
                        bootstrap.logger.info(f'[Verify] Block {block['id']}: no agreed maze geometry for {mid[:16]}, row provenance check skipped')
                except Exception as e:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} maze growth provenance check failed for {mid[:16]}: {e}')
                    return False
        for _pe in block.get('attestation_proof') or []:
            if not isinstance(_pe, dict):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof entry is not a dict — rejected')
                return False
            _pmid = str(_pe.get('maze_id') or _pe.get('miner_id') or '')
            if _pmid != att_mid:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof entry for a different maze — rejected')
                return False
            _psz = maze._valid_maze_size(_pe.get('new_size'))
            if _psz is None or _psz != att_size:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof size {_pe.get('new_size')!r} != attested {att_size} — rejected')
                return False
            _pseed = _pe.get('seed', '')
            _pdens = _pe.get('new_density', 0)
            _pturb = _pe.get('turbulenceppm', 0)
            if _pseed and _psz > 0:
                try:
                    _ploop = bootstrap.asyncio.get_event_loop()
                    _ptest = await _ploop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, _pseed, _psz, _pdens, _pturb, self.height)
                    _pexp = self.consensus._calculate_maze_root(_ptest)
                    _pclaim = _pe.get('mazeroot', '')
                    if _pclaim and _pexp != _pclaim:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof maze root mismatch — rejected')
                        return False
                except Exception as _pe_e:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof maze replay failed: {_pe_e}')
                    return False
            if _pe.get('caught_at_nonce') is not None:
                _pps = _pe.get('parent_seed', '')
                _ppsz = _pe.get('parent_size', 0)
                _ppd = _pe.get('parent_density', 0)
                _ppt = _pe.get('parent_turbulence', 0)
                _ppm = _pe.get('parent_mazeroot', '')
                _ppp = _pe.get('parent_pos', [])
                _ppg = _pe.get('parent_goal', [])
                _pdir = _pe.get('caught_by_direction', '')
                if not all([_pps, _ppsz > 0, _pdir, len(_ppp) == 3, len(_ppg) == 3]):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof growth missing provenance fields — rejected')
                    return False
                _ppsz_v = maze._valid_maze_size(_ppsz)
                if _ppsz_v is None:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof invalid parent size — rejected')
                    return False
                if _pdir not in self.consensus.DIRS:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof invalid direction — rejected')
                    return False
                if _psz != _ppsz_v + 1:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof size jump {_ppsz_v} -> {_psz} != +1 — rejected')
                    return False
                try:
                    _ploop2 = bootstrap.asyncio.get_event_loop()
                    _pparent = await _ploop2.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, _pps, _ppsz_v, _ppd, _ppt, self.height)
                    _pactual = self.consensus._calculate_maze_root(_pparent)
                    if _ppm and _pactual != _ppm:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof parent maze root mismatch — rejected')
                        return False
                    _px, _py, _pz = _ppp
                    if not (0 <= _px < _ppsz_v and 0 <= _py < _ppsz_v and (0 <= _pz < _ppsz_v)):
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof parent_pos out of bounds — rejected')
                        return False
                    _dx, _dy, _dz = self.consensus.DIRS[_pdir]
                    if (_px + _dx, _py + _dy, _pz + _dz) != (int(_ppg[0]), int(_ppg[1]), int(_ppg[2])):
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof goal mismatch — rejected')
                        return False
                except Exception as _pe2_e:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} attestation_proof parent check failed: {_pe2_e}')
                    return False
        block_id_val = block.get('id', 0)
        expected_merkle = crypto.compute_merkle_root(block.get('tx_hashes', []))
        if block.get('merkle_root', '') != expected_merkle:
            bootstrap.logger.warning(f'[Verify] Block {block_id_val} merkle_root mismatch')
            return False
        tx_hashes = block.get('tx_hashes', [])
        tx_list = block.get('transactions', [])
        if bool(tx_list) != bool(tx_hashes):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} transactions/tx_hashes presence mismatch')
            return False
        if tx_hashes:
            tx_count = block.get('tx_count', 0)
            if tx_count != len(tx_hashes):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} tx_count mismatch: {tx_count} vs {len(tx_hashes)}')
                return False
            if len(set(tx_hashes)) != len(tx_hashes):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} has duplicate tx_hash entries')
                return False
            _lok, _lreason = gas._block_limits_ok(tx_list)
            if not _lok:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} exceeds block limits: {_lreason} (BLOCK-GAS-1)')
                return False
            _tok, _treason = util._tx_lists_consistent(tx_hashes, tx_list)
            if not _tok:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} tx_hashes/envelopes mismatch: {_treason}')
                return False
            seen_nonces: bootstrap.Dict[str, int] = {}
            if isinstance(_branch, dict):
                seen_nonces = _branch.setdefault('nonces', {})
            for tx_data in tx_list:
                tx_hash = tx_data.get('tx_hash')
                if not tx_hash:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} transaction missing tx_hash')
                    return False
                val = int(tx_data.get('value', 0))
                fee = int(tx_data.get('fee', 0))
                if val < 0 or fee < 0:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} negative value or fee')
                    return False
                if not self._verify_tx_signature(tx_data):
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} has invalid signature')
                    return False
                _vbt = str(tx_data.get('tx_type', 'send'))
                if _vbt in ('send', 'burn'):
                    _vb_gas = gas._gas_intrinsic(tx_data)
                    _vb_fee = _vb_gas * gas._gas_price_of(tx_data)
                    if int(tx_data.get('_fee_charged', tx_data.get('fee', 0)) or 0) != _vb_fee:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} fee mismatch: declares {tx_data.get('_fee_charged')}, recomputed {_vb_fee}')
                        return False
                    try:
                        _vb_gu = int(tx_data.get('_gas_used'))
                    except (TypeError, ValueError):
                        _vb_gu = -1
                    if _vb_gu != _vb_gas:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} gas_used mismatch: declares {tx_data.get('_gas_used')}, recomputed {_vb_gas}')
                        return False
                elif _vbt in ('token_create', 'token_transfer', 'token_burn'):
                    try:
                        _vb_fee = gas._svf_native_fee(tx_data)
                    except (TypeError, ValueError):
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} SVF fee uncomputable')
                        return False
                    if int(tx_data.get('_fee_charged', tx_data.get('fee', 0)) or 0) != _vb_fee:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} SVF fee mismatch')
                        return False
                    try:
                        _vb_gu = int(tx_data.get('_gas_used'))
                    except (TypeError, ValueError):
                        _vb_gu = -1
                    if _vb_gu != 0:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} gas_used mismatch: declares {tx_data.get('_gas_used')}, recomputed 0')
                        return False
                _body = {k: v for k, v in tx_data.items() if k not in ('tx_hash', '_fee_charged', '_gas_used')}
                _clean = tx_hash.removeprefix('0x').lower()
                _hash_ok = crypto.hash_tx(_body) == tx_hash or crypto.hash_tx(tx_data) == tx_hash or crypto.hash_tx(_body) == _clean or (crypto.hash_tx(tx_data) == _clean)
                if not _hash_ok:
                    _sig = tx_data.get('signature', '')
                    if isinstance(_sig, str) and (_sig.startswith('0x') or len(_sig) > 130):
                        try:
                            _dec = util.decode_raw_eth_transaction(_sig)
                            _eth_hash = str(_dec.get('hash', '')).lower()
                            _hash_ok = bool(_eth_hash) and (_eth_hash == tx_hash.lower() or _eth_hash.removeprefix('0x') == _clean)
                        except Exception:
                            _hash_ok = False
                if not _hash_ok:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} hash does not match envelope')
                    return False
                from_w = tx_data.get('from_wallet', '')
                if from_w:
                    expected = seen_nonces.get(from_w, await self._get_confirmed_nonce(from_w))
                    if tx_data.get('nonce', -1) != expected:
                        existing_tx = await self.tx_repo.get_by_hash(tx_hash)
                        if existing_tx and int(existing_tx.get('block_id', -1)) >= 0:
                            seen_nonces[from_w] = max(expected, int(tx_data.get('nonce', 0)) + 1)
                        else:
                            bootstrap.logger.warning(f'[Verify] Block {block['id']} tx {tx_hash[:16]} nonce mismatch: expected {expected}, got {tx_data.get('nonce')}')
                            return False
                    else:
                        seen_nonces[from_w] = expected + 1
            if not await self._replay_transactions(tx_list, block.get('id'), block_ts=block.get('ts'), _branch_state=_branch.setdefault('maps', {}) if isinstance(_branch, dict) else None):
                bootstrap.logger.warning(f'[Verify] Block {block['id']} transaction re-execution failed')
                return False
        if block.get('id', 0) > 0:
            if gas._validated_block_reward(block, self.total_minted) is None:
                bootstrap.logger.warning(f'[Verify] Block {block['id']} reward/subsidy/supply mismatch')
                return False
        claimed_root = block.get('state_root', '')
        if block.get('id', 0) > 0 and (not claimed_root):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} missing state_root')
            return False
        if block.get('id', 0) > 0 and (not claimed_root):
            bootstrap.logger.warning(f'[Verify] Block {block['id']} missing state_root')
            return False
        if svf.svf_active_at(block.get('id', 0)):
            block_certs = block.get('svf_epoch_certificates')
            if block_certs is not None:
                if not isinstance(block_certs, list) or len(block_certs) > 1:
                    bootstrap.logger.warning(f'[Verify] Block {block['id']}: svf_epoch_certificates must be a list with at most one entry')
                    return False
                if len(block_certs) == 1:
                    cert = block_certs[0]
                    try:
                        cert_epoch = int(cert.get('evidence_epoch', -1))
                        if cert_epoch < 0:
                            raise svf.SVFReject('certificate missing evidence_epoch')
                        cert_committee_epoch = int(cert.get('committee_epoch', -1))
                        if cert_committee_epoch != svf_keys.SVF_COMMITTEE_EPOCH:
                            raise svf.SVFReject(f'certificate committee epoch {cert_committee_epoch} does not match configured epoch {svf_keys.SVF_COMMITTEE_EPOCH}')
                        end_height = cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1
                        anchor_hash = cert.get('anchor_block_hash', '')
                        if not anchor_hash:
                            raise svf.SVFReject('certificate missing anchor_block_hash')
                        anchor_block = await self.block_repo.get_by_id(end_height)
                        if anchor_block is None or anchor_block.get('hash') != anchor_hash:
                            raise svf.SVFReject(f'certificate anchor hash {anchor_hash[:16]}... does not match canonical block hash at height {end_height}')
                        epoch_root_entry = self.svf_epoch_roots.get(cert_epoch)
                        epoch_root = None
                        if isinstance(epoch_root_entry, (tuple, list)) and len(epoch_root_entry) >= 1:
                            _er = epoch_root_entry[0]
                            epoch_root = _er if isinstance(_er, bytes) else bytes.fromhex(_er)
                        cert_root = cert.get('evidence_root', '')
                        if not cert_root:
                            raise svf.SVFReject('certificate missing evidence_root')
                        if epoch_root is None:
                            raise svf.SVFReject(f'epoch {cert_epoch} evidence root not yet committed')
                        _cr = cert_root if isinstance(cert_root, bytes) else bytes.fromhex(cert_root)
                        if epoch_root != _cr:
                            raise svf.SVFReject('certificate evidence_root does not match committed epoch root')
                        cert_sig = cert.get('threshold_signature') or cert.get('signature', '')
                        if not cert_sig:
                            raise svf.SVFReject('certificate missing threshold signature')
                        if svf_keys.SVF_GROUP_PUBLIC_KEY is None:
                            raise svf.SVFReject('SVF group public key is not loaded')
                        group_pubkey_hex = svf_keys.SVF_GROUP_PUBLIC_KEY.hex()
                        group_pubkey_bytes = bytes.fromhex(group_pubkey_hex)
                        import struct as _svf_struct
                        cert_msg = b'MCX-SVF-EPOCH-BEACON-V1'
                        cert_msg += _svf_struct.pack('>H', 1)
                        cert_msg += _svf_struct.pack('>Q', int(config.CHAIN_ID))
                        cert_msg += _svf_struct.pack('>Q', int(cert_committee_epoch))
                        cert_msg += _svf_struct.pack('>Q', int(cert_epoch))
                        cert_msg += _svf_struct.pack('>Q', cert_epoch * svf.SVF_EPOCH_BLOCKS)
                        cert_msg += _svf_struct.pack('>Q', cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1)
                        cert_msg += bytes.fromhex(anchor_hash)
                        cert_msg += _cr
                        sig_bytes = bytes.fromhex(cert_sig) if isinstance(cert_sig, str) else bytes(cert_sig)
                        if not svf_keys._svf_bls_verify(group_pubkey_bytes, cert_msg, sig_bytes):
                            raise svf.SVFReject('certificate threshold signature does not verify against group key')
                        bootstrap.logger.debug(f'[SVF] block {block['id']}: certificate for epoch {cert_epoch} verified (applied on append, usable from block {block.get('id', 0) + 1})')
                    except svf.SVFReject as _cre:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']}: invalid SVF certificate: {_cre}')
                        return False
                    except Exception as e:
                        bootstrap.logger.warning(f'[Verify] Block {block['id']}: certificate verification failed: {e}')
                        return False
        else:
            block_certs = block.get('svf_epoch_certificates')
            if block_certs:
                bootstrap.logger.warning(f'[Verify] Block {block['id']}: SVF disabled but block carries certificate')
                return False
        return True

    async def _normalize_wallet_case(self):
        try:
            if self.db.db_type == 'sqlite':
                rows = await self.db.fetch('SELECT wallet, bal FROM balances WHERE wallet != LOWER(wallet)')
            else:
                rows = await self.db.fetch('SELECT wallet, bal FROM balances WHERE wallet != LOWER(wallet)')
            if not rows:
                return
            count = 0
            for r in rows:
                low = r['wallet'].lower()
                if self.db.db_type == 'sqlite':
                    existing = await self.db.fetchrow('SELECT bal FROM balances WHERE wallet = ?', low)
                    new_bal = (existing['bal'] if existing else 0) + r['bal']
                    await self.db.execute_dml('INSERT OR REPLACE INTO balances (wallet, bal) VALUES (?,?)', low, new_bal)
                    await self.db.execute_dml('DELETE FROM balances WHERE wallet = ?', r['wallet'])
                else:
                    await self.db.execute_dml('INSERT INTO balances (wallet, bal, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (wallet) DO UPDATE SET bal = balances.bal + $2, updated_at = NOW()', low, r['bal'])
                    await self.db.execute_dml('DELETE FROM balances WHERE wallet = $1', r['wallet'])
                count += 1
            if count:
                bootstrap.logger.info(f'[DB] Normalized {count} wallet address entries to lowercase')
        except Exception as e:
            bootstrap.logger.debug(f'[DB] Wallet case normalization skipped: {e}')

    async def get_balance(self, wallet: str) -> int:
        return await self.balance_repo.get(wallet)

    async def get_token_balance(self, token: str, wallet: str) -> int:
        return await self.token_balance_repo.get(token, wallet)

    async def register_miner(self, miner_id: str, wallet: str, pub_key: str, signature: str, timestamp: int, block_signing_pub: str=None, takeover_sig: str=None) -> bool:
        try:
            if abs(int(bootstrap.time.time()) - int(timestamp)) > 120:
                return False
        except (TypeError, ValueError):
            return False
        expected_wallet = util.pubkey_to_address(pub_key)
        if wallet.lower() != expected_wallet.lower():
            bootstrap.logger.warning(f'[MINER] Wallet mismatch for {miner_id[:16]}: got {wallet}, expected {expected_wallet}')
            return False
        if block_signing_pub:
            try:
                pk_bytes = bytes.fromhex(block_signing_pub)
                if len(pk_bytes) != 65 or pk_bytes[0] != 4:
                    bootstrap.logger.warning(f'[MINER] Invalid block_signing_pub format from {miner_id[:16]}: len={len(pk_bytes)} prefix={(pk_bytes[0] if pk_bytes else 'empty')}')
                    return False
            except Exception as e:
                bootstrap.logger.warning(f'[MINER] Invalid block_signing_pub from {miner_id[:16]}: {e}')
                return False
        existing = await self.miner_repo.get(miner_id)
        if existing:
            if existing.get('pub') != pub_key:
                if not takeover_sig:
                    bootstrap.logger.warning(f'[MINER] Pub key change rejected for {miner_id[:16]}: missing takeover_sig')
                    return False
                takeover_msg = f'MCXTAKEOVER|{miner_id}|{pub_key}|{timestamp}'
                if not crypto.verify_signature(existing['pub'], takeover_msg, takeover_sig):
                    bootstrap.logger.warning(f'[MINER] Pub key change rejected for {miner_id[:16]}: takeover_sig not signed by original key')
                    return False
                message = f'{miner_id}{wallet}{timestamp}'
                if not crypto.verify_signature(pub_key, message, signature):
                    bootstrap.logger.warning(f'[MINER] Pub key change rejected for {miner_id[:16]}: new key signature invalid')
                    return False
                bootstrap.logger.info(f'[MINER] Pub key updated for {miner_id[:16]}: authorized by original key')
                existing['pub'] = pub_key
                existing['wallet'] = wallet
                if block_signing_pub:
                    existing['block_signing_pub'] = block_signing_pub
            else:
                message = f'{miner_id}{wallet}{timestamp}'
                if not crypto.verify_signature(pub_key, message, signature):
                    bootstrap.logger.warning(f'[MINER] Re-registration signature invalid for {miner_id[:16]}')
                    return False
            now = bootstrap.time.time()
            if existing.get('banned_until', 0) > now:
                bootstrap.logger.info(f'[MINER] Re-registration rejected for {miner_id[:16]}: still banned for {existing['banned_until'] - now:.0f}s')
                return False
            existing['active'] = True
            existing['last_ping'] = now
            existing['consecutive_misses'] = 0
            await self.miner_repo.update(existing)
            bootstrap.logger.info(f'[MINER] Reactivated existing miner {miner_id[:16]}')
            return True
        message = f'{miner_id}{wallet}{timestamp}'
        if not crypto.verify_signature(pub_key, message, signature):
            bootstrap.logger.warning(f'[MINER] First-time registration signature invalid for {miner_id[:16]}')
            return False
        _expected = 'PC_' + bootstrap.hashlib.sha256(f'{util.pubkey_to_address(pub_key)}_mcx_miner'.encode()).hexdigest()[:32].upper()
        if not (miner_id == _expected or miner_id.startswith(_expected + '_')):
            bootstrap.logger.warning(f'[MINER] Register rejected: miner_id does not derive from pub_key')
            return False
        miner = {'miner_id': miner_id, 'wallet': wallet, 'pub': pub_key, 'block_signing_pub': block_signing_pub or pub_key, 'rewards': 0, 'blocks': 0, 'slashes': 0, 'uptime': 0, 'today_uptime': 0, 'type': 'web', 'liquidity': 0, 'fees': 0, 'last_ping': bootstrap.time.time(), 'banned_until': 0, 'created_at': bootstrap.time.time(), 'last_block': 0, 'consecutive_misses': 0, 'total_uptime': 0, 'ip_address': '', 'node_id': self.node_id, 'version': config.VERSION, 'active': True, 'confirmed_balance': 0, 'password_hash': '', 'private_key_encrypted': '', 'gas_collected': 0, 'maze_wins': 0}
        await self.miner_repo.create(miner)
        self.miners[miner_id] = miner
        bootstrap.logger.info(f'[MINER] New miner registered: {miner_id[:16]} (wallet: {wallet[:16]})')
        return True

    async def slash_miner(self, miner_id: str, reason: str):
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        miner['slashes'] += 1
        miner['consecutive_misses'] += 1
        rewards = int(miner.get('rewards', 0))
        slash_amount = rewards // 10
        wallet = miner.get('wallet')
        if wallet and slash_amount > 0:
            await self.balance_repo.subtract(wallet, slash_amount)
        if miner['slashes'] >= config.BAN_THRESHOLD:
            miner['active'] = False
            miner['banned_until'] = bootstrap.time.time() + config.BAN_DURATION
        await self.miner_repo.update(miner)
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO slashing_events (miner_id, amount, reason, block_id, timestamp) VALUES (?, ?, ?, ?, ?)', miner_id, slash_amount, reason, -1, bootstrap.time.time())
        else:
            await self.db.execute_dml('INSERT INTO slashing_events (miner_id, amount, reason, block_id, timestamp) VALUES ($1, $2, $3, $4, NOW())', miner_id, slash_amount, reason, -1)
        bootstrap.logger.warning(f'[Slash] Miner {miner_id[:16]} slashed: {reason} (amount={slash_amount})')

    async def get_token_temporal_config(self, token_address: str) -> dict:
        raw = await self.contract_state_repo.get(token_address, 'temporal_config')
        if raw:
            try:
                return bootstrap.json.loads(raw)
            except Exception:
                pass
        return {}

    async def get_blocks_range(self, start: int, end: int) -> bootstrap.List[bootstrap.Dict]:
        cached = {b['id']: b for b in self.blocks if start <= b['id'] <= end}
        missing = [i for i in range(start, end + 1) if i not in cached]
        if missing and self.block_repo:
            try:
                db_blocks = await self.block_repo.get_range(start, end, limit=max(10, end - start + 1))
                for b in db_blocks:
                    cached[b['id']] = b
            except Exception as e:
                bootstrap.logger.warning(f'[BlockRepo] get_range error: {e}')
        return [cached[i] for i in sorted(cached.keys())]

    async def _relay_verified_blocks(self, blocks):
        _p2p = getattr(self, 'p2p', None)
        if _p2p is None:
            return
        for _blk in blocks or []:
            try:
                await _p2p.broadcast_block(_blk, force=True)
            except Exception as _re:
                bootstrap.logger.warning(f'[Relay] Failed to relay verified block {(_blk or {}).get('id')}: {_re}')

    async def import_blocks(self, blocks_data: bootstrap.List[bootstrap.Dict]):
        sorted_blocks = sorted(blocks_data, key=lambda x: x['id'])
        for b in sorted_blocks:
            existing = await self.block_repo.get_by_id(b['id'])
            if existing and existing.get('hash') == b.get('hash'):
                continue
            if b['id'] > self.height:
                bootstrap.logger.debug(f'[IMPORT] Block {b['id']} above local tip {self.height} with unknown parent; skipping batch')
                break
            bid = b['id']
            phash = b.get('phash', '')
            if bid == self.height and phash == self.last_hash:
                if not await self.verify_block_proof(b):
                    bootstrap.logger.warning(f'[IMPORT] Block {b['id']} failed verification')
                    if not self._proof_field_hint_shown:
                        self._proof_field_hint_shown = True
                        bootstrap.logger.warning('[Verify] One or more blocks rejected for missing proof fields. If you are syncing from a node running a different MCX version, or your microcore.db predates the current proof schema, delete microcore.db and restart. Your wallet (config.yaml) is unaffected.')
                    continue
                try:
                    await self._append_block(b)
                except Exception as _ie:
                    _msg = str(_ie).lower()
                    _unique = isinstance(_ie, bootstrap.sqlite3.IntegrityError) or type(_ie).__name__ in ('UniqueViolation', 'IntegrityError') or 'unique' in _msg or ('duplicate' in _msg)
                    if not _unique:
                        raise
                    _ex = await self.block_repo.get_by_id(b['id'])
                    if _ex and _ex.get('hash') == b.get('hash'):
                        bootstrap.logger.debug(f'[IMPORT] Block {b['id']} already present (race), skipping')
                        continue
                    bootstrap.logger.warning(f'[IMPORT] Block {b['id']} unique conflict but hash mismatch (stored={(_ex or {}).get('hash', '')[:16]}… incoming={str(b.get('hash', ''))[:16]}…) — not skipping')
                    continue
                await self._relay_verified_blocks([b])
                continue
            if bid > 0 and phash != self.last_hash:
                our_block = await self.block_repo.get_by_id(bid - 1)
                if our_block and our_block.get('hash') == phash:
                    common_height = bid - 1
                else:
                    common_height = -1
                    for ch in range(bid - 1, max(-1, bid - 100), -1):
                        chk = await self.block_repo.get_by_id(ch)
                        if chk and chk.get('hash') == phash:
                            common_height = ch
                            break
                if common_height < 0:
                    bootstrap.logger.debug(f'[IMPORT] Fork at {bid} with unknown parent; skipping')
                    continue
                our_blocks = await self.block_repo.get_range(common_height + 1, self.height, limit=500)
                our_chain_weight = sum((maze._block_att_weight(ob) for ob in our_blocks))
                their_blocks = [blk for blk in sorted_blocks if blk.get('id', 0) > common_height]
                their_chain_weight = sum((maze._block_att_weight(tb) for tb in their_blocks))
                if their_chain_weight > our_chain_weight:
                    bootstrap.logger.warning(f'[REORG] Reorganizing at height {common_height}: their weight {their_chain_weight} > our {our_chain_weight}')
                    if await self._reorg_chain(common_height, their_blocks):
                        await self._relay_verified_blocks(their_blocks)
                    break
                elif their_chain_weight == our_chain_weight:
                    _our_tip = (our_blocks[-1].get('hash', '') if our_blocks else self.last_hash) or ''
                    _their_tip = (their_blocks[-1].get('hash', '') if their_blocks else '') or ''
                    if maze._fork_tiebreak_winner(_our_tip, _their_tip):
                        bootstrap.logger.warning(f'[REORG] Tie broken by hash at {bid}: adopting their tip {_their_tip[:16]} over {_our_tip[:16]}')
                        if await self._reorg_chain(common_height, their_blocks):
                            await self._relay_verified_blocks(their_blocks)
                        break
                    bootstrap.logger.debug(f'[IMPORT] Fork at {bid} tied on weight ({our_chain_weight} == {their_chain_weight}); keeping local tip on hash tiebreak')
                    continue
                else:
                    bootstrap.logger.debug(f'[IMPORT] Fork at {bid}: our chain heavier ({our_chain_weight} > {their_chain_weight})')
                    continue

    async def receive_block(self, block_data: bootstrap.Dict) -> str:
        _is_clean_append = isinstance(block_data, dict) and block_data.get('id') == self.height and (block_data.get('phash') == self.last_hash)
        if _is_clean_append:
            if not await self.verify_block_proof(block_data):
                bootstrap.logger.warning(f'[Block] Rejected block {block_data.get('id')} – invalid proof')
                return 'rejected'
        else:
            if not isinstance(block_data, dict) or 'hash' not in block_data or 'id' not in block_data:
                return 'rejected'
            try:
                _unsigned = {k: v for k, v in block_data.items() if k not in maze.CONSENSUS_EXCLUDED_FIELDS}
                if block_data.get('hash') != crypto.hash_block(_unsigned):
                    return 'rejected'
                _pp = block_data.get('producer_pub', '')
                if not _pp or not crypto.verify_signature(_pp, bytes.fromhex(block_data.get('hash', '')), block_data.get('signature', '')):
                    return 'rejected'
            except Exception:
                return 'rejected'
        await self.consensus._update_global_shrink_factor()
        bid = block_data['id']
        phash = block_data.get('phash', '')
        if bid < self.height:
            bootstrap.logger.debug(f'[Block] Below-tip fork singleton {bid} (tip {self.height}); fetching sender tail')
            return 'disconnected'
        if bid == self.height and phash == self.last_hash:
            try:
                await self._append_block(block_data)
            except Exception as _ie:
                _msg = str(_ie).lower()
                _unique = isinstance(_ie, bootstrap.sqlite3.IntegrityError) or type(_ie).__name__ in ('UniqueViolation', 'IntegrityError') or 'unique' in _msg or ('duplicate' in _msg)
                if not _unique:
                    raise
                _ex = await self.block_repo.get_by_id(bid)
                if _ex and _ex.get('hash') == block_data.get('hash'):
                    bootstrap.logger.debug(f'[Block] Block {bid} already present (race); treating as ok')
                    return 'ok'
                bootstrap.logger.warning(f'[Block] Block {bid} unique conflict with different hash — rejected')
                return 'rejected'
            bootstrap.logger.info(f'[Block] Received and accepted block {bid}')
            return 'ok'
        if bid > self.height and phash == self.last_hash:
            bootstrap.logger.warning(f'[Block] Rejected block {bid}: parent hash matches the local tip but the height is not the next height ({self.height})')
            return 'rejected'
        if bid > 0 and phash != self.last_hash:
            our_block = await self.block_repo.get_by_id(bid - 1)
            if our_block and our_block.get('hash') == phash:
                common_height = bid - 1
                our_blocks = await self.block_repo.get_range(common_height + 1, self.height, limit=500)
                our_chain_weight = sum((maze._block_att_weight(ob) for ob in our_blocks))
                their_chain_weight = maze._block_att_weight(block_data)
                if their_chain_weight > our_chain_weight:
                    bootstrap.logger.warning(f'[REORG] Reorganizing at height {common_height}: their weight {their_chain_weight} > our {our_chain_weight}')
                    if not await self._reorg_chain(common_height, [block_data]):
                        return 'rejected'
                    return 'ok'
                elif their_chain_weight == our_chain_weight:
                    _our_tip = (our_blocks[-1].get('hash', '') if our_blocks else self.last_hash) or ''
                    _their_tip = block_data.get('hash', '') or ''
                    if maze._fork_tiebreak_winner(_our_tip, _their_tip):
                        bootstrap.logger.warning(f'[REORG] Tie broken by hash at {bid}: adopting their tip {_their_tip[:16]} over {_our_tip[:16]}')
                        if not await self._reorg_chain(common_height, [block_data]):
                            return 'rejected'
                        return 'ok'
                    else:
                        bootstrap.logger.debug(f'[Block] Fork at {bid} tied on weight ({our_chain_weight} == {their_chain_weight}); keeping local tip on hash tiebreak; not relaying unverified block')
                        return 'ignored'
                else:
                    bootstrap.logger.debug(f'[Block] Fork at {bid}: our chain heavier ({our_chain_weight} > {their_chain_weight}); keeping the block pending (not relayed as verified)')
                    return 'ignored'
            else:
                bootstrap.logger.debug(f'[Block] Disconnected fork block {bid} (parent {phash[:12]} not at {bid - 1}); ignoring')
                return 'disconnected'
        bootstrap.logger.warning(f'[Block] Rejected block {bid}: no verifiable parent link to the local chain')
        return 'rejected'

    async def _restore_attestations_upto(self, common_height: int, affected: bootstrap.List[str]):
        remaining = set(affected)
        if not remaining:
            return
        q = 'SELECT id, hash, proof FROM blocks WHERE id <= ? AND proof IS NOT NULL ORDER BY id DESC' if self.db.db_type == 'sqlite' else 'SELECT id, hash, proof FROM blocks WHERE id <= $1 AND proof IS NOT NULL ORDER BY id DESC'
        rows = await self.db.fetch(q, common_height)
        for r in rows:
            if not remaining:
                break
            try:
                proof = bootstrap.json.loads(r.get('proof') or '{}')
            except Exception:
                continue
            att = proof.get('maze_attestation')
            if not isinstance(att, dict):
                continue
            mid = str(att.get('maze_id', ''))
            if mid in remaining:
                try:
                    await self.maze_attestation_repo.upsert({'maze_id': mid, 'last_size': int(att.get('size', 0)), 'last_block': int(r.get('id', 0)), 'last_block_hash': str(r.get('hash', '')), 'pubkey': str(att.get('pubkey', ''))})
                    remaining.discard(mid)
                except Exception:
                    continue
        if remaining:
            bootstrap.logger.warning(f'[IDEA5-ATTEST-REORG-2] no canonical attestation found for {sorted(remaining)[:4]} at/below {common_height}')

    async def _journal_state_row(self, block_id: int, addr: str, key: str, old_value, new_value) -> None:
        try:
            if block_id is None or int(block_id) < 0:
                return
        except (TypeError, ValueError):
            return

        def _s(v):
            return None if v is None else str(v)
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES (?,?,?,?,?,?)', int(block_id), 'contract_state', str(addr), str(key), _s(old_value), _s(new_value))
        else:
            await self.db.execute_dml('INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES ($1,$2,$3,$4,$5,$6)', int(block_id), 'contract_state', str(addr), str(key), _s(old_value), _s(new_value))

    async def _revert_exec_journal(self, common_height: int, touched_wallets=None, touched_tokens=None) -> int:
        sqlite = self.db.db_type == 'sqlite'
        _bids = await self.db.fetch('SELECT DISTINCT block_id FROM contract_exec_journal WHERE block_id > ? ORDER BY block_id DESC' if sqlite else 'SELECT DISTINCT block_id FROM contract_exec_journal WHERE block_id > $1 ORDER BY block_id DESC', int(common_height))
        n = 0
        for _b in _bids or []:
            _rbid = int(_b['block_id'])
            _jrows = await self.db.fetch('SELECT namespace, addr, key, old_value, new_value FROM contract_exec_journal WHERE block_id = ? ORDER BY rowid DESC' if sqlite else 'SELECT namespace, addr, key, old_value, new_value FROM contract_exec_journal WHERE block_id = $1 ORDER BY seq DESC', _rbid)
            for _jr in _jrows or []:
                _ns, _ad, _ky = (_jr['namespace'], _jr['addr'], _jr['key'])
                _ov, _nv = (_jr['old_value'], _jr['new_value'])
                if _ns == 'storage':
                    if _ov is None:
                        await self.db.execute_dml('DELETE FROM contract_storage_v2 WHERE contract_address = ? AND key = ?' if sqlite else 'DELETE FROM contract_storage_v2 WHERE contract_address = $1 AND key = $2', _ad, _ky)
                    else:
                        await self.contract_storage_v2_repo.set(_ad, _ky, str(_ov))
                elif _ns == 'contract_state' and _ky == 'burned_total':
                    _cr = await self.contract_state_repo.get(_ad, _ky)
                    try:
                        _cv = int(_cr) if _cr not in (None, '') else 0
                    except (TypeError, ValueError):
                        _cv = 0
                    _res = _cv + (int(_ov) if _ov is not None else 0) - (int(_nv) if _nv is not None else 0)
                    if _res == 0 and _ov is None:
                        await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = ? AND key = ?' if sqlite else 'DELETE FROM contract_state WHERE contract_address = $1 AND key = $2', _ad, _ky)
                    else:
                        await self.contract_state_repo.set(_ad, _ky, str(max(0, _res)))
                elif _ns == 'contract_state':
                    if _ov is None:
                        await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = ? AND key = ?' if sqlite else 'DELETE FROM contract_state WHERE contract_address = $1 AND key = $2', _ad, _ky)
                    else:
                        await self.contract_state_repo.set(_ad, _ky, str(_ov))
                elif _ns in ('balance', 'token_balance'):
                    _delta = (int(_ov) if _ov is not None else 0) - (int(_nv) if _nv is not None else 0)
                    if _delta:
                        if _ns == 'balance':
                            await self.balance_repo.add(_ad, _delta)
                            if touched_wallets is not None:
                                touched_wallets.add(str(_ad).lower())
                        else:
                            _cur = await self.token_balance_repo.get(_ad, _ky)
                            await self.token_balance_repo.set(_ad, _ky, int(_cur) + _delta)
                            if touched_tokens is not None:
                                touched_tokens.add((str(_ad), str(_ky)))
                else:
                    raise ValueError(f'unknown journal namespace {_ns}')
                n += 1
            await self.db.execute_dml('DELETE FROM contract_exec_journal WHERE block_id = ?' if sqlite else 'DELETE FROM contract_exec_journal WHERE block_id = $1', _rbid)
        return n

    async def _reorg_settle_negatives(self, touched_wallets, touched_tokens, shortfalls) -> None:
        for _w in sorted(touched_wallets or ()):
            _b = int(await self.balance_repo.get(_w) or 0)
            if _b < 0:
                bootstrap.logger.warning(f'[REORG] settle shortfall wallet {str(_w)[:16]} short {-_b}')
                shortfalls.append(('settle:balance', str(_w), -_b, 0))
                await self.balance_repo.set(_w, 0)
        for _t, _w in sorted(touched_tokens or ()):
            _b = int(await self.token_balance_repo.get(_t, _w) or 0)
            if _b < 0:
                bootstrap.logger.warning(f'[REORG] settle token shortfall {str(_t)[:16]}:{str(_w)[:16]} short {-_b}')
                shortfalls.append(('settle:token', 'token:' + str(_t)[:16] + ':' + str(_w), -_b, 0))
                await self.token_balance_repo.set(_t, _w, 0)

    async def _invert_block_txs(self, common_height: int, tx_hashes=None, _touched_w=None, _touched_t=None):
        if tx_hashes is not None and len(tx_hashes) == 0:
            return []
        if _touched_w is None:
            _touched_w = set()
        if _touched_t is None:
            _touched_t = set()
        _reorg_shortfalls: list = []
        _reorg_deploys: list = []
        _reorg_token_creates: list = []
        _reorg_htlc_ids: list = []
        if self.db.db_type == 'sqlite':
            tx_query = 'SELECT * FROM transactions WHERE block_id > ?'
            _order = ' ORDER BY block_id DESC, rowid DESC'
        else:
            tx_query = 'SELECT * FROM transactions WHERE block_id > $1'
            _order = ' ORDER BY block_id DESC, timestamp DESC, tx_hash DESC'
        _tx_params: list = [common_height]
        if tx_hashes is not None:
            _hashes = [str(h) for h in tx_hashes]
            if self.db.db_type == 'sqlite':
                tx_query += ' AND tx_hash IN (%s)' % ','.join('?' * len(_hashes))
                _tx_params += _hashes
            else:
                tx_query += ' AND tx_hash IN (%s)' % ','.join(('$%d' % n for n in range(2, 2 + len(_hashes))))
                _tx_params += _hashes
        tx_query += _order
        orphaned_txs = await self.db.fetch(tx_query, *_tx_params)
        for tx in orphaned_txs:
            tx_type = tx.get('tx_type', 'send')
            amount = tx.get('amount', 0)
            fee = tx.get('_fee_charged', tx.get('fee', 0))
            from_w = tx.get('from_wallet')
            to_w = tx.get('to_wallet')
            if from_w:
                await self._account_nonce_rollback(from_w, tx.get('nonce', 0))
            if tx_type == 'send' and from_w and to_w:
                total = amount + fee
                await self.balance_repo.add(from_w, total)
                if to_w.lower() in config.BURN_ADDRESSES:
                    self.burned_total = max(0, self.burned_total - amount)
                    await self.network_state_repo.set('burned_total', str(self.burned_total))
                    bootstrap.logger.info(f'[REORG] Un-burned {amount // config.SUBS} MCX (send to burn address reverted)')
                else:
                    await self.balance_repo.add(to_w, -int(amount))
                    _touched_w.add(str(to_w).lower())
            elif tx_type == 'burn' and from_w:
                await self.balance_repo.add(from_w, amount + fee)
                self.burned_total = max(0, self.burned_total - amount)
                await self.network_state_repo.set('burned_total', str(self.burned_total))
                bootstrap.logger.info(f'[REORG] Reversed burn of {amount // config.SUBS} MCX from {from_w[:16]}')
            elif tx_type == 'token_transfer' and from_w and to_w:
                token_addr = tx.get('token_address')
                _btax = 0
                try:
                    _dd = tx.get('data') or {}
                    if isinstance(_dd, str):
                        _dd = bootstrap.json.loads(_dd)
                    if isinstance(_dd, dict):
                        _btax = int(_dd.get('_burn_tax', 0) or 0)
                except Exception:
                    _btax = 0
                if _btax < 0:
                    _btax = 0
                _net = amount - _btax
                if _net < 0:
                    _net = 0
                if token_addr:
                    f_bal = await self.token_balance_repo.get(token_addr, from_w)
                    await self.token_balance_repo.set(token_addr, from_w, f_bal + amount)
                    t_bal = await self.token_balance_repo.get(token_addr, to_w)
                    await self.token_balance_repo.set(token_addr, to_w, t_bal - _net)
                    _touched_t.add((str(token_addr), str(to_w)))
                    if _btax > 0:
                        tok = await self.token_repo.get(token_addr)
                        if tok:
                            tok['total_supply'] = int(tok.get('total_supply', 0)) + _btax
                            await self.token_repo.upsert(tok)
                if fee > 0:
                    await self.balance_repo.add(from_w, fee)
            elif tx_type == 'contract_deploy':
                contract_addr = tx.get('contract_address') or tx.get('to_wallet')
                if fee > 0 and from_w:
                    await self.balance_repo.add(from_w, fee)
                _vmoved = util._moved_value_of(tx)
                if _vmoved > 0 and contract_addr and from_w:
                    _crev = min(_vmoved, max(0, int(await self.balance_repo.get(contract_addr) or 0)))
                    await self.balance_repo.add(contract_addr, -_crev)
                    _touched_w.add(str(contract_addr).lower())
                    await self.balance_repo.add(from_w, _crev)
                    _touched_w.add(str(from_w).lower())
                if contract_addr:
                    _reorg_deploys.append(contract_addr)
                    bootstrap.logger.warning(f'[REORG] Reverted contract_deploy for {contract_addr[:16]}')
            elif tx_type == 'contract_call':
                contract_addr = tx.get('to_wallet')
                if fee > 0 and from_w:
                    await self.balance_repo.add(from_w, fee)
                _vmoved = util._moved_value_of(tx)
                if _vmoved > 0 and contract_addr and from_w:
                    _crev = min(_vmoved, max(0, int(await self.balance_repo.get(contract_addr) or 0)))
                    await self.balance_repo.add(contract_addr, -_crev)
                    _touched_w.add(str(contract_addr).lower())
                    await self.balance_repo.add(from_w, _crev)
                    _touched_w.add(str(from_w).lower())
                if contract_addr:
                    bootstrap.logger.info(f'[REORG] contract_call on {contract_addr[:16]} reverted via contract_exec_journal (B6).')
            elif tx_type == 'htlc_create':
                if fee > 0 and from_w:
                    await self.balance_repo.add(from_w, fee)
                tx_id = tx.get('tx_hash')
                if tx_id:
                    if self.db.db_type == 'sqlite':
                        await self.db.execute_dml("UPDATE htlc_contracts SET status='reverted' WHERE id = ?", tx_id)
                    else:
                        await self.db.execute_dml("UPDATE htlc_contracts SET status='reverted' WHERE id = $1", tx_id)
                    bootstrap.logger.warning(f'[REORG] Reverted htlc_create {tx_id[:16]}')
                try:
                    _hd = tx.get('data') or {}
                    if isinstance(_hd, str):
                        _hd = bootstrap.json.loads(_hd)
                    _hid = _hd.get('htlc_id') or '' if isinstance(_hd, dict) else ''
                    if _hid:
                        _hid = str(_hid).lower()
                        if _hid not in _reorg_htlc_ids:
                            _reorg_htlc_ids.append(_hid)
                except Exception as e:
                    bootstrap.logger.warning(f'[Reorg] HTLC inverse failed for block {common_height}: {e}')
            elif tx_type == 'token_burn' and from_w:
                token_addr = tx.get('token_address')
                if token_addr:
                    tb = await self.token_balance_repo.get(token_addr, from_w)
                    await self.token_balance_repo.set(token_addr, from_w, tb + amount)
                    tok = await self.token_repo.get(token_addr)
                    if tok:
                        tok['total_supply'] = int(tok.get('total_supply', 0)) + amount
                        await self.token_repo.upsert(tok)
                    cur_burned = int(await self.contract_state_repo.get(token_addr, 'burned_total') or 0)
                    await self.contract_state_repo.set(token_addr, 'burned_total', str(max(0, cur_burned - amount)))
                if fee > 0:
                    await self.balance_repo.add(from_w, fee)
            elif tx_type == 'token_create':
                _tc_addr = tx.get('token_address') or ''
                if not _tc_addr:
                    try:
                        _rc = await self.receipt_repo.get(tx.get('tx_hash'))
                        _tc_addr = (_rc or {}).get('contract_address') or ''
                    except Exception:
                        _tc_addr = ''
                if not _tc_addr:
                    try:
                        _d = tx.get('data') or {}
                        if isinstance(_d, str):
                            _d = bootstrap.json.loads(_d)
                        _tc_addr = util._derive_token_address(tx.get('tx_hash'), from_w, _d.get('name'), _d.get('symbol'))
                    except Exception:
                        _tc_addr = ''
                if fee > 0 and from_w:
                    await self.balance_repo.add(from_w, fee)
                if _tc_addr:
                    _reorg_token_creates.append(_tc_addr)
                    try:
                        self.tokens.pop(_tc_addr, None)
                    except Exception as _le:
                        bootstrap.logger.warning(f'[Reorg] in-memory token pop skipped {str(_tc_addr or '?')[:16]}: {str(_le or '?')[:16]}')
        await self._revert_exec_journal(common_height, _touched_w, _touched_t)
        for _ca in _reorg_deploys:
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('DELETE FROM contract_v2 WHERE address = ?', _ca)
                await self.db.execute_dml('DELETE FROM contract_storage_v2 WHERE contract_address = ?', _ca)
                await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = ?', _ca)
            else:
                await self.db.execute_dml('DELETE FROM contract_v2 WHERE address = $1', _ca)
                await self.db.execute_dml('DELETE FROM contract_storage_v2 WHERE contract_address = $1', _ca)
                await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = $1', _ca)
        if _reorg_deploys and hasattr(self, 'vm_manager') and self.vm_manager:
            self.vm_manager._code_cache_valid = False
        for _ta in _reorg_token_creates:
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('DELETE FROM tokens WHERE address = ?', _ta)
                await self.db.execute_dml('DELETE FROM token_balances WHERE token_address = ?', _ta)
                await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = ?', _ta)
            else:
                await self.db.execute_dml('DELETE FROM tokens WHERE address = $1', _ta)
                await self.db.execute_dml('DELETE FROM token_balances WHERE token_address = $1', _ta)
                await self.db.execute_dml('DELETE FROM contract_state WHERE contract_address = $1', _ta)
        _created = set(_reorg_token_creates)
        _touched_t = {(t, w) for t, w in _touched_t if t not in _created}
        await self._reorg_settle_negatives(_touched_w, _touched_t, _reorg_shortfalls)
        for _hid in _reorg_htlc_ids:
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('DELETE FROM balances WHERE wallet = ? AND bal = 0', _hid)
            else:
                await self.db.execute_dml('DELETE FROM balances WHERE wallet = $1 AND bal = 0', _hid)
        if self.db.db_type == 'sqlite':
            if tx_hashes is None:
                await self.db.execute_dml('DELETE FROM transactions WHERE block_id > ?', common_height)
                await self.db.execute_dml('DELETE FROM transaction_receipts WHERE block_id > ?', common_height)
                await self.db.execute_dml('DELETE FROM blocks WHERE id > ?', common_height)
                await self.db.execute_dml('DELETE FROM block_state_roots WHERE block_id > ?', common_height)
            else:
                _hashes = [str(h) for h in tx_hashes]
                _in = '(%s)' % ','.join('?' * len(_hashes))
                await self.db.execute_dml('DELETE FROM transactions WHERE block_id > ? AND tx_hash IN ' + _in, common_height, *_hashes)
                await self.db.execute_dml('DELETE FROM transaction_receipts WHERE block_id > ? AND tx_hash IN ' + _in, common_height, *_hashes)
        elif tx_hashes is None:
            await self.db.execute_dml('DELETE FROM transactions WHERE block_id > $1', common_height)
            await self.db.execute_dml('DELETE FROM transaction_receipts WHERE block_id > $1', common_height)
            await self.db.execute_dml('DELETE FROM blocks WHERE id > $1', common_height)
            await self.db.execute_dml('DELETE FROM block_state_roots WHERE block_id > $1', common_height)
        else:
            _hashes = [str(h) for h in tx_hashes]
            _in = '(%s)' % ','.join(('$%d' % n for n in range(2, 2 + len(_hashes))))
            await self.db.execute_dml('DELETE FROM transactions WHERE block_id > $1 AND tx_hash IN ' + _in, common_height, *_hashes)
            await self.db.execute_dml('DELETE FROM transaction_receipts WHERE block_id > $1 AND tx_hash IN ' + _in, common_height, *_hashes)
        if svf.svf_active_at(common_height):
            try:
                if self.db.db_type == 'sqlite':
                    await self.db.execute_dml('DELETE FROM svf_evidence WHERE height > ?', common_height)
                else:
                    await self.db.execute_dml('DELETE FROM svf_evidence WHERE height > $1', common_height)
                _max_epoch = int(common_height) // svf.SVF_EPOCH_BLOCKS
                if self.db.db_type == 'sqlite':
                    _rows = await self.db.fetch('SELECT DISTINCT epoch_id FROM svf_evidence WHERE epoch_id <= ? ORDER BY epoch_id', _max_epoch)
                else:
                    _rows = await self.db.fetch('SELECT DISTINCT epoch_id FROM svf_evidence WHERE epoch_id <= $1 ORDER BY epoch_id', _max_epoch)
                for _er in _rows or []:
                    _eid = int(_er['epoch_id'])
                    if self.db.db_type == 'sqlite':
                        _ev_rows = await self.db.fetch('SELECT height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id = ? ORDER BY height', _eid)
                    else:
                        _ev_rows = await self.db.fetch('SELECT height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id = $1 ORDER BY height', _eid)
                    _recs = []
                    for _r in _ev_rows or []:
                        _recs.append({'block_id': int(_r['height']), 'block_hash': _r['block_hash'], 'winner_pubkey': _r['winner_pubkey'], 'attested_size': int(_r['attested_size']), 'attestation_weight': int(_r['attestation_weight']), 'growth_present': bool(int(_r['growth_present'])), 'record_hash': bytes.fromhex(_r['record_hash']) if _r['record_hash'] else b'\x00' * 32})
                    if len(_recs) == svf.SVF_EPOCH_BLOCKS:
                        _sorted = sorted(_recs, key=lambda r: r['block_id'])
                        _root = svf.compute_epoch_root(_sorted)
                        if self.db.db_type == 'sqlite':
                            await self.db.execute_dml('INSERT OR REPLACE INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES (?,?,?,?)', _eid, _root.hex(), len(_sorted), 1)
                        else:
                            await self.db.execute_dml('INSERT INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES ($1,$2,$3,$4) ON CONFLICT (epoch_id) DO UPDATE SET root_hash=$2, record_count=$3, complete=$4', _eid, _root.hex(), len(_sorted), 1)
                    elif self.db.db_type == 'sqlite':
                        await self.db.execute_dml('DELETE FROM svf_epoch_roots WHERE epoch_id = ?', _eid)
                    else:
                        await self.db.execute_dml('DELETE FROM svf_epoch_roots WHERE epoch_id = $1', _eid)
                if self.db.db_type == 'sqlite':
                    await self.db.execute_dml('DELETE FROM svf_profiles WHERE registration_block_height > ?', common_height)
                else:
                    await self.db.execute_dml('DELETE FROM svf_profiles WHERE registration_block_height > $1', common_height)
                if self.db.db_type == 'sqlite':
                    await self.db.execute_dml('DELETE FROM svf_certificates WHERE inclusion_block > ?', common_height)
                else:
                    await self.db.execute_dml('DELETE FROM svf_certificates WHERE inclusion_block > $1', common_height)
                self.svf_evidence_store = {}
                self.svf_epoch_roots = {}
                self.svf_certificates = {}
                self.svf_profiles = {}
                if self.db.db_type == 'sqlite':
                    _rows = await self.db.fetch('SELECT epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id <= ? ORDER BY epoch_id, height', _max_epoch)
                else:
                    _rows = await self.db.fetch('SELECT epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id <= $1 ORDER BY epoch_id, height', _max_epoch)
                for _r in _rows or []:
                    _eid = int(_r['epoch_id'])
                    self.svf_evidence_store.setdefault(_eid, []).append({'block_id': int(_r['height']), 'block_hash': _r['block_hash'], 'winner_pubkey': _r['winner_pubkey'], 'attested_size': int(_r['attested_size']), 'attestation_weight': int(_r['attestation_weight']), 'growth_present': bool(int(_r['growth_present'])), 'record_hash': bytes.fromhex(_r['record_hash']) if _r['record_hash'] else b'\x00' * 32})
                if self.db.db_type == 'sqlite':
                    _erows = await self.db.fetch('SELECT epoch_id, root_hash, record_count FROM svf_epoch_roots')
                    _crows = await self.db.fetch('SELECT evidence_epoch, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from FROM svf_certificates')
                else:
                    _erows = await self.db.fetch('SELECT epoch_id, root_hash, record_count FROM svf_epoch_roots')
                    _crows = await self.db.fetch('SELECT evidence_epoch, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from FROM svf_certificates')
                for _er in _erows or []:
                    try:
                        self.svf_epoch_roots[int(_er['epoch_id'])] = (bytes.fromhex(_er['root_hash']), int(_er['record_count']))
                    except Exception:
                        continue
                for _cr in _crows or []:
                    try:
                        self.svf_certificates[int(_cr['evidence_epoch'])] = {'evidence_epoch': int(_cr['evidence_epoch']), 'anchor_block_hash': _cr['anchor_block_hash'], 'evidence_root': _cr['evidence_root'], 'group_pubkey': _cr['group_public_key_id'], 'threshold_signature': _cr['threshold_signature'], 'inclusion_block': int(_cr['inclusion_block']), 'usable_from': int(_cr['usable_from'])}
                    except Exception:
                        continue
                _prows = await self.db.fetch("SELECT token_address, canonical_profile_bytes FROM svf_profiles WHERE status = 'ACTIVE'")
                for _pr in _prows or []:
                    try:
                        self.svf_profiles[str(_pr['token_address']).lower()] = svf.svf_parse_profile(bytes.fromhex(_pr['canonical_profile_bytes']))
                    except Exception:
                        continue
                bootstrap.logger.debug(f'[SVF] reorg rolled back to height {common_height}, rebuilt SVF state from DB')
            except Exception as _sve:
                bootstrap.logger.warning(f'[SVF] reorg rollback failed: {_sve}')
        return _reorg_shortfalls

    async def _branch_state_root_ok(self, block: dict) -> bool:
        try:
            if int(block.get('id', 0)) <= 0:
                return True
            claimed = block.get('state_root', '')
            if not claimed or not isinstance(claimed, str):
                return False
            reward = int(block.get('reward', 0) or 0)
            wallet = block.get('reward_wallet') or ''
            expected = await db._state_root_with_credit(self.db, self, int(block['id']), wallet, reward)
            return claimed == expected
        except Exception as e:
            bootstrap.logger.warning(f'[REORG-STATEROOT-1] block {block.get('id')} state_root check failed: {e}')
            return False

    async def _assert_reorg_cumulative(self, common_height: int, orphaned: list, adopted: list, pre_minted: int) -> None:
        _tip_id = int(common_height)
        _tip_hash = ''
        if adopted:
            _anchor = await self.block_repo.get_by_id(int(common_height))
            _anchor_hash = _anchor.get('hash', '') if isinstance(_anchor, dict) else ''
            if not _anchor_hash:
                if int(common_height) == 0:
                    _anchor_hash = '0' * 64
                else:
                    raise AuxStateError(f'reorg cumulative: no common ancestor at {common_height}')
            _prev = str(_anchor_hash)
            for _b in adopted:
                _bid = int(_b.get('id', -1))
                _row = await self.block_repo.get_by_id(_bid)
                if not isinstance(_row, dict):
                    raise AuxStateError(f'reorg cumulative: adopted block {_bid} missing from block_repo')
                if str(_row.get('hash', '')) != str(_b.get('hash', '')):
                    raise AuxStateError(f'reorg cumulative: adopted block {_bid} hash mismatch repo-vs-branch')
                if str(_row.get('phash', '')) != _prev:
                    raise AuxStateError(f'reorg cumulative: adopted block {_bid} not parent-linked')
                _prev = str(_b.get('hash', ''))
                _tip_id, _tip_hash = (_bid, _prev)
            if int(self.height) != _tip_id + 1:
                raise AuxStateError(f'reorg cumulative: height {self.height} != tip {_tip_id}+1')
            if str(self.last_hash) != str(_tip_hash):
                raise AuxStateError('reorg cumulative: last_hash != adopted tip hash')
            _sim = int(pre_minted)
            for _ob in sorted((o for o in orphaned or [] if isinstance(o, dict)), key=lambda x: int(x.get('id', 0))):
                _om = gas._reorg_base_mint(_ob)
                if _om > 0:
                    _floored = max(0, _sim - _om)
                    if _floored != _sim - _om:
                        bootstrap.logger.warning(f'[REORG] cumulative: mint rewind floored at 0 (pre={pre_minted} orphan={int(_ob.get('id', -1))})')
                    _sim = _floored
            for _b in adopted:
                _sim += gas._reorg_base_mint(_b)
            if int(self.total_minted) != _sim:
                raise AuxStateError(f'reorg cumulative: total_minted {self.total_minted} != conserved {_sim} (pre={pre_minted})')
            for _b in adopted:
                _bid = int(_b.get('id', -1))
                _want = set((str(h) for h in _b.get('tx_hashes') or []))
                if self.db.db_type == 'sqlite':
                    _rows = await self.db.fetch('SELECT tx_hash FROM transactions WHERE block_id = ?', _bid)
                else:
                    _rows = await self.db.fetch('SELECT tx_hash FROM transactions WHERE block_id = $1', _bid)
                _got = set((str(_r.get('tx_hash', '')) for _r in _rows or []))
                if _got != _want:
                    raise AuxStateError(f'reorg cumulative: block {_bid} persisted txs {sorted(_got)[:4]} != sealed {sorted(_want)[:4]}')
        elif int(self.height) != int(common_height) + 1:
            raise AuxStateError(f'reorg cumulative: empty adoption left height {self.height} != common {common_height}+1')

    async def _reorg_chain(self, common_height: int, new_blocks: bootstrap.List[bootstrap.Dict]):
        try:
            _cand_raw = list(new_blocks or [])
            for _ce in _cand_raw:
                if not isinstance(_ce, dict) or int(_ce.get('id', -1)) < 0:
                    bootstrap.logger.error('[Reorg] Candidate suffix contains a malformed entry; aborting reorg')
                    return False
            _cand = sorted((b for b in _cand_raw if int(b.get('id', -1)) > common_height), key=lambda x: int(x.get('id', 0)))
            if _cand:
                _anchor = await self.block_repo.get_by_id(common_height)
                _anchor_hash = _anchor.get('hash', '') if isinstance(_anchor, dict) else ''
                if not _anchor_hash:
                    if common_height == 0:
                        _anchor_hash = '0' * 64
                    else:
                        bootstrap.logger.error(f'[Reorg] No common ancestor at {common_height}; aborting reorg')
                        return False
                _branch_ts = []
                for _h in range(max(0, common_height - util.MEDIAN_WINDOW_BLOCKS + 1), common_height + 1):
                    _ar = await self.block_repo.get_by_id(_h)
                    if _ar and _ar.get('ts'):
                        _branch_ts.append(_ar.get('ts'))
                try:
                    _prev_ts = float(_anchor.get('ts', 0) or 0) if isinstance(_anchor, dict) else 0
                except (TypeError, ValueError):
                    _prev_ts = 0
                _prev_id, _prev_hash = (common_height, str(_anchor_hash))
                for _cb in _cand:
                    _cid = int(_cb.get('id', -1))
                    if _cid != _prev_id + 1 or str(_cb.get('phash', '')) != str(_prev_hash):
                        bootstrap.logger.error(f'[Reorg] Candidate suffix not contiguous at id {_cid} (prev {_prev_id}); aborting reorg')
                        return False
                    _cts = _cb.get('ts', 0)
                    if not _cts:
                        bootstrap.logger.error(f'[Reorg] Candidate {_cid} missing timestamp; aborting reorg')
                        return False
                    _anc_window = _branch_ts[-util.MEDIAN_WINDOW_BLOCKS:]
                    if _anc_window and (not util._block_timestamp_ok(_cts, _anc_window)):
                        bootstrap.logger.error(f'[Reorg] Candidate {_cid} timestamp outside parent-relative bounds; aborting reorg')
                        return False
                    try:
                        _prev_ts = float(_cts)
                    except (TypeError, ValueError):
                        _prev_ts = 0
                    _branch_ts.append(_cts)
                    _prev_id, _prev_hash = (_cid, str(_cb.get('hash', '')))
        except Exception as _link_e:
            bootstrap.logger.error(f'[Reorg] Candidate suffix validation failed ({_link_e}); aborting reorg')
            return False
        _att_base = {}
        _proven_base = {}
        try:
            _aq = 'SELECT id, hash, proof FROM blocks WHERE id <= ? AND proof IS NOT NULL ORDER BY id DESC' if self.db.db_type == 'sqlite' else 'SELECT id, hash, proof FROM blocks WHERE id <= $1 AND proof IS NOT NULL ORDER BY id DESC'
            for _r in await self.db.fetch(_aq, common_height) or []:
                try:
                    _rp = _r.get('proof')
                    if isinstance(_rp, str):
                        _rp = bootstrap.json.loads(_rp or '{}')
                    if not isinstance(_rp, dict):
                        continue
                except Exception as _le:
                    bootstrap.logger.warning(f'[Reorg] block {int(_r.get('id') or 0)} proof unparseable: {str(_le or '?')[:16]}')
                    continue
                _ra = _rp.get('maze_attestation')
                if isinstance(_ra, dict):
                    _rm = str(_ra.get('maze_id', ''))
                    if _rm and _rm not in _att_base:
                        try:
                            _att_base[_rm] = {'maze_id': _rm, 'last_size': int(_ra.get('size', 0)), 'last_block': int(_r.get('id', 0)), 'last_block_hash': str(_r.get('hash', '')), 'pubkey': str(_ra.get('pubkey', ''))}
                        except Exception as _le:
                            bootstrap.logger.warning(f'[Reorg] att_base row skipped maze {str(_rm or '?')[:16]}: {str(_le or '?')[:16]}')
                            continue
                for _pm, _psz in maze._proven_sizes_from_updates(_rp.get('maze_updates')).items():
                    if _pm not in _proven_base:
                        _proven_base[_pm] = _psz
        except Exception as _aw:
            bootstrap.logger.error(f'[P6] agreed-prefix state walk failed: {_aw} — aborting reorg (orphan-inclusive proof lookup refused)')
            return False
        bootstrap.logger.debug(f'[P6] attestation base: {(len(_att_base) if isinstance(_att_base, dict) else 'legacy')} rows at fork {common_height}')
        _maze_base = {}
        if _att_base is not None:
            try:
                for _r in await self.db.fetch(_aq, common_height) or []:
                    try:
                        _rp = _r.get('proof')
                        if isinstance(_rp, str):
                            _rp = bootstrap.json.loads(_rp or '{}')
                        if not isinstance(_rp, dict):
                            continue
                    except Exception as _le:
                        bootstrap.logger.warning(f'[Reorg] block {int(_r.get('id') or 0)} proof unparseable: {str(_le or '?')[:16]}')
                        continue
                    for _mm, _mu in maze._last_updates_by_maze(_rp.get('maze_updates')).items():
                        if _mm in _maze_base:
                            continue
                        try:
                            _sp = _mu.get('spawn') or [0, 0, 0]
                            _maze_base[_mm] = {'posx': int(_sp[0]), 'posy': int(_sp[1]), 'posz': int(_sp[2]), 'movenonce': 0, 'lastactiveheight': int(_r.get('id', 0))}
                        except Exception as _le:
                            bootstrap.logger.warning(f'[Reorg] maze base skipped maze {str(_mm or '?')[:16]}: {str(_le or '?')[:16]}')
                            continue
            except Exception as _mw:
                bootstrap.logger.error(f'[B2] maze-geometry walk failed: {_mw} — aborting reorg (orphan-tip geometry fallback refused)')
                return False
        else:
            bootstrap.logger.error('[B2] agreed-prefix attestation state unavailable; aborting reorg')
            return False
        _branch_ctx: dict = {}
        try:
            _nest = _branch_ctx.setdefault('nonces', {})
            for _sb in _cand:
                for _stx in _sb.get('transactions') or []:
                    if not isinstance(_stx, dict):
                        continue
                    _sw = _stx.get('from_wallet', '')
                    if _sw and _sw not in _nest:
                        _nest[_sw] = await self._get_confirmed_nonce_at(_sw, common_height)
        except Exception as _nse:
            bootstrap.logger.warning(f'[Reorg] ancestor nonce seeding failed ({_nse}); pre-verify uses live nonces')
        try:
            _base_bal = _branch_ctx.setdefault('balances', {})
            _wallets = set()
            for _sb in _cand:
                for _stx in _sb.get('transactions') or []:
                    if not isinstance(_stx, dict):
                        continue
                    for _k in ('from_wallet', 'to_wallet'):
                        _w = str(_stx.get(_k) or '')
                        if _w:
                            _wallets.add(_w)
            _orphans = []
            try:
                _tip_h = int(getattr(self, 'height', 0) or 0)
                if _tip_h > common_height + 1:
                    _orphans = list(await self.block_repo.get_range(common_height + 1, _tip_h - 1, limit=max(500, _tip_h - common_height + 5)) or [])
                elif _tip_h == common_height + 1:
                    _one = await self.block_repo.get_by_id(common_height + 1)
                    _orphans = [_one] if _one else []
            except Exception:
                _orphans = []
            for _ob in _orphans:
                if not isinstance(_ob, dict):
                    continue
                for _stx in _ob.get('transactions') or []:
                    if not isinstance(_stx, dict):
                        continue
                    for _k in ('from_wallet', 'to_wallet'):
                        _w = str(_stx.get(_k) or '')
                        if _w:
                            _wallets.add(_w)
                _win = str(_ob.get('winner') or '')
                if _win:
                    _wallets.add(_win)
            for _w in _wallets:
                try:
                    _base_bal[_w] = int(await self.balance_repo.get(_w))
                except Exception:
                    _base_bal[_w] = 0
            for _ob in sorted((o for o in _orphans if isinstance(o, dict)), key=lambda b: int(b.get('id', 0)), reverse=True):
                for _stx in reversed(list(_ob.get('transactions') or [])):
                    if not isinstance(_stx, dict):
                        continue
                    _tt = _stx.get('tx_type', 'send')
                    try:
                        _val = int(_stx.get('value', 0) or 0)
                        _fee = int(_stx.get('_fee_charged', _stx.get('fee', 0)) or 0)
                    except (TypeError, ValueError) as _le:
                        bootstrap.logger.warning(f'[Reorg] tx {str(_stx.get('tx_hash') or '?')[:16]} value/fee unparseable: {str(_le or '?')[:16]}')
                        continue
                    _fw = str(_stx.get('from_wallet') or '')
                    _tw = str(_stx.get('to_wallet') or '')
                    if _tt in ('send', 'burn'):
                        if _fw:
                            _base_bal[_fw] = int(_base_bal.get(_fw, 0)) + _val + _fee
                        if _tt == 'send' and _tw:
                            _base_bal[_tw] = int(_base_bal.get(_tw, 0)) - _val
                        _win = str(_ob.get('winner') or '')
                        if _win and _fee:
                            _base_bal[_win] = int(_base_bal.get(_win, 0)) - _fee
                    elif _tt in ('token_transfer', 'token_burn', 'contract_call', 'token_create', 'deploy'):
                        if _fw and _fee:
                            _base_bal[_fw] = int(_base_bal.get(_fw, 0)) + _fee
                        _win = str(_ob.get('winner') or '')
                        if _win and _fee:
                            _base_bal[_win] = int(_base_bal.get(_win, 0)) - _fee
                _mint = gas._reorg_base_mint(_ob)
                _win = str(_ob.get('winner') or '')
                if _win and _mint:
                    _base_bal[_win] = int(_base_bal.get(_win, 0)) - _mint
            bootstrap.logger.debug(f'[N-10-BAL-BASE-1] seeded {len(_base_bal)} wallet balance(s) at common_height={common_height} from {len(_orphans)} orphan block(s)')
            _base_tok = _branch_ctx.setdefault('token', {})
            _tok_keys = set()
            for _sb in list(_cand) + list(_orphans):
                if not isinstance(_sb, dict):
                    continue
                for _stx in _sb.get('transactions') or []:
                    if not isinstance(_stx, dict):
                        continue
                    _ta = str(_stx.get('token_address') or '')
                    if not _ta:
                        continue
                    for _k in ('from_wallet', 'to_wallet'):
                        _w = str(_stx.get(_k) or '')
                        if _w:
                            _tok_keys.add((_ta, _w))
            for _ta, _w in _tok_keys:
                try:
                    _base_tok[_ta, _w] = int(await self.token_balance_repo.get(_ta, _w))
                except Exception:
                    _base_tok[_ta, _w] = 0
            for _ob in sorted((o for o in _orphans if isinstance(o, dict)), key=lambda b: int(b.get('id', 0)), reverse=True):
                for _stx in reversed(list(_ob.get('transactions') or [])):
                    if not isinstance(_stx, dict):
                        continue
                    _tt = _stx.get('tx_type', '')
                    _ta = str(_stx.get('token_address') or '')
                    if not _ta:
                        continue
                    try:
                        _amount = int(_stx.get('value', 0) or 0)
                    except (TypeError, ValueError) as _le:
                        bootstrap.logger.warning(f'[Reorg] tx {str(_stx.get('tx_hash') or '?')[:16]} amount unparseable: {str(_le or '?')[:16]}')
                        continue
                    _fw = str(_stx.get('from_wallet') or '')
                    _tw = str(_stx.get('to_wallet') or '')
                    if _tt == 'token_transfer' and _amount:
                        _bbps = 0
                        try:
                            _trow = await self.token_repo.get(_ta)
                            if isinstance(_trow, dict):
                                _bbps = int((_trow.get('burn_fee_bps') or (_trow.get('data') or {}).get('burn_fee_bps') or 0) or 0)
                        except Exception:
                            _bbps = 0
                        _btax = _amount * _bbps // 10000 if _bbps > 0 else 0
                        _net = _amount - _btax
                        if _fw:
                            _k = (_ta, _fw)
                            _base_tok[_k] = int(_base_tok.get(_k, 0)) + _amount
                        if _tw:
                            _k = (_ta, _tw)
                            _base_tok[_k] = int(_base_tok.get(_k, 0)) - _net
                    elif _tt == 'token_burn' and _amount and _fw:
                        _k = (_ta, _fw)
                        _base_tok[_k] = int(_base_tok.get(_k, 0)) + _amount
                    elif _tt == 'token_create' and _fw:
                        try:
                            _sup = int((_stx.get('total_supply') or (_stx.get('data') or {}).get('total_supply') or 0) or 0)
                        except (TypeError, ValueError):
                            _sup = 0
                        if _sup:
                            try:
                                from_mod = False
                                _units = int(_sup) * int(config.SUBS)
                            except Exception:
                                _units = _sup
                            _k = (_ta, _fw)
                            _base_tok[_k] = int(_base_tok.get(_k, 0)) - _units
            bootstrap.logger.debug(f'[N-10-TOKEN-BASE-1] seeded {len(_base_tok)} token balance key(s) at common_height={common_height}')
        except Exception as _bse:
            bootstrap.logger.warning(f'[Reorg] ancestor balance seeding failed ({_bse}); pre-verify may use live tip balances')
        for b in sorted(new_blocks, key=lambda x: x['id']):
            if b['id'] > common_height:
                if not await self.verify_block_proof(b, _att_base, _maze_base, _branch_ctx, _proven_base):
                    bootstrap.logger.error(f'[Reorg] Block {b.get('id')} failed verification before reorg adoption; aborting reorg')
                    return False
                try:
                    _blk_last = maze._proven_sizes_from_updates(b.get('maze_updates'))
                except Exception as _pse:
                    bootstrap.logger.error(f'[Reorg] Block {b.get('id')} proven-state extension failed ({_pse}); aborting reorg')
                    return False
                if _blk_last:
                    _proven_base.update(_blk_last)
                try:
                    if _maze_base is not None:
                        for _mm, _mu in maze._last_updates_by_maze(b.get('maze_updates')).items():
                            _sp = _mu.get('spawn') or [0, 0, 0]
                            _maze_base[_mm] = {'posx': int(_sp[0]), 'posy': int(_sp[1]), 'posz': int(_sp[2]), 'movenonce': 0, 'lastactiveheight': int(b.get('id', 0))}
                except Exception as _mse:
                    bootstrap.logger.error(f'[Reorg] Block {b.get('id')} geometry-state extension failed ({_mse}); aborting reorg')
                    return False
                try:
                    _ba = b.get('maze_attestation') or {}
                    if _att_base is not None and isinstance(_ba, dict) and _ba.get('maze_id'):
                        _att_base[str(_ba.get('maze_id'))] = {'maze_id': str(_ba.get('maze_id')), 'last_size': int(_ba.get('size', 0)), 'last_block': int(b.get('id', 0)), 'last_block_hash': str(b.get('hash', '')), 'pubkey': str(_ba.get('pubkey', ''))}
                except Exception as _ase:
                    bootstrap.logger.error(f'[Reorg] Block {b.get('id')} attestation-state extension failed ({_ase}); aborting reorg')
                    return False
        try:
            _reorg_depth = int(self.height) - int(common_height)
        except (TypeError, ValueError):
            _reorg_depth = 0
        if _reorg_depth > config.PRUNE_BLOCKS:
            bootstrap.logger.error(f'[REORG] refused: depth {_reorg_depth} exceeds PRUNE_BLOCKS {config.PRUNE_BLOCKS} (common {common_height}, tip {self.height})')
            return False
        _rz_mem = (self.height, self.last_hash, self.total_minted, self.burned_total, self.blocks)
        _rz_slashes = list(self.consensus._pending_slashes)
        _rz_deferred = list(self.consensus._deferred_slashes)
        _rz_maze_updates = list(self.consensus._pending_maze_updates)
        if getattr(self, 'mempool', None) is not None:
            self.mempool.forget_confirmed()
        _rz_mempool = dict(self.mempool._transactions) if getattr(self, 'mempool', None) is not None else None
        _rz_final = self.finality_gadget.get_last_finalized_block()
        _rz_shrink = maze.GLOBAL_SHRINK_FACTOR
        _rz_mmut = getattr(self, 'mempool', None)
        _rz_pend = dict(_rz_mmut._pending_nonces) if _rz_mmut is not None and hasattr(_rz_mmut, '_pending_nonces') else None
        _rz_conf = dict(_rz_mmut._confirmed_nonces) if _rz_mmut is not None and hasattr(_rz_mmut, '_confirmed_nonces') else None
        try:
            _rz_dirty = dict(self.state_trie._dirty)
        except Exception:
            _rz_dirty = None
        try:
            async with await self.db.transaction():
                orphaned_blocks = []
                _fetch_from = int(common_height) + 1
                for _ in range(config.PRUNE_BLOCKS // 1000 + 2):
                    if _fetch_from > int(self.height):
                        break
                    _page = await self.block_repo.get_range(_fetch_from, self.height, limit=1000)
                    if not _page:
                        break
                    orphaned_blocks.extend(_page)
                    _fetch_from = max((int(b.get('id', 0)) for b in _page)) + 1
                    if len(orphaned_blocks) >= config.PRUNE_BLOCKS:
                        break
                orphaned_blocks = sorted(orphaned_blocks, key=lambda x: int(x.get('id', 0)))
                _reorg_shortfalls: list = []
                _touched_w: set = set()
                _touched_t: set = set()
                _reorg_deploys: list = []
                _reorg_token_creates: list = []
                _reorg_htlc_ids: list = []
                for b in orphaned_blocks:
                    reward = b.get('reward', 0)
                    winner = b.get('winner') or (b.get('miners') or [None])[0]
                    if winner and reward > 0:
                        if isinstance(winner, str) and winner.startswith('0x'):
                            winner_wallet = winner
                        elif b.get('reward_wallet'):
                            winner_wallet = b.get('reward_wallet')
                        else:
                            winner_miner = await self.miner_repo.get(winner)
                            winner_wallet = winner_miner.get('wallet') if winner_miner else None
                            if not winner_wallet:
                                _pub = b.get('producer_pub') or ''
                                if _pub:
                                    try:
                                        winner_wallet = util.pubkey_to_address(_pub)
                                    except Exception:
                                        winner_wallet = None
                        if winner_wallet:
                            await self.balance_repo.add(winner_wallet, -int(reward))
                            _touched_w.add(str(winner_wallet).lower())
                    if reward > 0:
                        _orphan_mint = gas._reorg_base_mint(b)
                        if _orphan_mint > 0:
                            self.total_minted = max(0, self.total_minted - _orphan_mint)
                            await self.network_state_repo.set('total_minted', str(self.total_minted))
                    for _ev in b.get('slashes') or []:
                        if _ev not in self.consensus._pending_slashes:
                            self.consensus._pending_slashes.append(dict(_ev))
                if orphaned_blocks:
                    try:
                        _affected = [str(r['maze_id']) for r in await self.maze_attestation_repo.get_all() or [] if int(r.get('last_block', 0)) > common_height]
                        await self.maze_attestation_repo.rollback_after(common_height)
                        if _affected:
                            await self._restore_attestations_upto(common_height, _affected)
                    except Exception as _e:
                        bootstrap.logger.warning(f'[IDEA5-ATTEST-REORG-1] attestation rollback failed: {_e}')
                _reorg_shortfalls = await self._invert_block_txs(common_height, None, _touched_w, _touched_t)
                _fork_block = await self.block_repo.get_by_id(common_height)
                if _fork_block:
                    await self._apply_maze_state(_fork_block)
                if self.db.db_type == 'sqlite':
                    await self.db.execute_dml('DELETE FROM balances WHERE bal = 0 AND NOT EXISTS (SELECT 1 FROM transactions WHERE block_id <= ? AND (from_wallet = balances.wallet OR to_wallet = balances.wallet))', common_height)
                else:
                    await self.db.execute_dml('DELETE FROM balances WHERE bal = 0 AND NOT EXISTS (SELECT 1 FROM transactions WHERE block_id <= $1 AND (from_wallet = balances.wallet OR to_wallet = balances.wallet))', common_height)
                self.height = common_height + 1
                if common_height > 0:
                    last_block = await self.block_repo.get_by_id(common_height)
                    self.last_hash = last_block.get('hash', '') if last_block else ''
                else:
                    self.last_hash = '0' * 64
                self.blocks = [b for b in self.blocks if b.get('id', 0) <= common_height]
                if _reorg_shortfalls:
                    _sf_wallets = sorted({str(w)[:16] for _, w, _, _ in _reorg_shortfalls})
                    _sf_hi = int(_rz_mem[0]) - 1
                    bootstrap.logger.error(f'[REORG] rollback of blocks {int(common_height) + 1}..{_sf_hi} left {len(_reorg_shortfalls)} debit shortfall(s) wallets={_sf_wallets}')
        except Exception as _rz_e:
            self.height, self.last_hash, self.total_minted, self.burned_total, self.blocks = _rz_mem
            self.consensus._pending_slashes = _rz_slashes
            self.consensus._deferred_slashes = _rz_deferred
            self.consensus._pending_maze_updates = _rz_maze_updates
            if _rz_mempool is not None and getattr(self, 'mempool', None) is not None:
                self.mempool._transactions = _rz_mempool
            try:
                if _rz_pend is not None and getattr(self, 'mempool', None) is not None:
                    self.mempool._pending_nonces = _rz_pend
                if _rz_conf is not None and getattr(self, 'mempool', None) is not None:
                    self.mempool._confirmed_nonces = _rz_conf
            except Exception as _le:
                bootstrap.logger.warning(f'[Reorg] nonce-map restore failed: {str(_le or '?')[:16]}')
            try:
                if _rz_dirty is not None:
                    self.state_trie._dirty = _rz_dirty
            except Exception as _le:
                bootstrap.logger.warning(f'[Reorg] state-trie dirt restore failed: {str(_le or '?')[:16]}')
            try:
                self.finality_gadget._last_finalized_block = _rz_final
            except Exception as _le:
                bootstrap.logger.warning(f'[Reorg] finality high-water restore failed: {str(_le or '?')[:16]}')
            maze.GLOBAL_SHRINK_FACTOR = _rz_shrink
            bootstrap.logger.error(f'[REORG] orphan rollback failed, in-memory mirrors restored: {_rz_e}')
            return False
        try:
            for b in sorted(new_blocks, key=lambda x: x['id']):
                if b['id'] > common_height:
                    await self._append_block(b)
            _adopted = sorted((b for b in new_blocks or [] if isinstance(b, dict) and int(b.get('id', -1)) > int(common_height)), key=lambda x: int(x.get('id', 0)))
            await self._assert_reorg_cumulative(common_height, orphaned_blocks, _adopted, int(_rz_mem[2]))
        except Exception as _adopt_e:
            bootstrap.logger.error(f'[REORG] adopt failed after rollback committed (fork {common_height}): {_adopt_e}')
            return False
        return True

    async def _apply_slash_event(self, ev: dict, block_id: int) -> bool:
        mid = ev.get('miner_id')
        amt = max(0, int(ev.get('amount', 0)))
        reason = ev.get('reason', '')
        ev_block = int(ev.get('block_id', block_id))
        if not mid:
            return False
        prior = await self.slash_repo.get_by_miner(mid)
        if any((int(r.get('block_id', -1)) == ev_block and r.get('reason') == reason for r in prior or [])):
            return False
        m = await self.miner_repo.get(mid)
        banned = False
        if m:
            m['rewards'] = max(0, int(m.get('rewards', 0)) - amt)
            if reason == 'equivocation':
                m['active'] = 0
                m['banned_until'] = bootstrap.time.time() + config.BAN_DURATION
                await self.maze_repo.update_miner_inactive(mid)
                banned = True
            elif reason == 'signing_refusal':
                m['consecutive_misses'] = int(m.get('consecutive_misses', 0)) + 1
                if m['consecutive_misses'] >= config.MAX_MISSES:
                    m['active'] = 0
                    m['banned_until'] = bootstrap.time.time() + config.BAN_DURATION
                    await self.maze_repo.update_miner_inactive(mid)
                    banned = True
            await self.miner_repo.update(m)
        else:
            bootstrap.logger.info(f'[IMPORT-SLASH] no local row for miner {mid} in block {block_id}; recording event only')
        await self.slash_repo.create(mid, amt, reason or 'unknown', ev_block)
        return banned

    async def _apply_maze_state(self, block: dict) -> None:
        _ms = block.get('maze_state') or []
        if not isinstance(_ms, list):
            raise AuxStateError(f'malformed maze_state in block {block.get('id')}')
        if not _ms:
            return
        _att = block.get('maze_attestation') or {}
        _att_mid = str(_att.get('maze_id', '') or '').lower() if isinstance(_att, dict) else ''
        _bid = int(block.get('id', 0))
        for _e in _ms:
            if not isinstance(_e, dict):
                raise AuxStateError(f'malformed maze_state entry in block {_bid}')
            _mid = str(_e.get('maze_id', '') or '')
            if not _mid:
                raise AuxStateError(f'maze_state entry without maze_id in block {_bid}')
            if _att_mid and _mid.lower() == _att_mid:
                if str(_e.get('minerid', '') or '').lower() == _att_mid and (not str(_e.get('minerid', '') or '')):
                    raise AuxStateError(f'maze_state entry for attested maze has no minerid in block {_bid}')
            existing = await self.maze_repo.get_by_maze_id(_mid)
            if existing:
                row = dict(existing)
                for _k in maze._MAZE_STATE_COLUMNS:
                    if _k in _e and _k != 'maze_id':
                        row[_k] = _e[_k]
                row['updatedat'] = int(bootstrap.time.time())
                row.setdefault('createdat', int(bootstrap.time.time()))
                await self.maze_repo.upsert(row)
            else:
                await self.maze_repo.upsert({'maze_id': _mid, 'minerid': _e.get('minerid', _mid), 'size': int(_att.get('size', config.MIN_MAZE_SIZE) or config.MIN_MAZE_SIZE) if _att_mid and _mid.lower() == _att_mid else config.MIN_MAZE_SIZE, 'walldensityppm': _e.get('walldensityppm', maze.MIN_WALL_DENSITY_PPM), 'seed': _e.get('seed', ''), 'posx': 0, 'posy': 0, 'posz': 0, 'goalx': _e.get('goalx', 0), 'goaly': _e.get('goaly', 0), 'goalz': _e.get('goalz', 0), 'movenonce': 0, 'consecutivewallhits': 0, 'turbulenceppm': 0, 'growthcount': 0, 'knowledge': 0, 'lastgoalheight': _bid, 'lastactiveheight': _bid, 'mazeroot': '', 'invitedguest': None, 'guestlock': False, 'lastknowledgeheight': 0, 'createdat': int(bootstrap.time.time()), 'updatedat': int(bootstrap.time.time()), 'ghostx': None, 'ghosty': None, 'ghostz': None})

    async def _append_block(self, block: dict):
        _vbase = gas._validated_block_reward(block, self.total_minted)
        if _vbase is None:
            raise AuxStateError(f'reward/subsidy/supply mismatch in block {block.get('id')}')
        _vbase = _vbase[0]
        _lok, _lreason = gas._block_limits_ok(block.get('transactions'))
        if not _lok:
            raise AuxStateError(f'block {block.get('id')} exceeds block limits: {_lreason}')
        async with await self.db.transaction():
            await self.block_repo.create(block)
            _pending_svf_epoch_root = None
            if svf.svf_active_at(block['id']):
                try:
                    _ev = svf.compute_block_evidence(block, block['id'])
                    if _ev is not None:
                        _ev_epoch = block['id'] // svf.SVF_EPOCH_BLOCKS
                        self.svf_evidence_store.setdefault(_ev_epoch, []).append(_ev)
                        _ev_rec = {'epoch_id': _ev_epoch, 'height': _ev.block_id, 'block_hash': _ev.block_hash, 'winner_pubkey': _ev.winner_pubkey, 'attested_size': _ev.attested_size, 'attestation_weight': str(_ev.attestation_weight), 'growth_present': 1 if _ev.growth_present else 0, 'record_hash': _ev.record_hash.hex()}
                        if self.db.db_type == 'sqlite':
                            await self.db.execute_dml('INSERT OR REPLACE INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES (?,?,?,?,?,?,?,?)', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                        else:
                            await self.db.execute_dml('INSERT INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (epoch_id, height) DO UPDATE SET block_hash=$3, winner_pubkey=$4, attested_size=$5, attestation_weight=$6, growth_present=$7, record_hash=$8', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                        bootstrap.logger.debug(f'[SVF] block {block['id']}: evidence persisted for epoch {_ev_epoch}')
                    _epoch_recs = self.svf_evidence_store.get(_ev_epoch, [])
                    _root = svf._svf_epoch_root_if_complete(_epoch_recs, _ev_epoch)
                    if _root is not None:
                        _pending_svf_epoch_root = (_ev_epoch, _root)
                except svf.SVFReject:
                    pass
                except Exception as _ev_e:
                    raise AuxStateError(f'SVF evidence extraction failed for block {block['id']}: {_ev_e}') from _ev_e
            winner = block.get('winner')
            if not winner:
                _miners = block.get('miners')
                if isinstance(_miners, str) and _miners and (not _miners.startswith('[')):
                    winner = _miners
                elif isinstance(_miners, list) and _miners:
                    winner = _miners[0]
            for ev in block.get('slashes') or []:
                try:
                    await self._apply_slash_event(ev, block['id'])
                except AuxStateError:
                    raise
                except Exception as e:
                    raise AuxStateError(f'slashes of block {block.get('id')}: {e}') from e
            if bool(block.get('transactions', [])) != bool(block.get('tx_hashes', [])):
                raise RuntimeError(f'transactions/tx_hashes presence mismatch in block {block.get('id')}')
            _replay_error = None
            _sealed_hashes: list = []
            for tx_data in block.get('transactions', []):
                try:
                    success, result = await self.execute_transaction(tx_data, block['id'], block_ts=block.get('ts'))
                except Exception as e:
                    _replay_error = f'crash on {str(tx_data.get('tx_hash') or '?')[:16]}: {e}'
                    break
                if not success:
                    _replay_error = f'replay failed on {str(tx_data.get('tx_hash') or '?')[:16]}: {result}'
                    break
                _declared_fee = tx_data.get('_fee_charged', tx_data.get('fee', 0))
                _recomputed_fee = result.get('fee_charged', tx_data.get('fee', 0))
                if int(_declared_fee or 0) != int(_recomputed_fee or 0):
                    _replay_error = f'fee mismatch on {str(tx_data.get('tx_hash') or '?')[:16]}: block declares {_declared_fee}, recomputed {_recomputed_fee}'
                    break
                _declared_gas = tx_data.get('_gas_used')
                _recomputed_gas = result.get('gas_used')
                try:
                    _dg = int(_declared_gas) if _declared_gas is not None else -1
                    _rg = int(_recomputed_gas) if _recomputed_gas is not None else -2
                except (TypeError, ValueError):
                    _dg, _rg = (-1, -2)
                if _dg != _rg:
                    _replay_error = f'gas_used mismatch on {str(tx_data.get('tx_hash') or '?')[:16]}: block declares {_declared_gas}, recomputed {_recomputed_gas}'
                    break
                if getattr(self, 'mempool', None) is not None:
                    _sealed_hashes.append(tx_data.get('tx_hash', ''))
            if _replay_error:
                bootstrap.logger.error(f'[Block] {_replay_error} — aborting import of block {block['id']}')
                raise RuntimeError(_replay_error)
            reward = block.get('reward', 0)
            if winner and reward > 0:
                winner_wallet = None
                if isinstance(winner, str) and winner.startswith('0x'):
                    winner_wallet = winner
                elif block.get('reward_wallet'):
                    winner_wallet = block.get('reward_wallet')
                else:
                    winner_miner = await self.miner_repo.get(winner)
                    if winner_miner and winner_miner.get('wallet'):
                        winner_wallet = winner_miner.get('wallet')
                if not winner_wallet:
                    pub = block.get('producer_pub') or ''
                    if pub:
                        try:
                            winner_wallet = util.pubkey_to_address(pub)
                        except Exception:
                            winner_wallet = None
                if winner_wallet:
                    await self.balance_repo.add(winner_wallet, reward)
                else:
                    bootstrap.logger.warning(f'[IMPORT-REWARD] Cannot resolve wallet for winner {winner} in block {block['id']}; reward {reward} not credited')
            if reward > 0:
                _mint = _vbase
                if _mint > 0:
                    if self.total_minted + _mint > config.MAX_SUPPLY:
                        raise AuxStateError(f'mint of block {block.get('id')} exceeds MAX_SUPPLY')
                    self.total_minted += _mint
                    await self.network_state_repo.set('total_minted', str(self.total_minted))
            for update in block.get('maze_updates', []):
                try:
                    mid = update.get('maze_id') or update.get('miner_id')
                    if not mid:
                        continue
                    existing = await self.maze_repo.get_by_maze_id(mid)
                    if existing:
                        existing = dict(existing)
                        if 'new_size' in update:
                            _sz = maze._valid_maze_size(update['new_size'])
                            if _sz is None:
                                bootstrap.logger.warning(f'[Block] Skipping maze_update with invalid size {update['new_size']!r} for {mid[:16]}')
                                continue
                            existing['size'] = _sz
                        if 'seed' in update:
                            existing['seed'] = update['seed']
                        if 'mazeroot' in update:
                            existing['mazeroot'] = update['mazeroot']
                        if 'new_density' in update:
                            existing['walldensityppm'] = update['new_density']
                        if 'goal' in update and len(update['goal']) == 3:
                            existing['goalx'], existing['goaly'], existing['goalz'] = update['goal']
                        if 'spawn' in update and len(update['spawn']) == 3:
                            existing['posx'], existing['posy'], existing['posz'] = update['spawn']
                        if 'turbulenceppm' in update:
                            existing['turbulenceppm'] = update['turbulenceppm']
                        if 'new_growthcount' in update:
                            existing['growthcount'] = update['new_growthcount']
                        existing['movenonce'] = 0
                        existing['lastactiveheight'] = block['id']
                        await self.maze_repo.upsert(existing)
                    else:
                        goal = update.get('goal', [0, 0, 0])
                        spawn = update.get('spawn', [0, 0, 0])
                        new_row = {'maze_id': mid, 'minerid': update.get('miner_id', mid), 'size': maze._valid_maze_size(update.get('new_size', config.MIN_MAZE_SIZE)) or config.MIN_MAZE_SIZE, 'walldensityppm': update.get('new_density', maze.MIN_WALL_DENSITY_PPM), 'seed': update.get('seed', ''), 'posx': spawn[0], 'posy': spawn[1], 'posz': spawn[2], 'goalx': goal[0], 'goaly': goal[1], 'goalz': goal[2], 'movenonce': 0, 'consecutivewallhits': 0, 'turbulenceppm': update.get('turbulenceppm', 0), 'growthcount': update.get('new_growthcount', 0), 'knowledge': update.get('knowledge', 0), 'lastgoalheight': block['id'], 'lastactiveheight': block['id'], 'mazeroot': update.get('mazeroot', ''), 'invitedguest': None, 'guestlock': False, 'createdat': int(bootstrap.time.time()), 'updatedat': int(bootstrap.time.time())}
                        await self.maze_repo.upsert(new_row)
                    try:
                        _mpr = getattr(self, 'maze_proof_repo', None)
                        if _mpr is not None and isinstance(update, dict) and (maze._valid_maze_size(update.get('new_size')) is not None):
                            await _mpr.upsert(mid, update, block['id'])
                    except Exception as _mp_e:
                        bootstrap.logger.warning(f'[Block] maze_proof upsert failed for {str(mid)[:16]}: {_mp_e}')
                except Exception as e:
                    bootstrap.logger.warning(f'[Block] Failed to apply maze_update: {e}')
            for _pu in block.get('attestation_proof') or []:
                try:
                    _pmid = _pu.get('maze_id') or _pu.get('miner_id') if isinstance(_pu, dict) else None
                    if not _pmid:
                        continue
                    _mpr2 = getattr(self, 'maze_proof_repo', None)
                    if _mpr2 is not None and maze._valid_maze_size(_pu.get('new_size')) is not None:
                        await _mpr2.upsert(_pmid, _pu, block['id'])
                except Exception as _mp2_e:
                    bootstrap.logger.warning(f'[Block] maze_proof upsert (attestation_proof) failed: {_mp2_e}')
            await self._apply_maze_state(block)
            for _e in block.get('maze_state') or []:
                if not isinstance(_e, dict):
                    continue
                _mid = str(_e.get('maze_id') or '')
                if not _mid:
                    continue
                _row = await self.maze_repo.get_by_maze_id(_mid)
                if _row is None:
                    raise AuxStateError(f'maze_state maze {_mid[:16]} missing after apply in block {block.get('id')}')
                for _k in maze._MAZE_STATE_COLUMNS:
                    if _k == 'maze_id':
                        continue
                    if _k in _e and str(_row.get(_k, '')) != str(_e.get(_k, '')):
                        raise AuxStateError(f'maze_state mismatch for {_mid[:16]} column {_k} in block {block.get('id')}')
            if int(block.get('id', 0)) > 0 and block.get('state_root'):
                _post_root = await db._compute_full_state_root(self.db, self, int(block['id']))
                if _post_root != block.get('state_root'):
                    raise AuxStateError(f'state_root of block {block.get('id')} does not match post-apply state')
            if _pending_svf_epoch_root is not None:
                _pe, _pr = _pending_svf_epoch_root
                self.svf_epoch_roots[_pe] = (_pr, svf.SVF_EPOCH_BLOCKS)
                _pr_hex = _pr.hex()
                if self.db.db_type == 'sqlite':
                    await self.db.execute_dml('INSERT OR REPLACE INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES (?,?,?,?)', _pe, _pr_hex, svf.SVF_EPOCH_BLOCKS, 1)
                else:
                    await self.db.execute_dml('INSERT INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES ($1,$2,$3,$4) ON CONFLICT (epoch_id) DO UPDATE SET root_hash=$2, record_count=$3, complete=$4', _pe, _pr_hex, svf.SVF_EPOCH_BLOCKS, 1)
                bootstrap.logger.debug(f'[SVF] block {block['id']}: epoch {_pe} root persisted')
            _block_certs = block.get('svf_epoch_certificates') or []
            if _block_certs:
                _cert = _block_certs[0]
                _cert_epoch = int(_cert.get('evidence_epoch', -1))
                if _cert_epoch >= 0:
                    _cert_sig = _cert.get('threshold_signature') or _cert.get('signature', '')
                    self.svf_certificates[_cert_epoch] = {'evidence_epoch': _cert_epoch, 'anchor_block_hash': _cert.get('anchor_block_hash', ''), 'evidence_root': _cert.get('evidence_root', ''), 'group_pubkey': _cert.get('group_pubkey', ''), 'threshold_signature': _cert_sig, 'inclusion_block': int(block['id']), 'usable_from': int(block['id']) + 1}
                    if self.db.db_type == 'sqlite':
                        await self.db.execute_dml('INSERT OR REPLACE INTO svf_certificates (evidence_epoch, chain_id, committee_epoch, window_start_height, window_end_height, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from) VALUES (?,?,?,?,?,?,?,?,?,?,?)', _cert_epoch, int(config.CHAIN_ID), 0, _cert_epoch * svf.SVF_EPOCH_BLOCKS, _cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1, _cert.get('anchor_block_hash', ''), _cert.get('evidence_root', ''), _cert.get('group_pubkey', ''), _cert_sig, int(block['id']), int(block['id']) + 1)
                    else:
                        await self.db.execute_dml('INSERT INTO svf_certificates (evidence_epoch, chain_id, committee_epoch, window_start_height, window_end_height, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (evidence_epoch) DO UPDATE SET chain_id=$2, committee_epoch=$3, window_start_height=$4, window_end_height=$5, anchor_block_hash=$6, evidence_root=$7, group_public_key_id=$8, threshold_signature=$9, inclusion_block=$10, usable_from=$11', _cert_epoch, int(config.CHAIN_ID), 0, _cert_epoch * svf.SVF_EPOCH_BLOCKS, _cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1, _cert.get('anchor_block_hash', ''), _cert.get('evidence_root', ''), _cert.get('group_pubkey', ''), _cert_sig, int(block['id']), int(block['id']) + 1)
                    bootstrap.logger.debug(f'[SVF] block {block['id']}: certificate for epoch {_cert_epoch} applied (dict + DB), usable from block {int(block['id']) + 1}')
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('INSERT OR REPLACE INTO block_state_roots (block_id, state_root, receipt_root) VALUES (?, ?, ?)', block['id'], block.get('state_root', ''), block.get('receipt_root', '0x' + '00' * 32))
            else:
                await self.db.execute_dml('INSERT INTO block_state_roots (block_id, state_root, receipt_root) VALUES ($1, $2, $3) ON CONFLICT (block_id) DO UPDATE SET state_root=$2, receipt_root=$3', block['id'], block.get('state_root', ''), block.get('receipt_root', '0x' + '00' * 32))
            _att = block.get('maze_attestation')
            if isinstance(_att, dict) and _att.get('maze_id') and (_att.get('size') is not None):
                _av = config._effective_validators()
                if _av and config._normalize_validator_key(_att.get('pubkey', '')) not in _av:
                    raise AuxStateError(f'attestation key not in validator set in block {block.get('id')}')
                try:
                    await self.maze_attestation_repo.upsert({'maze_id': str(_att['maze_id']), 'last_size': int(_att['size']), 'last_block': int(block['id']), 'last_block_hash': str(block.get('hash', '')), 'pubkey': str(_att.get('pubkey', ''))})
                except Exception as _e:
                    raise AuxStateError(f'maze_attestation of block {block.get('id')}: {_e}') from _e
            await self.distribute_token_mining_rewards(block['id'])
        if getattr(self, 'mempool', None) is not None:
            for _h in _sealed_hashes:
                if _h:
                    await self.mempool.remove(_h)
            for _stx in block.get('transactions', []):
                try:
                    _w = _stx.get('from_wallet', '') if isinstance(_stx, dict) else ''
                    if _w:
                        self.mempool.note_confirmed_nonce(_w, int(_stx.get('nonce', 0)) + 1)
                        try:
                            await self._account_nonce_note(_w, int(_stx.get('nonce', 0)) + 1)
                        except Exception as _ne:
                            bootstrap.logger.warning(f'[Import] account_nonces store skipped tx {str(_stx.get('tx_hash') or '?')[:16]}: {_ne}')
                except (TypeError, ValueError) as _le:
                    bootstrap.logger.warning(f'[Import] confirmed-nonce wire skipped tx {str(_stx.get('tx_hash') or '?')[:16]}: {str(_le or '?')[:16]}')
        await self.finality_gadget.on_block(block)
        self.blocks.append(block)
        if len(self.blocks) > maze.BLOCK_CACHE_MAX:
            self.blocks = self.blocks[-maze.BLOCK_CACHE_MAX:]
        self.height = block['id'] + 1
        self.last_hash = block.get('hash', '')
        if getattr(self, 'health_checker', None) is not None:
            self.health_checker.last_block_time = bootstrap.time.time()
        if 'global_shrink_factor' in block:
            maze.GLOBAL_SHRINK_FACTOR = float(block['global_shrink_factor'])
        height_msg = {'type': 'block_height_update', 'height': self.height, 'block_id': block['id']}
        for mid, mws in list(self.miner_websockets.items()):
            try:
                await mws.send_json(height_msg)
            except Exception as _le:
                bootstrap.logger.warning(f'[Import] height broadcast failed miner {str(mid or '?')[:16]}: {str(_le or '?')[:16]}')

    async def receive_transaction(self, tx_data: bootstrap.Dict) -> bool:
        tx_hash = tx_data.get('tx_hash')
        if not tx_hash:
            return False
        is_valid_hash = False
        sig = tx_data.get('signature', '')
        decoded = None
        if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
            try:
                decoded = util.decode_raw_eth_transaction(sig)
                if decoded.get('hash', '').lower() == tx_hash.lower():
                    is_valid_hash = True
            except Exception as e:
                bootstrap.logger.warning(f'[Verify] Raw eth tx decode failed for {tx_hash[:16]}: {e}')
        if decoded is not None:
            if not util._raw_chain_id_ok(decoded):
                bootstrap.logger.debug(f'[TX] Rejected {tx_hash[:12]}: bad chain_id {decoded.get('chainId')}')
                return False
        if not is_valid_hash:
            tx_body = {k: v for k, v in tx_data.items() if k != 'tx_hash'}
            if crypto.hash_tx(tx_body) == tx_hash:
                is_valid_hash = True
        if not is_valid_hash:
            bootstrap.logger.debug('[TX] Rejected: tx_hash does not match tx contents')
            return False
        if not self._verify_tx_signature(tx_data):
            bootstrap.logger.debug(f'[TX] Rejected {tx_hash[:12]}: invalid signature')
            return False
        existing = await self.tx_repo.get_by_hash(tx_hash)
        if existing:
            return True
        if not await self.mempool.add(tx_data):
            return False
        tx_data['status'] = 'pending'
        tx_data['confirmed'] = False
        tx_data['block_id'] = -1
        await self.tx_repo.create(tx_data)
        if self.p2p:
            bootstrap.asyncio.create_task(self.p2p.broadcast_transaction(tx_data))
        return True

    async def distribute_token_mining_rewards(self, block_id: int):
        return

    async def send_to_miner(self, miner_id: str, message: dict) -> bool:
        ws = self.miner_websockets.get(miner_id)
        if not ws:
            bootstrap.logger.warning(f'[WS] No websocket for miner {miner_id}')
            return False
        try:
            await ws.send_str(bootstrap.json.dumps(message))
            bootstrap.logger.debug(f'[WS] Sent to {miner_id}: {message.get('type')}')
            return True
        except Exception as e:
            bootstrap.logger.error(f'[WS] Send to {miner_id} failed: {e}')
            if miner_id in self.miner_websockets:
                del self.miner_websockets[miner_id]
            return False

    async def cleanup_miners(self):
        timeout = maze.ACTIVE_MINER_WINDOW_SEC
        now = bootstrap.time.time()
        active_miners = await self.miner_repo.get_active()
        for miner in active_miners:
            last_ping = miner.get('last_ping', 0)
            if isinstance(last_ping, float):
                age = now - last_ping
            else:
                age = now - last_ping.timestamp() if hasattr(last_ping, 'timestamp') else 9999
            if age > timeout:
                miner['active'] = False
                await self.miner_repo.update(miner)
                self.miners.pop(miner['miner_id'], None)
                self.miner_rate_limiters.pop(miner['miner_id'], None)
                ws = self.miner_websockets.pop(miner['miner_id'], None)
                if ws:
                    try:
                        await ws.close(code=1000, message=b'inactive')
                    except Exception:
                        pass
                bootstrap.logger.info(f'[Cleanup] Deactivated inactive miner: {miner['miner_id'][:16]}... (age: {age:.0f}s)')

    async def cleanup_nodes(self):
        timeout = 600
        now = bootstrap.time.time()
        active_nodes = await self.node_repo.get_active()
        for node in active_nodes:
            if node.get('node_id') == self.node_id:
                continue
            last_seen = node.get('last_seen', 0)
            if isinstance(last_seen, float):
                age = now - last_seen
            else:
                age = now - last_seen.timestamp() if hasattr(last_seen, 'timestamp') else 9999
            if age > timeout:
                node['active'] = False
                await self.node_repo.update(node)
                bootstrap.logger.info(f'[Cleanup] Deactivated inactive node: {node['node_id'][:16]}... (age: {age:.0f}s)')

    async def _mempool_restore(self):
        try:
            rows = await self.db.fetch('SELECT tx_json FROM mempool_persist')
        except Exception as e:
            bootstrap.logger.warning(f'[Mempool] restore query failed: {e}')
            return
        restored = 0
        for r in rows or []:
            try:
                tx = bootstrap.json.loads(r['tx_json'])
            except Exception:
                continue
            tx_hash = tx.get('tx_hash')
            if not tx_hash:
                continue
            try:
                existing = await self.tx_repo.get_by_hash(tx_hash)
                if existing and existing.get('status') != 'pending':
                    await self.mempool._unpersist(tx_hash)
                    continue
                if await self.mempool.add(tx):
                    restored += 1
            except Exception as e:
                bootstrap.logger.debug(f'[Mempool] restore skipped {str(tx_hash)[:16]}: {e}')
        if restored:
            bootstrap.logger.info(f'[Mempool] Restored {restored} persisted tx(s) after restart')

    async def _automation_loop(self):
        while not self._shutdown_flag:
            await bootstrap.asyncio.sleep(1.0)
            try:
                active_autos = await self.automation_repo.list_active()
                now = bootstrap.time.time()
                for auto in active_autos:
                    trigger_type = auto.get('trigger_type')
                    t_conf = auto.get('trigger_config', {})
                    last_run = auto.get('last_run_at') or auto.get('created_at', now)
                    should_run = False
                    if trigger_type == 'time_interval':
                        interval = float(t_conf.get('interval_seconds', 60))
                        if now - last_run >= interval:
                            should_run = True
                    elif trigger_type == 'block':
                        target_block = int(t_conf.get('target_block', 0))
                        interval_blocks = int(t_conf.get('interval_blocks', 0))
                        if target_block > 0 and self.height >= target_block and (auto.get('run_count', 0) == 0):
                            should_run = True
                        elif interval_blocks > 0:
                            last_block = int(auto.get('last_block_run', 0) or 0)
                            if self.height - last_block >= interval_blocks:
                                should_run = True
                    elif trigger_type == 'condition':
                        cond_type = t_conf.get('condition_type')
                        if cond_type == 'balance_below':
                            target_wallet = t_conf.get('wallet')
                            threshold = int(t_conf.get('threshold', 0))
                            bal = await self.balance_repo.get(target_wallet)
                            if bal < threshold:
                                should_run = True
                    if should_run:
                        a_conf = auto.get('action_config', {}) or {}
                        run_count = int(auto.get('run_count', 0))
                        res_msg = 'success'
                        try:
                            pre_signed = a_conf.get('txs') or []
                            bad = None
                            if not isinstance(pre_signed, list) or run_count >= len(pre_signed):
                                bad = 'Pre-signed transaction missing or exhausted'
                            else:
                                tx_data = dict(pre_signed[run_count])
                                if not tx_data.get('tx_hash'):
                                    tx_data['tx_hash'] = crypto.hash_tx(tx_data)
                                if not self._verify_tx_signature(tx_data):
                                    bad = 'Pre-signed transaction failed signature verification'
                                elif not await self.mempool.add(tx_data):
                                    bad = 'Pre-signed transaction rejected by mempool'
                                else:
                                    if self.p2p:
                                        await self.p2p.broadcast_transaction(tx_data)
                                    res_msg = f'Queued pre-signed tx {str(tx_data['tx_hash'])[:16]}'
                            if bad is not None:
                                res_msg = bad
                                await self.automation_repo.update_run(auto['id'], now, run_count + 1, res_msg, last_block_run=self.height)
                                await self.automation_repo.set_enabled(auto['id'], False)
                                bootstrap.logger.warning(f'[Automation] Disabled {auto.get('name', auto['id'])}: {res_msg}')
                                continue
                        except Exception as act_err:
                            res_msg = f'Action error: {act_err}'
                        new_count = run_count + 1
                        await self.automation_repo.update_run(auto['id'], now, new_count, res_msg, last_block_run=self.height)
                        bootstrap.logger.info(f'[Automation] Ran {auto.get('name', auto['id'])}: {res_msg}')
            except Exception as e:
                bootstrap.logger.debug(f'[Automation] Loop error: {e}')

    async def _prune_floor(self):
        try:
            height = int(getattr(self, 'height', 0) or 0)
            current_epoch = height // svf.SVF_EPOCH_BLOCKS
            cert_epochs = set()
            _certs_ok = False
            try:
                _rows = await self.db.fetch('SELECT evidence_epoch FROM svf_certificates')
                _certs_ok = True
                for _r in _rows or []:
                    try:
                        cert_epochs.add(int(_r['evidence_epoch']))
                    except (TypeError, ValueError, KeyError):
                        continue
            except Exception:
                _certs_ok = False
            counts = {}
            _ev_ok = False
            try:
                _rows = await self.db.fetch('SELECT epoch_id, COUNT(*) AS cnt FROM svf_evidence GROUP BY epoch_id')
                _ev_ok = True
                for _r in _rows or []:
                    try:
                        counts[int(_r['epoch_id'])] = int(_r['cnt'])
                    except (TypeError, ValueError, KeyError):
                        continue
            except Exception:
                _ev_ok = False
            if not _certs_ok or not _ev_ok:
                return 0
            if height >= svf.SVF_EPOCH_BLOCKS and (not counts):
                return 0
            floor = None
            epochs = set(counts.keys())
            epochs.add(current_epoch)
            for ep in epochs:
                if ep in cert_epochs:
                    continue
                if ep <= 0:
                    continue
                complete = counts.get(ep, 0) >= svf.SVF_EPOCH_BLOCKS
                if not complete and ep != current_epoch:
                    continue
                start = ep * svf.SVF_EPOCH_BLOCKS
                floor = start if floor is None else min(floor, start)
            return floor
        except Exception:
            return 0

    async def _cleanup_loop(self):
        while not self._shutdown_flag:
            await bootstrap.asyncio.sleep(15)
            try:
                await self.cleanup_miners()
                await self.cleanup_nodes()
                max_blocks = self.config.get('consensus', {}).get('prune_blocks', 10000)
                if self.height > max_blocks:
                    prune_height = self.height - max_blocks
                    _floor = await self._prune_floor()
                    if _floor is not None and _floor < prune_height:
                        prune_height = _floor
                        bootstrap.logger.info(f'[Cleanup] Prune floor {_floor}: retaining anchor/proof-source blocks for uncertified epochs')
                    if prune_height > 0:
                        await self.db.execute_dml('DELETE FROM blocks WHERE id < ?', prune_height)
                        await self.db.execute_dml('DELETE FROM transactions WHERE block_id < ?', prune_height)
                        bootstrap.logger.info(f'[Cleanup] Pruned blocks and transactions older than {prune_height}')
            except Exception as e:
                bootstrap.logger.error(f'[Cleanup] Error: {e}')

    def get_public_key_hex(self) -> str:
        priv_int = int(self.priv, 16)
        try:
            priv_key = bootstrap.ec.derive_private_key(priv_int, bootstrap.ec.SECP256K1())
        except TypeError:
            priv_key = bootstrap.ec.derive_private_key(priv_int, bootstrap.ec.SECP256K1)
        pub = priv_key.public_key()
        x = pub.public_numbers().x.to_bytes(32, 'big')
        y = pub.public_numbers().y.to_bytes(32, 'big')
        return (b'\x04' + x + y).hex()

    async def ensure_genesis(self):
        await self.db.create_tables()
        if not self.wallet or not self.priv:
            self._setup_wallet()
            self.node_id = self.wallet
        latest = await self.block_repo.get_latest()
        if latest:
            await self._load_state()
            await self._bind_genesis_to_db()
            await self._register_self_node()
            self._genesis_handled = True
            bootstrap.logger.info('Loaded existing blockchain.')
            return True
        bootstrap.logger.info('No local blockchain. Attempting to join network via P2P...')
        default_timeout = 60
        max_discovery_time = self.config.get('p2p', {}).get('discovery_timeout', default_timeout) if self.p2p else 0
        bootstrap.logger.info(f'[Genesis] P2P discovery window: {max_discovery_time}s (override with p2p.discovery_timeout in config.yaml)')
        start = bootstrap.time.time()
        discovered = False
        last_peer_count = -1
        last_log_at = 0.0
        while self.p2p and bootstrap.time.time() - start < max_discovery_time and (not discovered):
            for p in list(self.p2p.peers.values()):
                try:
                    bootstrap.asyncio.create_task(self.p2p._send_message(p, config.MSG_GET_STATUS, b'{}'))
                except Exception:
                    pass
            await self.p2p.sync_with_peers()
            latest = await self.block_repo.get_latest()
            if latest:
                await self._load_state()
                await self._register_self_node()
                self._genesis_handled = True
                bootstrap.logger.info('Synced blockchain from network.')
                return True
            peer_count = self.p2p.get_peer_count() if self.p2p else 0
            now = bootstrap.time.time()
            if peer_count != last_peer_count or now - last_log_at >= 5.0:
                elapsed = int(now - start)
                if self.p2p and self.p2p.peers:
                    max_remote_h = max((p.height for p in self.p2p.peers.values()))
                    remote_h_str = str(max_remote_h)
                else:
                    remote_h_str = 'unknown'
                bootstrap.logger.info(f'[Genesis] Discovery progress: {elapsed}s elapsed, peers={peer_count}, remote_height={remote_h_str}')
                last_peer_count = peer_count
                last_log_at = now
            await bootstrap.asyncio.sleep(2)
        peer_count = self.p2p.get_peer_count() if self.p2p else 0
        if getattr(self, '_allow_new_genesis', False):
            if self.p2p and peer_count == 0:
                bootstrap.logger.warning(f'[Genesis] P2P discovery window closed with 0 peers. Check p2p.dns_seeds and p2p.bootstrap_nodes in config.yaml — they must point to a running node reachable on its P2P port. --allow-new-genesis is set: deliberately creating a NEW chain.')
            else:
                bootstrap.logger.info('Creating genesis block for a deliberate new chain (--allow-new-genesis).')
            try:
                await self._create_genesis()
            except Exception as _ge:
                bootstrap.logger.error(f'[Genesis] --allow-new-genesis create failed: {_ge}')
                bootstrap.logger.error(bootstrap.traceback.format_exc())
                raise
            await self._register_self_node()
            self._genesis_handled = True
            bootstrap.logger.info('[Genesis] New chain genesis committed successfully')
            return True
        _local = genesis.load_genesis_file()
        if _local:
            _vok, _vwhy = genesis.genesis_export_verified(_local)
            if not _vok:
                bootstrap.logger.error(f'[Genesis] Local genesis.json failed verification ({_vwhy}); refusing to join with an untrusted identity. Copy the file from the network you intend to join.')
                bootstrap.sys.exit(1)
            _pin_why = config._genesis_pin_failure(str((_local or {}).get('hash', '')), config.EXPECTED_GENESIS_PIN)
            if _pin_why:
                bootstrap.logger.error(f'[Genesis] {_pin_why}; refusing to join. Use the genesis.json of the pinned chain.')
                bootstrap.sys.exit(1)
            await self._create_genesis()
            await self._register_self_node()
            self._genesis_handled = True
            bootstrap.logger.info('[Genesis] Restored verified local genesis; syncing the remaining chain from peers (production paused until sync establishes state).')
            return False
        bootstrap.logger.error('[Genesis] No local chain, no syncable peers, and no genesis.json. Joining nodes never create a genesis: copy genesis.json from the network you intend to join (mismatched identities are rejected), or restart with --allow-new-genesis for a DELIBERATE new chain. Refusing to boot.')
        bootstrap.sys.exit(1)

    async def _bind_genesis_to_db(self):
        g0 = await self.block_repo.get_by_id(0)
        if not g0:
            bootstrap.logger.warning('[GENESIS] no persisted genesis block (id 0) to bind genesis.json against')
            return
        db_hash = str(g0.get('hash') or '').lower()
        if not db_hash:
            bootstrap.logger.error('[GENESIS] persisted genesis block has no hash; refusing to start')
            bootstrap.sys.exit(1)
        gd = genesis.load_genesis_file()
        file_hash = str((gd or {}).get('hash') or '').lower()
        if file_hash:
            if file_hash != db_hash:
                bootstrap.logger.error(f"[GENESIS] genesis.json ({bootstrap.os.path.abspath(config.GENESIS_FILE)}) hash {file_hash[:16]}... does NOT match the genesis block stored in this node's database ({db_hash[:16]}...). Refusing to start: use the genesis.json this database was created from, or a fresh data directory/database for the new chain.")
                bootstrap.sys.exit(1)
            return
        genesis._node_genesis_hash = db_hash
        try:
            genesis.FORK_ID = int(db_hash[:8], 16) ^ int(db_hash[8:16], 16)
        except ValueError:
            bootstrap.logger.error('[GENESIS] persisted genesis hash is not hex; refusing to start')
            bootstrap.sys.exit(1)
        bootstrap.logger.warning(f'[GENESIS] {bootstrap.os.path.abspath(config.GENESIS_FILE)} is missing but the database holds genesis {db_hash[:16]}...; using the database identity. Peers cannot learn genesis from this node until genesis.json is restored.')

    async def _ensure_genesis_alloc(self):
        if await self.network_state_repo.get('genesis_alloc_applied'):
            return
        genesis_data = genesis.load_genesis_file()
        if not genesis_data:
            return
        _gok, _gwhy = genesis.genesis_export_verified(genesis_data)
        if not _gok:
            bootstrap.logger.error(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} refusing unverified genesis file: {_gwhy}')
            raise RuntimeError(f'genesis file failed verification: {_gwhy}')
        async with await self.db.transaction():
            alloc = genesis_data.get('alloc')
            if isinstance(alloc, dict) and alloc:
                for _addr, _amt in alloc.items():
                    _amt = int(_amt)
                    cur = await self.balance_repo.get(_addr)
                    new_bal = cur + _amt
                    await self.balance_repo.set(_addr, new_bal)
                    await self.state_trie.put(f'balance:{_addr}', new_bal)
                    self.balances[_addr] = new_bal
                gm = int(genesis_data.get('total_minted', config.GENESIS_SUPPLY))
                cur_m = await self.network_state_repo.get('total_minted')
                new_m = (int(cur_m) if cur_m else 0) + gm
                await self.network_state_repo.set('total_minted', str(new_m))
                self.total_minted = new_m
                bootstrap.logger.info(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} Applied genesis alloc (+{gm // config.SUBS} MCX, {len(alloc)} address(es))')
            await self.network_state_repo.set('genesis_alloc_applied', '1')

    async def _create_genesis(self):
        genesis_data = genesis.load_genesis_file()
        if not genesis_data:
            if not getattr(self, '_allow_new_genesis', False):
                bootstrap.logger.error(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} No {config.GENESIS_FILE} found. Start the seed node with --allow-new-genesis, or copy genesis.json from a running node.')
                raise RuntimeError('No genesis.json found. Cannot create genesis.')
            bootstrap.logger.info(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} Creating genesis block...')
            _gw = str(self.wallet).lower()
            if len(_gw) != 42 or not _gw.startswith('0x') or any((c not in '0123456789abcdef' for c in _gw[2:])):
                raise RuntimeError(f'refusing genesis creation: wallet {_gw!r} is not a canonical lowercase 0x address')
            if int(config.GENESIS_SUPPLY) <= 0:
                raise RuntimeError('refusing genesis creation: GENESIS_SUPPLY must be positive')
            try:
                _svf_public = svf_keys._svf_public_for_genesis()
            except svf_keys.SVFKeyError as _e:
                if int(config.CHAIN_ID) != 6621 or svf_keys._svf_key_file_path() is not None:
                    bootstrap.logger.error(f'[SVF] {_e}; refusing to create genesis')
                    bootstrap.sys.exit(1)
                _svf_public = svf_keys._svf_auto_generate_test_key()
            _fresh_ruleset = genesis._effective_consensus_ruleset()
            await self.state_trie.put('height:0', 0)
            await self.state_trie.put(f'balance:{_gw}', config.GENESIS_SUPPLY)
            genesis_ts = bootstrap.time.time()
            _snap = {'height:0': 0, f'balance:{_gw}': config.GENESIS_SUPPLY}
            state_root = db._state_root_from_snapshot(_snap)
            _fresh_ruleset = genesis._effective_consensus_ruleset()
            block_dict = {'id': 0, 'ts': genesis_ts, 'phash': '0' * 64, 'miners': [], 'reward': 0, 'tx_count': 0, 'merkle_root': '', 'nonce': 0, 'difficulty': 0, 'version': config.VERSION, 'challenge': '', 'coverage': 0.0, 'total_tx_value': 0, 'total_fees': 0, 'tx_hashes': [], 'finalized': True, 'state_root': state_root, 'producer_pub': '', 'alloc': {_gw: config.GENESIS_SUPPLY}, 'total_minted': config.GENESIS_SUPPLY, 'chain_id': config.CHAIN_ID, 'consensus': _fresh_ruleset, 'validators': list(_fresh_ruleset['validators']), 'svf_public': _svf_public}
            block_hash = crypto.calculate_block_hash(block_dict)
            block_dict['hash'] = block_hash
            block_dict['signature'] = crypto.sign_bytes(self.priv, crypto.block_signing_payload(block_dict))
            genesis_export = {k: v for k, v in block_dict.items() if k not in ('finalized', 'signature')}
            genesis_export['signature'] = block_dict['signature']
            _sok, _swhy = genesis.genesis_export_verified(bootstrap.json.loads(bootstrap.json.dumps(genesis_export)))
            if not _sok:
                bootstrap.logger.error(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} freshly built genesis FAILED self-verification: {_swhy}')
                raise RuntimeError(f'fresh genesis failed self-verification: {_swhy}')
            genesis._write_genesis_file_atomic(genesis_export)
            genesis._node_genesis_data = genesis_export
            async with await self.db.transaction():
                await self.state_trie.put('height:0', 0)
                await self.state_trie.put(f'balance:{_gw}', config.GENESIS_SUPPLY)
                _committed_root = await self.state_trie.commit()
                if _committed_root != state_root:
                    raise RuntimeError(f'genesis trie recomputation diverged: committed={_committed_root!r} expected={state_root!r}')
                await self.balance_repo.set(_gw, config.GENESIS_SUPPLY)
                await self.network_state_repo.set('total_minted', str(config.GENESIS_SUPPLY))
                await self.network_state_repo.set('burned_total', '0')
                await self.network_state_repo.set('genesis_alloc_applied', '1')
                await self.block_repo.create(block_dict)
            try:
                self.state_trie.mark_committed()
            except Exception as e:
                bootstrap.logger.warning(f'[Genesis] state_trie.mark_committed failed: {e}')
            self.balances[_gw] = config.GENESIS_SUPPLY
            self.total_minted = config.GENESIS_SUPPLY
            self.burned_total = 0
            self.genesis_hash = block_hash
            genesis._node_genesis_hash = block_hash
            genesis.FORK_ID = int(block_hash[:8], 16) ^ int(block_hash[8:16], 16)
            self.blocks.append(block_dict)
            self.height = 1
            self.last_hash = block_hash
            self._next_block_time = genesis_ts + config.BLOCK_TIME
            config._update_genesis_pin_in_file(block_hash)
        else:
            _gok, _gwhy = genesis.genesis_export_verified(genesis_data)
            if not _gok:
                bootstrap.logger.error(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} refusing unverified genesis file: {_gwhy}')
                raise RuntimeError(f'genesis file failed verification: {_gwhy}')
            _restored_validators = list(genesis_data['validators'])
            self.genesis_hash = genesis_data.get('hash', '')
            genesis._node_genesis_hash = self.genesis_hash
            genesis.FORK_ID = int(self.genesis_hash[:8], 16) ^ int(self.genesis_hash[8:16], 16)
            total_minted = int(genesis_data.get('total_minted', 0))
            self.total_minted = total_minted
            self.burned_total = 0
            alloc = genesis_data.get('alloc')
            for _addr, _amt in alloc.items():
                await self.state_trie.put(f'balance:{_addr}', int(_amt))
            await self.state_trie.put('height:0', 0)
            state_root = genesis_data.get('state_root')
            if not state_root:
                state_root = await self.state_trie.commit()
            genesis_block = {'id': 0, 'ts': genesis_data.get('ts', bootstrap.time.time()), 'phash': '0' * 64, 'miners': [], 'reward': 0, 'tx_count': 0, 'merkle_root': '', 'nonce': 0, 'difficulty': 0, 'version': genesis_data.get('version', config.VERSION), 'challenge': '', 'coverage': 0.0, 'total_tx_value': 0, 'total_fees': 0, 'tx_hashes': [], 'finalized': True, 'state_root': state_root, 'hash': self.genesis_hash, 'signature': '', 'producer_pub': '', 'validators': _restored_validators, 'svf_public': svf_keys._svf_public_for_genesis()}
            async with await self.db.transaction():
                for _addr, _amt in alloc.items():
                    await self.balance_repo.set(_addr, int(_amt))
                await self.network_state_repo.set('total_minted', str(total_minted))
                await self.network_state_repo.set('burned_total', '0')
                await self.network_state_repo.set('genesis_alloc_applied', '1')
                await self.block_repo.create(genesis_block)
            for _addr, _amt in alloc.items():
                self.balances[_addr] = int(_amt)
            self.blocks.append(genesis_block)
            self.height = 1
            self.last_hash = self.genesis_hash
            self._next_block_time = genesis_block['ts'] + config.BLOCK_TIME
            bootstrap.logger.info(f'{bootstrap.GREEN}[GENESIS]{bootstrap.RESET} Restored genesis block from {config.GENESIS_FILE} (hash={self.genesis_hash[:16]}...)')
            assert self.height == 1 and self.last_hash, 'genesis restore failed'

    async def _register_self_node(self):
        self.miner_id = 'PC_' + bootstrap.hashlib.sha256(f'{self.wallet}_mcx_miner'.encode()).hexdigest()[:32].upper()
        node_id = self.wallet
        existing = await self.node_repo.get(node_id)
        if existing:
            existing['active'] = True
            existing['mining_enabled'] = self._producing_enabled
            existing['staking_enabled'] = self._producing_enabled
            existing['last_seen'] = bootstrap.time.time()
            await self.node_repo.update(existing)
            await self.node_repo.update_height(node_id, self.height)
            bootstrap.logger.info(f'{bootstrap.GREEN}[SELF NODE]{bootstrap.RESET} Node {node_id[:16]}... already registered.')
            return
        node = {'node_id': node_id, 'wallet': self.wallet, 'ip': config.EXTERNAL_IP or '0.0.0.0', 'port': config.WS_PORT, 'last_seen': bootstrap.time.time(), 'height': self.height, 'active': True, 'rewards_earned': 0, 'version': config.VERSION, 'mining_enabled': self._producing_enabled, 'staking_enabled': self._producing_enabled, 'last_sync': bootstrap.time.time(), 'is_multisig_signer': False, 'public_key': self.get_public_key_hex()}
        await self.node_repo.create(node)
        bootstrap.logger.info(f'{bootstrap.GREEN}[SELF NODE]{bootstrap.RESET} Registered node ID: {node_id[:16]}...')

    async def shutdown(self):
        if self._shutdown_flag:
            return
        self._shutdown_flag = True
        bootstrap.logger.info('[Node] Shutting down...')
        self._producing_enabled = False
        _early: list = [getattr(self, n, None) for n in ('_production_task', '_node_cleanup_task', '_automation_task')]
        if self.p2p:
            _early += list(getattr(self.p2p, '_bg_tasks', []))
            _early += list(self.p2p._conn_tasks)
            _prune = getattr(self.p2p, '_prune_task', None)
            if _prune is not None:
                _early.append(_prune)
        for _t in _early:
            if _t is not None and (not _t.done()):
                _t.cancel()
        for _t in _early:
            if _t is None:
                continue
            try:
                await _t
            except bootstrap.asyncio.CancelledError:
                pass
            except Exception:
                pass
        try:
            drained = await self.mempool.drain(timeout=30.0)
            if drained:
                bootstrap.logger.info('[Node] Mempool drained cleanly')
        except Exception as e:
            bootstrap.logger.warning(f'[Node] Mempool drain error: {e}')
        if hasattr(self, '_ws_task') and (not self._ws_task.done()):
            self._ws_task.cancel()
            try:
                await self._ws_task
            except bootstrap.asyncio.CancelledError:
                pass
        for ws in self.miner_websockets.values():
            try:
                await ws.close()
            except Exception:
                pass
        self.miner_websockets.clear()
        if self.p2p:
            await self.p2p.shutdown()
        if self.mempool._cleanup_task and (not self.mempool._cleanup_task.done()):
            self.mempool._cleanup_task.cancel()
            try:
                await self.mempool._cleanup_task
            except bootstrap.asyncio.CancelledError:
                pass
        for _rl in (self.rate_limiter, self.subnet_rate_limiter, self.register_rate_limiter, self.rpc_rate_limiter):
            _ct = getattr(_rl, '_cleanup_task', None)
            if _ct is not None and (not _ct.done()):
                _ct.cancel()
                try:
                    await _ct
                except bootstrap.asyncio.CancelledError:
                    pass
                except Exception:
                    pass
        if self.vm_manager:
            self.vm_manager.close()
        await self.db.close()
        bootstrap.logger.info('[Node] Shutdown complete.')

    async def _listener_probe(self, host, port, path):
        try:
            reader, writer = await bootstrap.asyncio.wait_for(bootstrap.asyncio.open_connection(host, port), timeout=5)
        except Exception:
            return False
        try:
            writer.write(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'.encode())
            await writer.drain()
            data = await bootstrap.asyncio.wait_for(reader.read(256), timeout=5)
            return data.startswith(b'HTTP/')
        except Exception:
            return False
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _listener_rebind(self, rec):
        from aiohttp import web
        old = rec['site']
        try:
            await bootstrap.asyncio.wait_for(old.stop(), timeout=5)
        except Exception as _e:
            bootstrap.logger.warning(f'[LISTENER] {rec['name']} old site stop failed (ignored): {_e}')
        try:
            site = web.TCPSite(rec['runner'], rec['host'], rec['port'])
            await site.start()
        except OSError as _e:
            if getattr(_e, 'errno', None) in (48, 98, 10048):
                bootstrap.logger.warning(f'[LISTENER] {rec['name']} port still held - old listener alive, keeping it')
                return
            raise
        rec['site'] = site
        bootstrap.logger.info(f'[LISTENER] {rec['name']} re-bound on {rec['host']}:{rec['port']}')

    async def _listener_watchdog(self, sites):
        while True:
            await bootstrap.asyncio.sleep(15)
            for rec in sites:
                try:
                    host = rec['host']
                    if host in ('0.0.0.0', ''):
                        probe_host = '127.0.0.1'
                    elif host == '::':
                        probe_host = '::1'
                    else:
                        probe_host = host
                    alive = await self._listener_probe(probe_host, rec['port'], rec['path'])
                except Exception as _e:
                    bootstrap.logger.warning(f'[LISTENER] {rec['name']} probe error (ignored): {_e}')
                    continue
                if alive:
                    rec['fails'] = 0
                    continue
                rec['fails'] += 1
                bootstrap.logger.warning(f'[LISTENER] {rec['name']} probe failed ({rec['fails']}/3)')
                if rec['fails'] < 3:
                    continue
                rec['fails'] = 0
                try:
                    await self._listener_rebind(rec)
                except Exception as _e:
                    bootstrap.logger.error(f'[LISTENER] {rec['name']} rebind failed: {_e}')

    async def _run_websocket(self):
        from aiohttp import web, WSMsgType
        from aiohttp.web import Application, Request, Response, WebSocketResponse

        @web.middleware
        async def cors_middleware(request, handler):
            if request.method == 'OPTIONS':
                resp = Response(status=204)
            else:
                resp = await handler(request)
            origin = request.headers.get('Origin')
            if util._cors_origin_allowed(origin):
                resp.headers['Access-Control-Allow-Origin'] = origin
                resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
                resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return resp
        app = Application(middlewares=[cors_middleware])

        async def websocket_handler(request):
            ws = WebSocketResponse(heartbeat=60)
            await ws.prepare(request)
            client_ip = request.remote
            if len(self.ws_sessions) >= config.WS_MAX_CONNECTIONS:
                bootstrap.logger.warning(f'[WS] Connection from {client_ip} refused: max WS connections ({config.WS_MAX_CONNECTIONS}) reached')
                await ws.close(code=1013, message=b'too many connections')
                return ws
            if sum((1 for _s in self.ws_sessions.values() if _s.get('client_ip') == client_ip)) >= config.WS_MAX_CONNECTIONS_PER_IP:
                bootstrap.logger.warning(f'[WS] Connection from {client_ip} refused: max WS connections per IP ({config.WS_MAX_CONNECTIONS_PER_IP}) reached')
                await ws.close(code=1013, message=b'too many connections from this IP')
                return ws
            self.ws_sessions[ws] = {'tasks': set(), 'client_ip': client_ip}
            bootstrap.set_trace_id(f'ws-{bootstrap.new_trace_id()}')
            bootstrap.logger.info(f'[WS] New connection from {client_ip}')
            miner_id = None
            try:
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        try:
                            data = bootstrap.json.loads(msg.data)
                            if not isinstance(data, dict):
                                await ws.send_json({'type': 'error', 'message': 'Invalid message'})
                                continue
                            msg_type = data.get('type')
                            session = self.ws_sessions.get(ws)
                            if msg_type == 'enc' and session and ('pqe_key' in session):
                                try:
                                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                                    ct = bytes.fromhex(data.get('ct', ''))
                                    nonce = bytes.fromhex(data.get('nonce', ''))
                                    plain = _AESGCM(session['pqe_key']).decrypt(nonce, ct, None)
                                    data = bootstrap.json.loads(plain.decode('utf-8'))
                                    msg_type = data.get('type')
                                except Exception as e:
                                    bootstrap.logger.warning(f'[WS] PQE decrypt error: {e}')
                                    continue
                            if msg_type == 'ping':
                                await ws.send_json({'type': 'pong', 'timestamp': bootstrap.time.time()})
                                continue
                            _rate_exempt = msg_type in ('maze_move', 'wall_hit_solve', 'block_signed', 'memory_challenge_response')
                            if not _rate_exempt:
                                allowed = await self.rate_limiter.is_allowed(client_ip)
                                if not allowed:
                                    await ws.send_json({'type': 'error', 'message': 'Rate limit exceeded'})
                                    continue
                            await self._handle_ws_message(ws, data, client_ip)
                            if data.get('miner_id') and (not miner_id):
                                miner_id = data['miner_id']
                        except bootstrap.json.JSONDecodeError:
                            await ws.send_json({'type': 'error', 'message': 'Invalid JSON'})
                        except Exception as e:
                            if not self._shutdown_flag:
                                bootstrap.logger.error(f'[WS] Handler error: {e}', exc_info=True)
                            try:
                                await ws.send_json({'type': 'error', 'message': str(e)})
                            except Exception:
                                pass
                    elif msg.type == WSMsgType.ERROR:
                        bootstrap.logger.debug(f'[WS] Connection error: {ws.exception()}')
            except Exception as e:
                if not self._shutdown_flag:
                    bootstrap.logger.error(f'[WS] Connection error: {e}')
            finally:
                _sess = self.ws_sessions.pop(ws, None)
                if _sess:
                    for _t in _sess.get('tasks', set()):
                        if not _t.done():
                            _t.cancel()
                if ws.closed and (not self._shutdown_flag):
                    bootstrap.logger.info(f'[WS] Connection closed: code={ws.close_code}')
                if miner_id and self.miner_websockets.get(miner_id) is ws:
                    del self.miner_websockets[miner_id]
            return ws
        app_ws = _ws_app_routes(Application(middlewares=[cors_middleware]), websocket_handler)

        async def rpc_handler(request):
            req_id = None
            try:
                if request.method == 'GET':
                    return web.json_response({'jsonrpc': '2.0', 'id': 1, 'result': hex(self.height - 1 if self.height > 0 else 0)})
                try:
                    body = await request.json()
                except Exception:
                    return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32700, 'message': 'Parse error'}, 'id': None})
                if not body:
                    return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32700, 'message': 'Parse error: empty body'}, 'id': None})
                method = body.get('method')
                params = body.get('params', [])
                req_id = body.get('id', 1)
                _origin = (request.headers.get('Origin') or '').strip()
                if _origin:
                    _o_host = bootstrap.urlparse(_origin).hostname
                    if _o_host not in ('localhost', '127.0.0.1', '::1'):
                        return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32001, 'message': 'RPC unauthorized: cross-origin request rejected'}})
                if not wallet._rpc_remote_authorized(request, self.config):
                    return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32001, 'message': 'RPC unauthorized: non-loopback clients must present the configured bearer token (MCX_RPC_TOKEN / node.rpc_token)'}})
                HEAVY_METHODS = {'eth_call', 'eth_estimateGas', 'eth_getLogs', 'debug_traceTransaction'}
                if method in HEAVY_METHODS:
                    client_ip = request.remote or '127.0.0.1'
                    if not await self.rpc_rate_limiter.is_allowed(client_ip):
                        return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32005, 'message': 'Rate limit exceeded for heavy RPC calls'}})
                if method == 'eth_chainId':
                    result = hex(config.CHAIN_ID)
                elif method == 'net_version':
                    result = str(config.CHAIN_ID)
                elif method == 'web3_clientVersion':
                    result = 'Munex/v0.6.3/python'
                elif method == 'net_listening':
                    result = True
                elif method == 'net_peerCount':
                    result = hex(len(self.p2p.peers)) if self.p2p else '0x0'
                elif method == 'eth_syncing':
                    result = False
                elif method == 'eth_blockNumber':
                    result = hex(self.height - 1 if self.height > 0 else 0)
                elif method == 'mcx_getBurnedTotal':
                    result = {'burned_total_subunits': hex(self.burned_total), 'burned_total_mcx': self.burned_total // config.SUBS, 'total_minted_mcx': self.total_minted // config.SUBS, 'circulating_supply_mcx': (self.total_minted - self.burned_total) // config.SUBS}
                elif method == 'eth_getBalance':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    bal = await self.get_balance(addr.lower())
                    result = hex(bal)
                elif method == 'eth_getTransactionCount':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    addr = addr.lower()
                    confirmed = await self._get_confirmed_nonce(addr)
                    pending = self.mempool.get_nonce(addr)
                    nonce = max(confirmed, pending)
                    result = hex(nonce)
                elif method == 'eth_gasPrice':
                    result = hex(config.GAS_PRICE)
                elif method == 'eth_maxPriorityFeePerGas':
                    result = hex(config.GAS_PRICE // 2)
                elif method == 'eth_feeHistory':
                    return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32000, 'message': 'eth_feeHistory is not supported by this node'}})
                elif method == 'eth_getCode':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    contract = await self.contract_v2_repo.get(addr)
                    result = '0x' + contract['bytecode'] if contract else '0x'
                elif method == 'eth_getStorageAt':
                    addr = params[0] if params else ''
                    _raw = params[1] if len(params) > 1 else '0'
                    try:
                        key = int(_raw, 16) if str(_raw).startswith('0x') else int(_raw)
                    except (TypeError, ValueError):
                        return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32602, 'message': 'Invalid storage key'}})
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    val = await self.contract_storage_v2_repo.get(addr, str(key))
                    if val:
                        result = '0x' + int(val, 16).to_bytes(32, 'big').hex()
                    else:
                        result = '0x' + '0' * 64
                elif method == 'eth_call':
                    tx_obj = params[0] if params else {}
                    from_addr = tx_obj.get('from', '0x0000000000000000000000000000000000000000')
                    to_addr = tx_obj.get('to', '')
                    data = tx_obj.get('data') or tx_obj.get('input') or '0x'
                    try:
                        value = int(tx_obj.get('value', '0x0'), 16) if isinstance(tx_obj.get('value'), str) else int(tx_obj.get('value', 0))
                        gas_limit = int(tx_obj.get('gas', '0x' + hex(config.GAS_LIMIT_DEFAULT)[2:]), 16) if isinstance(tx_obj.get('gas'), str) else int(tx_obj.get('gas', config.GAS_LIMIT_DEFAULT))
                    except (TypeError, ValueError):
                        return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32602, 'message': 'Invalid value/gas'}})
                    if not to_addr:
                        result = '0x'
                    else:
                        try:
                            input_data = bytes.fromhex(data[2:]) if data.startswith('0x') else b''
                        except ValueError:
                            return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32602, 'message': 'Invalid hex input'}})
                        success, ret, gas_used, logs = await self.vm_manager.execute(to_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                        result = '0x' + ret.hex() if success else '0x'
                elif method == 'eth_estimateGas':
                    tx_obj = params[0] if params else {}
                    from_addr = tx_obj.get('from', '0x0000000000000000000000000000000000000000')
                    to_addr = tx_obj.get('to', '')
                    data = tx_obj.get('data') or tx_obj.get('input') or '0x'
                    value = int(tx_obj.get('value', '0x0'), 16) if isinstance(tx_obj.get('value'), str) else tx_obj.get('value', 0)
                    gas_limit = config.MAX_BLOCK_GAS
                    if not to_addr:
                        bytecode = data[2:] if data.startswith('0x') else data
                        input_data = bytes.fromhex(bytecode) if bytecode else b''
                        nonce = await self._get_confirmed_nonce(from_addr)
                        contract_addr = util.compute_contract_address(from_addr, nonce)
                        success, ret, gas_used, logs = await self.vm_manager.execute(contract_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                        if not success:
                            return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32000, 'message': 'execution reverted'}})
                        result = hex(max(53000, gas_used + 21000))
                    else:
                        try:
                            input_data = bytes.fromhex(data[2:]) if data.startswith('0x') and len(data) > 2 else b''
                        except ValueError:
                            return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32602, 'message': 'Invalid hex input'}})
                        if not input_data:
                            result = hex(21000)
                        else:
                            success, ret, gas_used, logs = await self.vm_manager.execute(to_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                            if not success:
                                return web.json_response({'jsonrpc': '2.0', 'id': req_id, 'error': {'code': -32000, 'message': 'execution reverted'}})
                            result = hex(max(21000, gas_used + 10000))
                elif method == 'eth_sendRawTransaction':
                    raw_tx = params[0] if params else ''
                    if not raw_tx or not raw_tx.startswith('0x'):
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid raw tx'}, 'id': req_id})
                    try:
                        decoded = util.decode_raw_eth_transaction(raw_tx)
                    except Exception as e:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': f'Decode error: {str(e)}'}, 'id': req_id})
                    if not util._raw_chain_id_ok(decoded):
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid chain ID'}, 'id': req_id})
                    from_addr = (decoded.get('from') or '').lower()
                    if not from_addr:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid sender recovery from raw tx'}, 'id': req_id})
                    to = (decoded.get('to') or '').lower()
                    value = int(decoded.get('value', 0))
                    gas = int(decoded.get('gas', 21000))
                    gasPrice = int(decoded.get('gasPrice', 0))
                    if gas < 21000 or gasPrice < 0 or value < 0:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid gas, gasPrice, or value'}, 'id': req_id})
                    maxFee = gas * gasPrice
                    total = value + maxFee
                    bal = await self.get_balance(from_addr)
                    if bal < total:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': 'insufficient funds'}, 'id': req_id})
                    confirmed_nonce = await self._get_confirmed_nonce(from_addr)
                    if decoded['nonce'] < confirmed_nonce:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': 'nonce too low'}, 'id': req_id})
                    pending_nonce = self.mempool.get_nonce(from_addr)
                    max_pending = max(confirmed_nonce, pending_nonce) if pending_nonce else confirmed_nonce
                    if decoded['nonce'] > max_pending + 10:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': 'nonce too far ahead (max gap: 10)'}, 'id': req_id})
                    tx_hash = decoded['hash']
                    tx_data = {'tx_hash': tx_hash, 'from_wallet': from_addr, 'to_wallet': to if to else '', 'value': value, 'fee': maxFee, 'nonce': decoded['nonce'], 'timestamp': bootstrap.time.time(), 'signature': raw_tx, 'data': decoded.get('data', ''), 'gas': gas, 'gasPrice': gasPrice, 'tx_type': 'contract_deploy' if not to else 'contract_call' if decoded.get('data') and len(decoded['data']) > 0 else 'send'}
                    if not self._verify_tx_signature(tx_data):
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32602, 'message': 'Invalid transaction signature'}, 'id': req_id})
                    if await self.mempool.add(tx_data):
                        await self.p2p.broadcast_transaction(tx_data)
                        result = tx_hash
                    else:
                        return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32000, 'message': 'mempool full'}, 'id': req_id})
                elif method == 'eth_getTransactionByHash':
                    tx_hash = params[0] if params else ''
                    tx = await self.tx_repo.get_by_hash(tx_hash)
                    if tx:
                        _blk = await self.block_repo.get_by_id(tx['block_id']) if tx['block_id'] >= 0 else None
                        _amt = tx.get('amount', tx.get('value', 0))
                        _v, _r, _s = util._eth_sig_fields(tx)
                        _txl = []
                        try:
                            _txh = _blk.get('tx_hashes', '') if _blk else ''
                            _txl = bootstrap.json.loads(_txh) if isinstance(_txh, str) else _txh or []
                        except Exception:
                            _txl = []
                        _tidx = _txl.index(tx['tx_hash']) if tx['tx_hash'] in _txl else 0
                        result = {'hash': tx['tx_hash'], 'nonce': hex(tx['nonce']), 'blockHash': '0x' + _blk['hash'] if _blk else None, 'blockNumber': hex(tx['block_id']) if _blk else None, 'transactionIndex': hex(_tidx) if _blk else None, 'from': tx['from_wallet'], 'to': tx['to_wallet'], 'value': hex(_amt), 'gas': hex(tx.get('gas', config.GAS_LIMIT_DEFAULT)), 'gasPrice': hex(tx.get('gasPrice', config.GAS_PRICE)), 'input': util.tx_data_to_hex(tx.get('data', '0x')), 'v': _v, 'r': _r, 's': _s}
                    else:
                        result = None
                elif method == 'eth_getTransactionReceipt':
                    tx_hash = params[0] if params else ''
                    receipt = await self.receipt_repo.get(tx_hash)
                    result = None
                    if receipt:
                        _blk = await self.block_repo.get_by_id(receipt['block_id'])
                        if _blk:
                            tx = await self.tx_repo.get_by_hash(tx_hash)
                            _txl2 = []
                            try:
                                _txh2 = _blk.get('tx_hashes', '')
                                _txl2 = bootstrap.json.loads(_txh2) if isinstance(_txh2, str) else _txh2 or []
                            except Exception:
                                _txl2 = []
                            _tidx2 = _txl2.index(tx_hash) if tx_hash in _txl2 else 0
                            _ord = []
                            try:
                                _rq = 'SELECT tx_hash, gas_used FROM transaction_receipts WHERE block_id = ?' if self.db.db_type == 'sqlite' else 'SELECT tx_hash, gas_used FROM transaction_receipts WHERE block_id = $1'
                                _rrows = await self.db.fetch(_rq, receipt['block_id'])
                                _bymap = {str(_r.get('tx_hash')): int(_r.get('gas_used', 0) or 0) for _r in _rrows or []}
                                _ord = [(_h, _bymap.get(str(_h), 0)) for _h in _txl2]
                            except Exception:
                                _ord = [(tx_hash, receipt['gas_used'])]
                            _logs2 = receipt.get('logs', [])
                            if isinstance(_logs2, str):
                                try:
                                    _logs2 = bootstrap.json.loads(_logs2)
                                except Exception:
                                    _logs2 = []
                            result = {'transactionHash': tx_hash, 'transactionIndex': hex(_tidx2), 'blockHash': '0x' + _blk['hash'], 'blockNumber': hex(receipt['block_id']), 'from': tx['from_wallet'] if tx else '0x0', 'to': tx['to_wallet'] if tx else '0x0', 'cumulativeGasUsed': hex(util._cumulative_gas_used(_ord, tx_hash)), 'gasUsed': hex(receipt['gas_used']), 'contractAddress': receipt.get('contract_address', ''), 'logs': _logs2, 'logsBloom': util._logs_bloom(_logs2 if isinstance(_logs2, list) else []), 'status': hex(receipt['status'])}
                elif method == 'eth_getLogs':
                    filter_obj = params[0] if params else {}
                    if not isinstance(filter_obj, dict):
                        filter_obj = {}
                    _tip = self.height - 1 if self.height > 0 else 0

                    def _blk_tag(v, default):
                        try:
                            if isinstance(v, str):
                                if v in ('latest', 'pending'):
                                    return _tip
                                if v == 'earliest':
                                    return 0
                                if v.lower().startswith('0x'):
                                    return int(v, 16)
                                return int(v)
                            if isinstance(v, int):
                                return v
                        except (TypeError, ValueError):
                            pass
                        return default
                    from_block = _blk_tag(filter_obj.get('fromBlock'), 0)
                    to_block = _blk_tag(filter_obj.get('toBlock'), _tip)
                    _bh = filter_obj.get('blockHash')
                    _addr_f = filter_obj.get('address')
                    _addrs = None
                    if isinstance(_addr_f, str):
                        _addrs = [_addr_f]
                    elif isinstance(_addr_f, list):
                        _addrs = [a for a in _addr_f if isinstance(a, str)]
                    _topics_f = filter_obj.get('topics')
                    if not isinstance(_topics_f, list):
                        _topics_f = None
                    if self.db.db_type == 'sqlite':
                        q = 'SELECT tx_hash,block_id,status,gas_used,logs,contract_address FROM transaction_receipts WHERE block_id >= ? AND block_id <= ?'
                        rows = await self.db.fetch(q, from_block, to_block)
                    else:
                        q = 'SELECT tx_hash,block_id,status,gas_used,logs,contract_address FROM transaction_receipts WHERE block_id >= $1 AND block_id <= $2'
                        rows = await self.db.fetch(q, from_block, to_block)
                    if _bh:
                        _bh_norm = str(_bh).lower()
                    else:
                        _bh_norm = None
                    _hash_cache = {}
                    result = []
                    for r in rows or []:
                        logs = r.get('logs', [])
                        if isinstance(logs, str):
                            try:
                                logs = bootstrap.json.loads(logs)
                            except Exception:
                                logs = []
                        if not isinstance(logs, list):
                            continue
                        _bid = r.get('block_id')
                        if _bid not in _hash_cache:
                            try:
                                _brow = await self.block_repo.get_by_id(_bid)
                            except Exception:
                                _brow = None
                            _bhx = _brow.get('hash', '') if _brow else ''
                            _hash_cache[_bid] = '0x' + _bhx if _bhx and (not str(_bhx).startswith('0x')) else str(_bhx) if _bhx else ''
                            try:
                                _txl = _brow.get('tx_hashes', '') if _brow else ''
                                _txl = bootstrap.json.loads(_txl) if isinstance(_txl, str) else _txl or []
                            except Exception:
                                _txl = []
                            _hash_cache[_bid, 'txs'] = list(_txl) if isinstance(_txl, list) else []
                            _hash_cache[_bid, 'n'] = 0
                        if _bh_norm and _hash_cache[_bid].lower() != _bh_norm:
                            continue
                        _txl = _hash_cache.get((_bid, 'txs'), [])
                        try:
                            _tidx = _txl.index(r.get('tx_hash')) if r.get('tx_hash') in _txl else 0
                        except Exception:
                            _tidx = 0
                        for _li, log in enumerate(logs):
                            if not isinstance(log, dict):
                                continue
                            if not util._log_matches_filter(log.get('address'), log.get('topics'), _addrs, _topics_f):
                                continue
                            _n = _hash_cache.get((_bid, 'n'), 0)
                            _hash_cache[_bid, 'n'] = _n + 1
                            result.append(util._enrich_eth_log(log, _hash_cache[_bid], hex(_bid), r.get('tx_hash'), hex(_tidx), _n))
                elif method == 'eth_getBlockByNumber':
                    tag = params[0] if params else 'latest'
                    if tag in ('latest', 'pending'):
                        block_id = self.height - 1 if self.height > 0 else 0
                    elif tag == 'earliest':
                        block_id = 0
                    elif isinstance(tag, str) and tag.startswith('0x'):
                        block_id = int(tag, 16)
                    elif isinstance(tag, int):
                        block_id = tag
                    else:
                        block_id = self.height - 1 if self.height > 0 else 0
                    found_block = next((b for b in self.blocks if b.get('id') == block_id), None)
                    if not found_block and self.block_repo:
                        found_block = await self.block_repo.get_by_id(block_id)
                    if found_block:
                        include_full_tx = len(params) > 1 and params[1] is True
                        tx_hashes = found_block.get('tx_hashes', [])
                        if include_full_tx and found_block.get('transactions'):
                            tx_objs = []
                            for _ti, t in enumerate(found_block['transactions']):
                                _vv, _rr, _ss = util._eth_sig_fields(t)
                                tx_objs.append({'hash': t.get('tx_hash', ''), 'nonce': hex(t.get('nonce', 0)), 'blockHash': '0x' + found_block['hash'], 'blockNumber': hex(found_block['id']), 'transactionIndex': hex(_ti), 'from': t.get('from_wallet', ''), 'to': t.get('to_wallet', ''), 'value': hex(t.get('value', 0)), 'gas': hex(t.get('gas', config.GAS_LIMIT_DEFAULT)), 'gasPrice': hex(t.get('gasPrice', config.GAS_PRICE)), 'input': util.tx_data_to_hex(t.get('data', '0x')), 'v': _vv, 'r': _rr, 's': _ss})
                            tx_result = tx_objs
                        else:
                            tx_result = tx_hashes
                        _bgas = await db._block_gas_used(self.db, found_block['id'])
                        result = {'number': hex(found_block['id']), 'hash': '0x' + found_block['hash'] if not found_block['hash'].startswith('0x') else found_block['hash'], 'parentHash': '0x' + found_block['phash'] if not found_block['phash'].startswith('0x') else found_block['phash'], 'timestamp': hex(int(found_block['ts'])), 'transactions': tx_result, 'miner': found_block.get('miners', [''])[0] if found_block.get('miners') else '', 'gasUsed': hex(_bgas), 'gasLimit': hex(config.GAS_LIMIT_DEFAULT), 'stateRoot': found_block.get('state_root', '0x' + '00' * 32)}
                    else:
                        result = None
                elif method == 'eth_getBlockByHash':
                    block_hash = params[0] if params else ''
                    clean_hash = block_hash[2:] if block_hash.startswith('0x') else block_hash
                    found_block = next((b for b in self.blocks if b.get('hash') in (block_hash, clean_hash)), None)
                    if not found_block and self.block_repo:
                        q = 'SELECT * FROM blocks WHERE hash = ? OR hash = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM blocks WHERE hash = $1 OR hash = $2'
                        row = await self.db.fetchrow(q, block_hash, clean_hash)
                        if row:
                            found_block = self.block_repo._unpack_block(row)
                    if found_block:
                        _bgas2 = await db._block_gas_used(self.db, found_block['id'])
                        result = {'number': hex(found_block['id']), 'hash': '0x' + found_block['hash'] if not found_block['hash'].startswith('0x') else found_block['hash'], 'parentHash': '0x' + found_block['phash'] if not found_block['phash'].startswith('0x') else found_block['phash'], 'timestamp': hex(int(found_block['ts'])), 'transactions': found_block.get('tx_hashes', []), 'miner': found_block.get('miners', [''])[0] if found_block.get('miners') else '', 'gasUsed': hex(_bgas2), 'gasLimit': hex(config.GAS_LIMIT_DEFAULT)}
                    else:
                        result = None
                elif method == 'eth_getBlockTransactionCountByNumber':
                    block_id = int(params[0], 16) if params and params[0].startswith('0x') else self.height - 1
                    found_block = next((b for b in self.blocks if b.get('id') == block_id), None)
                    if not found_block and self.block_repo:
                        found_block = await self.block_repo.get_by_id(block_id)
                    if found_block:
                        result = hex(len(found_block.get('tx_hashes', [])))
                    else:
                        result = '0x0'
                else:
                    return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32601, 'message': f'Method {method} not found'}, 'id': req_id})
                response = {'jsonrpc': '2.0', 'result': result, 'id': req_id}
                return web.json_response(response)
            except Exception as e:
                bootstrap.logger.error(f'[RPC] Error: {e}', exc_info=True)
                return web.json_response({'jsonrpc': '2.0', 'error': {'code': -32603, 'message': str(e)}, 'id': req_id})
        app.router.add_post('/rpc', rpc_handler)
        app.router.add_get('/rpc', rpc_handler)

        async def rpc_options(request):
            headers = {'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type'}
            origin = request.headers.get('Origin')
            if util._cors_origin_allowed(origin):
                headers['Access-Control-Allow-Origin'] = origin
            return web.Response(status=204, headers=headers)
        app.router.add_options('/rpc', rpc_options)

        async def stats_handler(request):
            stats = {'height': self.height, 'peers': self.p2p.get_peer_count() if self.p2p else 0, 'total_miners': len(self.miners), 'active_miners': len(self.miner_websockets), 'uptime': int(bootstrap.time.time() - self.health_checker.start_time), 'total_minted': self.total_minted // config.SUBS, 'burned_total': self.burned_total // config.SUBS, 'burned_total_subunits': self.burned_total, 'circulating_supply': (self.total_minted - self.burned_total) // config.SUBS, 'version': config.VERSION, 'healthy': self.health_checker.get_status().get('healthy', False)}
            return web.json_response(stats)
        app.router.add_get('/stats', stats_handler)

        async def health_handler(request):
            status = self.health_checker.get_status()
            healthy = bool(status.get('healthy', False))
            body = {'ok': healthy, 'version': config.VERSION, 'height': self.height, 'last_hash': self.last_hash, 'peers': self.p2p.get_peer_count() if self.p2p else 0, 'miners_active': len(self.miner_websockets), 'mempool': self.mempool.size(), 'finality_lag_blocks': self._finality_lag_blocks(), 'last_block_age': status.get('last_block_age'), 'errors': status.get('errors', 0), 'uptime_seconds': int(bootstrap.time.time() - self._start_time), 'producing': bool(self._producing_enabled)}
            return web.json_response(body, status=200 if healthy else 503)
        app.router.add_get('/health', health_handler)

        async def peers_handler(request):
            peers = []
            if self.p2p:
                for nid, (url, last_seen) in getattr(self.p2p, 'tunnel_peers', {}).items():
                    peers.append({'node_id': nid, 'url': url, 'last_seen': last_seen})
                for nid, info in getattr(self.p2p, 'peers', {}).items():
                    if hasattr(info, 'addr') and info.addr not in [p.get('url', '') for p in peers]:
                        peers.append({'node_id': nid, 'url': info.addr, 'last_seen': getattr(info, 'last_seen', 0)})
            _api_port = self.config.get('node', {}).get('api_port', config.API_PORT)
            peers.append({'node_id': 'self', 'url': f'http://127.0.0.1:{_api_port}/rpc', 'last_seen': bootstrap.time.time(), 'height': self.height})
            return web.json_response({'peers': peers, 'total': len(peers)})
        app.router.add_get('/peers', peers_handler)

        async def metrics_handler(request):
            metrics = []
            metrics.append(f'# HELP mcx_block_height Current block height')
            metrics.append(f'# TYPE mcx_block_height gauge')
            metrics.append(f'mcx_block_height {self.height}')
            metrics.append(f'# HELP mcx_mempool_size Mempool size')
            metrics.append(f'# TYPE mcx_mempool_size gauge')
            metrics.append(f'mcx_mempool_size {self.mempool.size()}')
            metrics.append(f'# HELP mcx_active_miners Number of active miners')
            metrics.append(f'# TYPE mcx_active_miners gauge')
            try:
                active = await self.miner_repo.get_active()
                metrics.append(f'mcx_active_miners {len(active)}')
            except Exception:
                metrics.append(f'mcx_active_miners 0')
            metrics.append(f'# HELP mcx_pending_pow Pending PoW challenges')
            metrics.append(f'# TYPE mcx_pending_pow gauge')
            metrics.append(f'mcx_pending_pow {len(self.consensus._pending_pow)}')
            metrics.append(f'# HELP mcx_uptime_seconds Node uptime in seconds')
            metrics.append(f'# TYPE mcx_uptime_seconds counter')
            metrics.append(f'mcx_uptime_seconds {int(bootstrap.time.time() - self._start_time)}')
            metrics.append(f'# HELP mcx_total_burned Total burned MCX')
            metrics.append(f'# TYPE mcx_total_burned gauge')
            metrics.append(f'mcx_total_burned {self.burned_total // config.SUBS}')
            metrics.append(f'# HELP mcx_circulating_supply Total circulating MCX')
            metrics.append(f'# TYPE mcx_circulating_supply gauge')
            metrics.append(f'mcx_circulating_supply {(self.total_minted - self.burned_total) // config.SUBS}')
            metrics.append(f'# HELP mcx_global_shrink_factor Global shrink factor')
            metrics.append(f'# TYPE mcx_global_shrink_factor gauge')
            metrics.append(f'mcx_global_shrink_factor {maze.GLOBAL_SHRINK_FACTOR}')
            metrics.append(f'# HELP mcx_global_avg_size Global average maze size')
            metrics.append(f'# TYPE mcx_global_avg_size gauge')
            metrics.append(f'mcx_global_avg_size {self.consensus._global_avg_size}')
            metrics.append(f'# HELP mcx_finality_lag_blocks Blocks since last finality checkpoint')
            metrics.append(f'# TYPE mcx_finality_lag_blocks gauge')
            metrics.append(f'mcx_finality_lag_blocks {self._finality_lag_blocks()}')
            metrics.append(f'# HELP mcx_sign_timeout_total Total block-signing timeouts since start')
            metrics.append(f'# TYPE mcx_sign_timeout_total counter')
            metrics.append(f'mcx_sign_timeout_total {self._sign_timeout_total}')
            return web.Response(text='\n'.join(metrics), content_type='text/plain')
        app.router.add_get('/metrics', metrics_handler)

        async def api_tokens_list(request):
            tokens = list(self.tokens.values())
            return web.json_response({'success': True, 'tokens': tokens, 'count': len(tokens)})

        async def api_tokens_create(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            owner = data.get('owner')
            name = data.get('name')
            symbol = data.get('symbol')
            try:
                total_supply = util._rint(data, 'total_supply')
                decimals = util._rint(data, 'decimals', 18)
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            burnable = bool(data.get('burnable', True))
            temporal_config = data.get('temporal_config', {})
            if not owner or not name or (not symbol) or (total_supply <= 0):
                return web.json_response({'success': False, 'error': 'Missing required token parameters'}, status=400)
            pub_key = data.get('pub_key')
            signature = data.get('signature')
            ts = data.get('timestamp')
            if not pub_key or not signature:
                return web.json_response({'success': False, 'error': 'Missing signature'}, status=401)
            if ts is None:
                return web.json_response({'success': False, 'error': 'Missing timestamp'}, status=401)
            try:
                fee = util._rint(data, 'fee') if data.get('fee') else gas.quote_token_creation_fee(self.mempool.size())
                nonce = util._rint(data, 'nonce') if data.get('nonce') is not None else max(await self._get_confirmed_nonce(owner), self.mempool.get_nonce(owner))
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            _tc_msg = crypto.canonical_json_bytes(temporal_config or {}).decode('utf-8')
            message = f'{config.CHAIN_ID}:create_token:{owner}:{name}:{symbol}:{total_supply}:{decimals}:{int(bool(burnable))}:{nonce}:{fee}:{int(ts)}:{_tc_msg}'
            try:
                if util.pubkey_to_address(pub_key).lower() != str(owner).lower():
                    return web.json_response({'success': False, 'error': 'pub_key does not match owner'}, status=401)
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid pub_key'}, status=401)
            if not crypto.verify_signature(pub_key, message, signature):
                return web.json_response({'success': False, 'error': 'Invalid signature'}, status=401)
            if abs(bootstrap.time.time() - float(ts)) > 300:
                return web.json_response({'success': False, 'error': 'Stale timestamp'}, status=401)
            tx_data = {'tx_type': 'token_create', 'from_wallet': owner, 'to_wallet': owner, 'value': 0, 'fee': fee, 'nonce': nonce, 'timestamp': int(ts), 'signature': signature, 'pub_key': pub_key, 'data': {'name': name, 'symbol': symbol, 'total_supply': total_supply, 'decimals': decimals, 'burnable': bool(burnable), 'temporal_config': temporal_config}}
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_tokens_get(request):
            addr = request.match_info.get('address')
            token = await self.token_repo.get(addr)
            if not token:
                return web.json_response({'success': False, 'error': 'Token not found'}, status=404)
            temporal_config = await self.get_token_temporal_config(addr)
            burned_total = int(await self.contract_state_repo.get(addr, 'burned_total') or 0)
            return web.json_response({'success': True, 'token': token, 'temporal_config': temporal_config, 'burned_total': burned_total})

        async def api_tokens_balance(request):
            addr = request.match_info.get('address')
            wallet = request.match_info.get('wallet')
            bal = await self.token_balance_repo.get(addr, wallet)
            temporal_config = await self.get_token_temporal_config(addr)
            locked = 0
            vesting = temporal_config.get('vesting_schedules', {}).get(wallet) if temporal_config else None
            now = bootstrap.time.time()
            if vesting:
                v_total = int(vesting.get('total', 0))
                v_start = float(vesting.get('start', 0))
                v_dur = float(vesting.get('duration', 1))
                if now < v_start:
                    locked = v_total
                elif now >= v_start + v_dur:
                    locked = 0
                else:
                    locked = int(v_total * (1.0 - (now - v_start) / v_dur))
            return web.json_response({'success': True, 'token': addr, 'wallet': wallet, 'balance': bal, 'unlocked': max(0, bal - locked), 'locked_vesting': locked})

        async def api_tokens_transfer(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            addr = request.match_info.get('address')
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            try:
                _v, _f, _n = (util._rint(data, 'amount'), util._rint(data, 'fee'), util._rint(data, 'nonce'))
                _ts = util._rfloat_opt(data, 'timestamp')
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            tx_data = {'tx_type': 'token_transfer', 'token_address': addr, 'from_wallet': data.get('from_wallet'), 'to_wallet': data.get('to_wallet'), 'value': _v, 'fee': _f, 'nonce': _n, 'signature': data.get('signature', ''), 'pub_key': data.get('pub_key')}
            if _ts is not None:
                tx_data['timestamp'] = _ts
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_tokens_burn(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            addr = request.match_info.get('address')
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            try:
                _v, _f, _n = (util._rint(data, 'amount'), util._rint(data, 'fee'), util._rint(data, 'nonce'))
                _ts = util._rfloat_opt(data, 'timestamp')
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            tx_data = {'tx_type': 'token_burn', 'token_address': addr, 'from_wallet': data.get('from_wallet'), 'value': _v, 'fee': _f, 'nonce': _n, 'signature': data.get('signature', ''), 'pub_key': data.get('pub_key')}
            if _ts is not None:
                tx_data['timestamp'] = _ts
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_native_burn(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            from_wallet = data.get('from_wallet')
            try:
                amount = util._rint(data, 'amount')
                _f, _n = (util._rint(data, 'fee'), util._rint(data, 'nonce'))
                _ts = util._rfloat_opt(data, 'timestamp')
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            if not from_wallet or amount <= 0:
                return web.json_response({'success': False, 'error': 'Invalid from_wallet or amount'}, status=400)
            tx_data = {'tx_type': 'burn', 'from_wallet': from_wallet, 'to_wallet': config.BURN_ADDRESS_ZERO, 'value': amount, 'fee': _f, 'nonce': _n, 'signature': data.get('signature', ''), 'pub_key': data.get('pub_key')}
            if _ts is not None:
                tx_data['timestamp'] = _ts
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_list(request):
            apps = await self.contract_v2_repo.get_all()
            return web.json_response({'success': True, 'apps': apps, 'count': len(apps)})

        async def api_apps_get(request):
            addr = request.match_info.get('address')
            app_record = await self.contract_v2_repo.get(addr)
            if not app_record:
                return web.json_response({'success': False, 'error': 'App not found'}, status=404)
            return web.json_response({'success': True, 'app': app_record})

        async def api_apps_deploy(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            try:
                _v = util._rint(data, 'value')
                _g = util._rint(data, 'gas', config.GAS_LIMIT_DEFAULT)
                _f, _n = (util._rint(data, 'fee'), util._rint(data, 'nonce'))
                _ts = util._rfloat_opt(data, 'timestamp')
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            tx_data = {'tx_type': 'contract_deploy', 'from_wallet': data.get('from_wallet'), 'bytecode': data.get('bytecode'), 'abi': data.get('abi', {}), 'value': _v, 'gas': _g, 'fee': _f, 'nonce': _n, 'signature': data.get('signature', ''), 'pub_key': data.get('pub_key')}
            if _ts is not None:
                tx_data['timestamp'] = _ts
            if tx_data.get('value', 0) > 0:
                tx_data['_value_moved'] = int(tx_data['value'])
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_call(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            addr = request.match_info.get('address')
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            try:
                _v = util._rint(data, 'value')
                _g = util._rint(data, 'gas', config.GAS_LIMIT_DEFAULT)
                _f, _n = (util._rint(data, 'fee'), util._rint(data, 'nonce'))
                _ts = util._rfloat_opt(data, 'timestamp')
            except util._BadInt as _e:
                return web.json_response({'success': False, 'error': f'{_e} must be numeric'}, status=400)
            tx_data = {'tx_type': 'contract_call', 'from_wallet': data.get('caller', data.get('from_wallet', '0x0000000000000000000000000000000000000000')), 'to_wallet': addr, 'input': data.get('data', data.get('input', '')), 'value': _v, 'gas': _g, 'fee': _f, 'nonce': _n, 'signature': data.get('signature', ''), 'pub_key': data.get('pub_key')}
            if _ts is not None:
                tx_data['timestamp'] = _ts
            if tx_data.get('input') is not None and (not tx_data.get('data')):
                tx_data['data'] = tx_data.pop('input')
            if tx_data.get('value', 0) > 0:
                tx_data['_value_moved'] = int(tx_data['value'])
            tx_data['tx_hash'] = crypto.hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_state(request):
            addr = request.match_info.get('address')
            state = await self.contract_storage_v2_repo.get_all(addr)
            return web.json_response({'success': True, 'address': addr, 'state': state})

        async def api_automations_list(request):
            owner = request.query.get('owner')
            if owner:
                autos = await self.automation_repo.list_by_owner(owner)
            else:
                autos = await self.automation_repo.list_active()
            return web.json_response({'success': True, 'automations': autos, 'count': len(autos)})

        async def api_automations_create(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            try:
                data = await request.json()
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid JSON'}, status=400)
            auto_id = 'auto_' + bootstrap.secrets.token_hex(16)
            rec = {'id': auto_id, 'name': data.get('name', 'MunexAutomation'), 'owner': data.get('owner'), 'trigger_type': data.get('trigger_type', 'time_interval'), 'trigger_config': data.get('trigger_config', {}), 'action_type': data.get('action_type', 'contract_call'), 'action_config': data.get('action_config', {}), 'enabled': bool(data.get('enabled', True)), 'created_at': bootstrap.time.time(), 'last_run_at': None, 'run_count': 0, 'last_result': ''}
            if not rec['owner']:
                return web.json_response({'success': False, 'error': 'Missing owner'}, status=400)
            pub_key = data.get('pub_key')
            signature = data.get('signature')
            ts = data.get('timestamp')
            if not pub_key or not signature:
                return web.json_response({'success': False, 'error': 'Missing signature'}, status=401)
            if ts is None:
                return web.json_response({'success': False, 'error': 'Missing timestamp'}, status=401)
            sign_payload = {'owner': rec['owner'], 'name': rec['name'], 'trigger_type': rec['trigger_type'], 'action_type': rec['action_type'], 'trigger_config': rec['trigger_config'], 'action_config': rec['action_config'], 'timestamp': int(ts), 'enabled': bool(rec['enabled'])}
            message = f'{config.CHAIN_ID}:create_automation:' + crypto.canonical_json_bytes(sign_payload).decode('utf-8')
            try:
                if util.pubkey_to_address(pub_key).lower() != str(rec['owner']).lower():
                    return web.json_response({'success': False, 'error': 'pub_key does not match owner'}, status=401)
            except Exception:
                return web.json_response({'success': False, 'error': 'Invalid pub_key'}, status=401)
            if not crypto.verify_signature(pub_key, message, signature):
                return web.json_response({'success': False, 'error': 'Invalid signature'}, status=401)
            if abs(bootstrap.time.time() - float(ts)) > 300:
                return web.json_response({'success': False, 'error': 'Stale timestamp'}, status=401)
            _seen = getattr(self, '_seen_automation_sigs', None)
            if _seen is None:
                _seen = self._seen_automation_sigs = {}
            _rkey = repos._automation_replay_key(message)
            if repos._automation_sig_replay(_seen, _rkey, bootstrap.time.time()):
                return web.json_response({'success': False, 'error': 'Duplicate signature (replay)'}, status=409)
            try:
                if await self.automation_repo.note_replay_seen(_rkey, bootstrap.time.time()):
                    return web.json_response({'success': False, 'error': 'Duplicate signature (replay)'}, status=409)
            except Exception as _rse:
                bootstrap.logger.debug(f'[Automation] replay-seen DB check skipped: {_rse}')
            await self.automation_repo.create(rec)
            return web.json_response({'success': True, 'automation': repos.AutomationRepo._redact(rec)})

        async def api_automations_get(request):
            auto_id = request.match_info.get('id')
            rec = await self.automation_repo.get(auto_id)
            if not rec:
                return web.json_response({'success': False, 'error': 'Automation not found'}, status=404)
            return web.json_response({'success': True, 'automation': rec})

        async def api_automations_delete(request):
            if not wallet._rpc_remote_authorized(request, self.config):
                return web.json_response({'success': False, 'error': 'Unauthorized: non-loopback clients must present the configured bearer token'}, status=401)
            auto_id = request.match_info.get('id')
            try:
                data = await request.json()
            except Exception:
                data = {}
            owner = (data or {}).get('owner')
            ok, err = repos.verify_automation_delete_auth(auto_id, owner, (data or {}).get('pub_key'), (data or {}).get('signature'), (data or {}).get('timestamp'))
            if not ok:
                return web.json_response({'success': False, 'error': err}, status=401)
            rec = await self.automation_repo.get(auto_id)
            if not rec:
                return web.json_response({'success': False, 'error': 'Automation not found'}, status=404)
            if str(rec.get('owner', '')).lower() != str(owner).lower():
                return web.json_response({'success': False, 'error': 'Not automation owner'}, status=403)
            await self.automation_repo.delete(auto_id)
            return web.json_response({'success': True, 'deleted': auto_id})
        app.router.add_get('/api/v1/tokens', api_tokens_list)
        app.router.add_post('/api/v1/tokens', api_tokens_create)
        app.router.add_get('/api/v1/tokens/{address}', api_tokens_get)
        app.router.add_get('/api/v1/tokens/{address}/balance/{wallet}', api_tokens_balance)
        app.router.add_post('/api/v1/tokens/{address}/transfer', api_tokens_transfer)
        app.router.add_post('/api/v1/tokens/{address}/burn', api_tokens_burn)
        app.router.add_post('/api/v1/burn', api_native_burn)
        app.router.add_get('/api/v1/apps', api_apps_list)
        app.router.add_post('/api/v1/apps', api_apps_deploy)
        app.router.add_get('/api/v1/apps/{address}', api_apps_get)
        app.router.add_get('/api/v1/apps/{address}/state', api_apps_state)
        app.router.add_post('/api/v1/apps/{address}/call', api_apps_call)
        app.router.add_get('/api/v1/automations', api_automations_list)
        app.router.add_post('/api/v1/automations', api_automations_create)
        app.router.add_get('/api/v1/automations/{id}', api_automations_get)
        app.router.add_delete('/api/v1/automations/{id}', api_automations_delete)
        ws_port = self.config.get('node', {}).get('ws_port', config.WS_PORT)
        ws_bind_ip = self.config.get('node', {}).get('ws_bind_ip', '0.0.0.0')
        api_port = self.config.get('node', {}).get('api_port', config.API_PORT)
        try:
            ws_bind_ip, ws_port, api_port = util._validate_ws_bind(ws_bind_ip, ws_port, api_port)
        except ValueError as _be:
            bootstrap.logger.error(f'[WS] Invalid WebSocket listener configuration: {_be}')
            raise
        lan_ip = util._detect_lan_ip()
        bootstrap.logger.info(f'[WS] Miner WebSocket listener: ws://{ws_bind_ip}:{ws_port}/ws (route /ws + GET /healthz; LAN check: ws://{lan_ip}:{ws_port}/ws)')
        runner_ws = web.AppRunner(app_ws)
        await runner_ws.setup()
        try:
            _site_ws = web.TCPSite(runner_ws, ws_bind_ip, ws_port)
            await _site_ws.start()
        except OSError as _oe:
            bootstrap.logger.error(f'[WS] Failed to bind miner WebSocket on {ws_bind_ip}:{ws_port}: {_oe} (port already in use by another process? invalid address for this host?)')
            await runner_ws.cleanup()
            raise RuntimeError(f'miner WebSocket bind failed on {ws_bind_ip}:{ws_port}: {_oe}') from _oe
        runner_api = web.AppRunner(app)
        await runner_api.setup()
        _rpc_bind = self.config.get('node', {}).get('rpc_bind_ip', config.RPC_BIND_IP)
        _site_api = web.TCPSite(runner_api, _rpc_bind, api_port)
        await _site_api.start()
        bootstrap.logger.info(f'[API] Private RPC/REST:       http://{_rpc_bind}:{api_port}/rpc')
        bootstrap.logger.info(f'[API] Private metrics/health: http://{_rpc_bind}:{api_port}/metrics')
        if str(_rpc_bind) == '0.0.0.0' and (not wallet._rpc_bearer_token(self.config)):
            bootstrap.logger.warning('[API] RPC bound to 0.0.0.0 with no bearer token configured: remote POST /rpc is refused; set MCX_RPC_TOKEN / node.rpc_token to serve LAN wallets, and firewall the port')
        bootstrap.logger.info(f'[WS] MetaMask RPC URL: http://{lan_ip}:{api_port}/rpc  (Chain ID: {config.CHAIN_ID})')
        _sites = [{'name': 'WS', 'runner': runner_ws, 'site': _site_ws, 'host': ws_bind_ip, 'port': ws_port, 'path': '/healthz', 'fails': 0}, {'name': 'API', 'runner': runner_api, 'site': _site_api, 'host': _rpc_bind, 'port': api_port, 'path': '/health', 'fails': 0}]
        self._listener_watchdog_task = bootstrap.asyncio.create_task(self._listener_watchdog(_sites))
        try:
            while True:
                await bootstrap.asyncio.sleep(3600)
        except bootstrap.asyncio.CancelledError:
            _wd = getattr(self, '_listener_watchdog_task', None)
            if _wd is not None:
                _wd.cancel()
                try:
                    await _wd
                except bootstrap.asyncio.CancelledError:
                    pass
            await runner_ws.cleanup()
            await runner_api.cleanup()
            raise

    def _subnet_key(self, client_ip: str) -> str:
        try:
            ip = bootstrap.ipaddress.ip_address(client_ip)
            if isinstance(ip, bootstrap.ipaddress.IPv6Address):
                net = bootstrap.ipaddress.ip_network(f'{ip}/64', strict=False)
            else:
                net = bootstrap.ipaddress.ip_network(f'{ip}/24', strict=False)
            return str(net)
        except ValueError:
            return client_ip

    async def _miner_path_allowed(self, miner_id: str) -> bool:
        rl = self.miner_rate_limiters.get(miner_id)
        if rl is None:
            if len(self.miner_rate_limiters) >= 10000:
                return False
            rl = mempool.RateLimiter(max_requests=1200, window_seconds=60)
            self.miner_rate_limiters[miner_id] = rl
        return await rl.is_allowed(miner_id)

    async def _handle_ws_message(self, ws, data: dict, client_ip: str):
        session = self.ws_sessions.get(ws)
        if session is None:
            session = {'tasks': set()}
            self.ws_sessions[ws] = session
        elif 'tasks' not in session:
            session['tasks'] = set()
        msg_type = data.get('type')
        miner_id = data.get('miner_id')
        if miner_id and msg_type != 'register' and (session.get('miner_id') == miner_id) and session.get('authenticated'):
            bootstrap.asyncio.create_task(self.miner_repo.update_last_ping(miner_id))
        if msg_type in ('pqe_hello', 'pqe_confirm'):
            if not bootstrap.MLKEM_AVAILABLE:
                return
            peer_ip = client_ip or 'unknown'
            pqe_timestamps = self.p2p._pqe_rate_limiter.setdefault(peer_ip, [])
            now_ts = bootstrap.time.time()
            pqe_timestamps[:] = [t for t in pqe_timestamps if now_ts - t < 60]
            if len(pqe_timestamps) >= self.p2p._pqe_rate_limit[0]:
                await ws.send_json({'type': 'error', 'message': 'PQE rate limit exceeded'})
                return
            pqe_timestamps.append(now_ts)
        if msg_type == 'pqe_hello':
            try:
                if not bootstrap.MLKEM_AVAILABLE:
                    return
                miner_pqe_pub_hex = data.get('pqe_pub', '')
                if not miner_pqe_pub_hex:
                    await ws.send_json({'type': 'error', 'message': 'pqe_pub missing'})
                    return
                node_priv = bootstrap.mlkem.MLKEM768PrivateKey.generate()
                node_pub_raw = node_priv.public_key().public_bytes_raw()
                miner_pub = bootstrap.mlkem.MLKEM768PublicKey.from_public_bytes(bytes.fromhex(miner_pqe_pub_hex))
                ss_for_miner, ct_for_miner = miner_pub.encapsulate()
                session['pqe_node_priv'] = node_priv
                session['pqe_ss_for_miner'] = ss_for_miner
                await ws.send_json({'type': 'pqe_hello_ack', 'ct': ct_for_miner.hex(), 'node_pqe_pub': node_pub_raw.hex()})
            except Exception as e:
                bootstrap.logger.warning(f'[WS] PQE hello error: {e}')
            return
        if msg_type == 'pqe_confirm':
            try:
                if not bootstrap.MLKEM_AVAILABLE or 'pqe_node_priv' not in session:
                    return
                ct_from_miner = bytes.fromhex(data.get('ct', ''))
                node_priv = session.pop('pqe_node_priv')
                ss_remote = node_priv.decapsulate(ct_from_miner)
                ss_local = session.pop('pqe_ss_for_miner', b'')
                combined = ss_local + ss_remote
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
                from cryptography.hazmat.primitives.hashes import SHA384 as _SHA384
                key = _HKDF(algorithm=_SHA384(), length=32, salt=None, info=b'mcx_miner_ws_mlkem768_aes256gcm').derive(combined)
                session['pqe_key'] = key
                session['pqe_nonce_ctr'] = 0
                orig_send_json = ws.send_json

                async def pqe_send_json(payload_dict, *args, **kwargs):
                    if 'pqe_key' in session:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                        session['pqe_nonce_ctr'] += 1
                        nonce = session['pqe_nonce_ctr'].to_bytes(12, 'big')
                        ct = _AESGCM(session['pqe_key']).encrypt(nonce, bootstrap.json.dumps(payload_dict).encode('utf-8'), None)
                        return await orig_send_json({'type': 'enc', 'ct': ct.hex(), 'nonce': nonce.hex()}, *args, **kwargs)
                    return await orig_send_json(payload_dict, *args, **kwargs)
                ws.send_json = pqe_send_json
                bootstrap.logger.info(f'[WS] PQE ML-KEM-768 session established with {data.get('miner_id', '?'[:16])}')
            except Exception as e:
                bootstrap.logger.warning(f'[WS] PQE confirm error: {e}')
            return
        if msg_type == 'enc' and 'pqe_key' in session:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                ct = bytes.fromhex(data.get('ct', ''))
                nonce = bytes.fromhex(data.get('nonce', ''))
                plain = _AESGCM(session['pqe_key']).decrypt(nonce, ct, None)
                data = bootstrap.json.loads(plain.decode('utf-8'))
                msg_type = data.get('type')
            except Exception as e:
                bootstrap.logger.warning(f'[WS] PQE decrypt error: {e}')
                return
        if msg_type == 'register':
            try:
                miner_id = data.get('miner_id')
                if not miner_id or not miner_id.startswith('PC_'):
                    await ws.send_json({'type': 'registration_failed', 'error': 'Miner ID must start with PC_ prefix'})
                    return
                wallet = data.get('wallet')
                pub_key = data.get('public_key')
                sig = data.get('signature')
                timestamp = data.get('timestamp', int(bootstrap.time.time()))
                block_signing_pub = data.get('block_signing_pub')
                takeover_sig = data.get('takeover_sig')
                ok = await self.register_miner(miner_id, wallet, pub_key, sig, timestamp, block_signing_pub, takeover_sig)
                if ok:
                    challenge = self.memory_mgr.generate_challenge(miner_id)
                    session['challenge_sent'] = True
                    session['miner_id'] = miner_id
                    session['maze_id'] = data.get('maze_id') or miner_id
                    await ws.send_json(challenge)
                else:
                    await ws.send_json({'type': 'registration_failed', 'error': 'Invalid signature or banned'})
            except Exception as e:
                if isinstance(e, (ConnectionResetError, ConnectionError)) or ws.closed:
                    bootstrap.logger.debug(f'[WS] Registration send failed, transport closing: {e}')
                    return
                bootstrap.logger.error(f'[WS] Registration error: {e}', exc_info=True)
                try:
                    await ws.send_json({'type': 'registration_failed', 'error': f'Internal error: {str(e)}'})
                except Exception:
                    pass
        elif msg_type == 'memory_challenge_response':
            if not session.get('challenge_sent'):
                await ws.send_json({'type': 'error', 'message': 'No challenge pending'})
                return
            miner_id = data.get('miner_id')
            if miner_id != session.get('miner_id'):
                await ws.send_json({'type': 'error', 'message': 'Miner ID mismatch'})
                return
            seed = data.get('seed')
            commitment = data.get('commitment')
            loop = bootstrap.asyncio.get_event_loop()
            ok = await loop.run_in_executor(None, self.memory_mgr.verify_commitment, miner_id, seed, commitment)
            if ok:
                session['authenticated'] = True
                session['challenge_verified'] = True
                self.miner_websockets[miner_id] = ws
                self._next_block_time = min(self._next_block_time, bootstrap.time.time() + 0.3)
                await ws.send_json({'type': 'registered', 'confirmed_balance': 0})
                try:
                    row = await self.consensus._load_or_create_maze(miner_id, session.get('maze_id'))
                    if row is None:
                        await ws.send_json({'type': 'error', 'message': 'Maze already in use by another miner'})
                        return
                    loop = bootstrap.asyncio.get_event_loop()
                    sparse_maze = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, row['seed'], row['size'], int(row['walldensityppm']), int(row['turbulenceppm']), self.height)
                    maze = _maze.sparse_to_dense(sparse_maze)
                    maze_id_init = row.get('maze_id') or miner_id
                    sealed_init = self.consensus._sealed_walls.get(maze_id_init, set())
                    for sx, sy, sz in sealed_init:
                        if 0 <= sz < row['size'] and 0 <= sy < row['size'] and (0 <= sx < row['size']):
                            maze[sz][sy][sx] = 1
                    start = (row['posx'], row['posy'], row['posz'])
                    goal = (row['goalx'], row['goaly'], row['goalz'])
                    maze_id = row.get('maze_id') or miner_id
                    ghost = self.consensus._ghost_tuple(row)
                    sealed = self.consensus._sealed_walls.get(maze_id)
                    await ws.send_json({'type': 'maze_init', 'maze': maze, 'size': row['size'], 'start': list(start), 'goal': list(goal), 'maze_root': row['mazeroot'], 'block_id': self.height, 'difficulty': 1.0, 'max_path_length': 10 ** 9, 'step_interval': 0.0, 'required_knowledge': 10, 'ghost': list(ghost) if ghost else None, 'sealed_walls': [list(w) for w in sealed] if sealed else [], 'growthcount': int(row['growthcount']), 'movenonce': int(row['movenonce'])})
                except Exception as e:
                    bootstrap.logger.error(f'[WS] MAZE_INIT ERROR for {miner_id}: {e}', exc_info=True)
                    await ws.send_json({'type': 'error', 'message': f'maze_init: {e}'})
            else:
                await ws.send_json({'type': 'registration_failed', 'error': 'Challenge failed'})
        elif msg_type == 'maze_move':
            try:
                miner_id = data.get('miner_id')
                maze_id = data.get('maze_id') or miner_id
                direction = data.get('direction')
                signature = data.get('signature')
                move_nonce = data.get('move_nonce', None)
                if not all([miner_id, direction, signature]):
                    await ws.send_json({'type': 'error', 'message': 'Missing fields'})
                    return
                if not isinstance(miner_id, str) or not isinstance(maze_id, str) or (not isinstance(direction, str)) or (not isinstance(signature, str)) or (len(miner_id) > 128) or (len(maze_id) > 192) or (len(signature) > 1024):
                    await ws.send_json({'type': 'error', 'message': 'Malformed fields'})
                    return
                if not (session.get('authenticated') and session.get('miner_id') == miner_id):
                    await ws.send_json({'type': 'error', 'message': 'Not authenticated as miner'})
                    return
                _inflight_since = self.consensus._inflight_moves.get(miner_id)
                if _inflight_since is not None:
                    if bootstrap.time.monotonic() - _inflight_since > 30:
                        bootstrap.logger.warning(f'[WS] Reclaiming stale in-flight move for {miner_id[:16]} (age {bootstrap.time.monotonic() - _inflight_since:.0f}s)')
                        self.consensus._inflight_moves.pop(miner_id, None)
                    else:
                        _q = self.consensus._move_queues.setdefault(miner_id, bootstrap.deque())
                        if len(_q) < 2:
                            _q.append((ws, session, miner_id, maze_id, direction, signature, move_nonce))
                            return
                        await ws.send_json({'type': 'maze_move_ack', 'success': False, 'message': 'busy, retry'})
                        return
                self.consensus._inflight_moves[miner_id] = bootstrap.time.monotonic()

                async def _run_move(_job):
                    ws, session, miner_id, maze_id, direction, signature, move_nonce = _job
                    try:
                        if ws.closed:
                            return
                        _own_row = await self.maze_repo.get_by_maze_id(maze_id)
                        if not _own_row or str(_own_row.get('minerid') or '') != miner_id:
                            await ws.send_json({'type': 'error', 'message': 'Maze not owned by miner'})
                            return
                        if not await self._miner_path_allowed(miner_id):
                            await ws.send_json({'type': 'error', 'message': 'Rate limit exceeded'})
                            return
                        _pre_row = await self.maze_repo.get_by_maze_id(maze_id)
                        _pre_growthcount = int(_pre_row['growthcount']) if _pre_row else 0
                        success, msg, state = await self.consensus.process_move(miner_id, maze_id, direction, signature, move_nonce)
                        if ws.closed:
                            return
                        if state.get('type') == 'wall_hit':
                            await ws.send_json(state)
                        else:
                            ack = {'type': 'maze_move_ack', 'success': success, 'message': msg, 'state': state}
                            _ack_row = await self.maze_repo.get_by_maze_id(maze_id)
                            if _ack_row:
                                ack['movenonce'] = int(_ack_row['movenonce'])
                                ack['growthcount'] = int(_ack_row['growthcount'])
                            ghost = self.consensus._ghost_tuple(_ack_row)
                            if ghost:
                                ack['ghost'] = list(ghost)
                            sealed = self.consensus._sealed_walls.get(maze_id)
                            if sealed:
                                ack['sealed_walls'] = [list(w) for w in sealed]
                            if success and (state.get('caught') or state.get('shrink')):
                                try:
                                    row = await self.maze_repo.get_by_maze_id(maze_id)
                                    if row:
                                        loop = bootstrap.asyncio.get_event_loop()
                                        sparse_maze = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, row['seed'], row['size'], int(row['walldensityppm']), int(row['turbulenceppm']), self.height)
                                        ack['maze'] = _maze.sparse_to_dense(sparse_maze)
                                        ack['size'] = row['size']
                                        ack['start'] = [row['posx'], row['posy'], row['posz']]
                                        ack['goal'] = [row['goalx'], row['goaly'], row['goalz']]
                                        ack['growthcount'] = row['growthcount']
                                        ack['movenonce'] = row['movenonce']
                                except Exception as e:
                                    bootstrap.logger.error(f'[WS] maze growth send error for {miner_id}: {e}', exc_info=True)
                            await ws.send_json(ack)
                        if (success or state.get('type') == 'wall_hit') and getattr(self, 'p2p', None):
                            try:
                                _post_row = await self.maze_repo.get_by_maze_id(maze_id)
                                _g_pubrow = await self.miner_repo.get(miner_id)
                                _g_pub = ''
                                if _g_pubrow and _g_pubrow.get('pub'):
                                    _g_pub = _g_pubrow['pub']
                                elif miner_id in self.miners:
                                    _g_pub = (self.miners[miner_id] or {}).get('pub', '')
                                _gossip = {'miner_id': miner_id, 'maze_id': maze_id, 'direction': direction, 'signature': signature, 'height': self.height, 'move_nonce': int(_pre_row['movenonce']) + 1 if _pre_row else move_nonce if move_nonce is not None else 0, 'growthcount': _pre_growthcount, 'pub': _g_pub, 'row': dict(_post_row) if _post_row else None, 'pos_hist': [[int(v) for v in p] for p in self.consensus._pos_history.get(maze_id, [])], 'oscillating': maze_id in self.consensus._oscillating_mazes}
                                await self.p2p.broadcast_message(config.MSG_NEW_MOVE, bootstrap.json.dumps(_gossip).encode())
                            except Exception as _ge:
                                bootstrap.logger.debug(f'[WS] move-gossip broadcast failed: {_ge}')
                    except Exception as e:
                        bootstrap.logger.error(f'[WS] maze_move task error: {e}', exc_info=True)
                        if not ws.closed:
                            try:
                                await ws.send_json({'type': 'error', 'message': f'Internal error: {str(e)}'})
                            except Exception:
                                pass
                    finally:
                        self.consensus._inflight_moves.pop(miner_id, None)
                        _q = self.consensus._move_queues.get(miner_id)
                        while _q:
                            _njob = _q.popleft()
                            if not _q:
                                self.consensus._move_queues.pop(miner_id, None)
                            _nws, _nsess, _nminer, _nmaze, _ndir, _nsig, _nnonce = _njob
                            if _nws.closed:
                                continue
                            self.consensus._inflight_moves[_nminer] = bootstrap.time.monotonic()
                            _nt = bootstrap.asyncio.create_task(_run_move(_njob))
                            _nsess.setdefault('tasks', set()).add(_nt)
                            _nt.add_done_callback(lambda _, _s=_nsess, _t=_nt: _s.get('tasks', set()).discard(_t))
                            break
                _t = bootstrap.asyncio.create_task(_run_move((ws, session, miner_id, maze_id, direction, signature, move_nonce)))
                session.setdefault('tasks', set()).add(_t)
                _t.add_done_callback(lambda _: session.get('tasks', set()).discard(_t))
            except Exception as e:
                bootstrap.logger.error(f'[WS] maze_move error: {e}', exc_info=True)
                await ws.send_json({'type': 'error', 'message': f'Internal error: {str(e)}'})
        elif msg_type == 'wall_hit_solve':
            miner_id = data.get('miner_id')
            maze_id = data.get('maze_id') or miner_id
            if not isinstance(miner_id, str) or not isinstance(maze_id, str) or len(miner_id) > 128 or (len(maze_id) > 192) or (not (session.get('authenticated') and session.get('miner_id') == miner_id)):
                await ws.send_json({'type': 'wall_hit_solved', 'accepted': False, 'error': 'Not authenticated as miner'})
                return
            _own_row = await self.maze_repo.get_by_maze_id(maze_id)
            if not _own_row or str(_own_row.get('minerid') or '') != miner_id:
                await ws.send_json({'type': 'wall_hit_solved', 'accepted': False, 'error': 'Maze not owned by miner'})
                return
            if not await self._miner_path_allowed(miner_id):
                await ws.send_json({'type': 'wall_hit_solved', 'accepted': False, 'error': 'Rate limit exceeded'})
                return
            pending = self.consensus._pending_pow.get(maze_id)
            accepted = False
            caught_by_ghost = False
            if pending:
                seed, difficulty, ts = pending
                if bootstrap.time.time() - ts > 60:
                    self.consensus._pending_pow.pop(maze_id, None)
                else:
                    try:
                        nonce = int(data.get('nonce'))
                        digest = bootstrap.hashlib.sha256(f'{seed}{nonce}'.encode()).digest()
                        accepted = int.from_bytes(digest, 'big') >> 256 - difficulty == 0
                    except (TypeError, ValueError, OverflowError):
                        accepted = False
                    if accepted:
                        self.consensus._pending_pow.pop(maze_id, None)
            resp = {'type': 'wall_hit_solved', 'accepted': accepted}
            if accepted:

                async def _solve_and_reply():
                    try:
                        if ws.closed:
                            return
                        caught = False
                        async with self.consensus._lock_for(maze_id):
                            row = await self.consensus.maze_repo.get_by_maze_id(maze_id)
                            if row:
                                gpos = self.consensus._ghost_tuple(row)
                                gpos_moved = False
                                gsize = int(row['size'])
                                msx, msy, msz = (int(row['posx']), int(row['posy']), int(row['posz']))
                                loop = bootstrap.asyncio.get_event_loop()
                                msparse = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, row['seed'], gsize, int(row['walldensityppm']), int(row['turbulenceppm']), self.height)
                                mdense = _maze.sparse_to_dense(msparse)
                                if gpos:
                                    if maze_id in self.consensus._oscillating_mazes:
                                        if maze_id not in self.consensus._ghost_cycle:
                                            cycle_cells = []
                                            for p in self.consensus._pos_history.get(maze_id, []):
                                                if p not in cycle_cells:
                                                    cycle_cells.append(p)
                                            if cycle_cells:

                                                def _manh(a, b):
                                                    return abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
                                                farthest_idx = max(range(len(cycle_cells)), key=lambda i: _manh(gpos, cycle_cells[i]))
                                                self.consensus._ghost_cycle[maze_id] = cycle_cells
                                                self.consensus._ghost_cycle_idx[maze_id] = farthest_idx
                                                self.consensus._ghost_frozen_target[maze_id] = cycle_cells[farthest_idx]
                                        if maze_id in self.consensus._ghost_cycle:
                                            cycle_cells = self.consensus._ghost_cycle[maze_id]
                                            idx = self.consensus._ghost_cycle_idx[maze_id]
                                            target = cycle_cells[idx]
                                            if gpos == target:
                                                idx = (idx + 1) % len(cycle_cells)
                                                self.consensus._ghost_cycle_idx[maze_id] = idx
                                                target = cycle_cells[idx]
                                            for _ in range(3):
                                                gdx, gdy, gdz = self.consensus._bfs_next_step(mdense, gsize, gpos, target)
                                                if gdx is None:
                                                    break
                                                new_gpos = (gpos[0] + gdx, gpos[1] + gdy, gpos[2] + gdz)
                                                gpos = new_gpos
                                                gpos_moved = True
                                                if new_gpos == (msx, msy, msz):
                                                    caught = True
                                                    restart_ev = await self.consensus._restart_position(dict(row), maze_id, row['minerid'], gsize)
                                                    if restart_ev:
                                                        await self.consensus.maze_repo.upsert({**dict(row), **restart_ev})
                                                    break
                                    else:
                                        for _ in range(3):
                                            gdx, gdy, gdz = self.consensus._bfs_next_step(mdense, gsize, gpos, (msx, msy, msz))
                                            if gdx is None:
                                                break
                                            new_gpos = (gpos[0] + gdx, gpos[1] + gdy, gpos[2] + gdz)
                                            gpos = new_gpos
                                            gpos_moved = True
                                            if new_gpos == (msx, msy, msz):
                                                caught = True
                                                restart_ev = await self.consensus._restart_position(dict(row), maze_id, row['minerid'], gsize)
                                                if restart_ev:
                                                    await self.consensus.maze_repo.upsert({**dict(row), **restart_ev})
                                                break
                                if gpos_moved and (not caught):
                                    self.consensus._set_ghost(row, gpos)
                                    await self.consensus.maze_repo.upsert(dict(row))
                        reply = {'type': 'wall_hit_solved', 'accepted': True, 'caught': caught}
                        reply['sealed_walls'] = list(self.consensus._sealed_walls.get(maze_id, set()))
                        reply['ghost'] = None
                        try:
                            row_data = await self.maze_repo.get_by_maze_id(maze_id)
                            if row_data:
                                _gp = self.consensus._ghost_tuple(row_data)
                                reply['ghost'] = list(_gp) if _gp else None
                                reply['position'] = [int(row_data['posx']), int(row_data['posy']), int(row_data['posz'])]
                                reply['goal'] = [int(row_data['goalx']), int(row_data['goaly']), int(row_data['goalz'])]
                                reply['size'] = int(row_data['size'])
                                reply['movenonce'] = int(row_data['movenonce'])
                                reply['growthcount'] = int(row_data['growthcount'])
                                sz = int(row_data['size'])
                                loop = bootstrap.asyncio.get_event_loop()
                                sp = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, row_data['seed'], sz, int(row_data['walldensityppm']), int(row_data['turbulenceppm']), self.height)
                                maze_arr = _maze.sparse_to_dense(sp)
                                sealed_here = self.consensus._sealed_walls.get(maze_id, set())
                                for wx, wy, wz in sealed_here:
                                    if 0 <= wz < sz and 0 <= wy < sz and (0 <= wx < sz):
                                        maze_arr[wz][wy][wx] = 1
                                reply['maze'] = maze_arr
                        except Exception:
                            pass
                        if not ws.closed:
                            await ws.send_json(reply)
                    except Exception as e:
                        bootstrap.logger.error(f'[WS] wall_hit_solve task error: {e}', exc_info=True)
                        if not ws.closed:
                            try:
                                await ws.send_json({'type': 'error', 'message': str(e)})
                            except Exception:
                                pass
                _t = bootstrap.asyncio.create_task(_solve_and_reply())
                session.setdefault('tasks', set()).add(_t)
                _t.add_done_callback(lambda _: session.get('tasks', set()).discard(_t))
            else:
                resp['caught'] = False
                await ws.send_json(resp)
        elif msg_type == 'knowledge_report':
            await ws.send_json({'type': 'knowledge_ack', 'accepted': True})
        elif msg_type == 'lottery_commit':
            miner_id = data.get('miner_id')
            commit = data.get('commit')
            target_height = data.get('height')
            if not all([miner_id, commit, target_height is not None]):
                await ws.send_json({'type': 'error', 'message': 'Missing fields'})
                return
            if not (session.get('authenticated') and session.get('miner_id') == miner_id):
                await ws.send_json({'type': 'error', 'message': 'Not authenticated as miner'})
                return
            if target_height < self.height + 1 or target_height > self.height + 2:
                await ws.send_json({'type': 'error', 'message': 'Commit window is [height+1, height+2]'})
                return
            commits = self.consensus._lottery_commits.setdefault(target_height, {})
            commits[miner_id] = commit
            await self.consensus.lottery_repo.put_commit(target_height, miner_id, commit)
            await ws.send_json({'type': 'lottery_commit_ack', 'accepted': True})
        elif msg_type == 'lottery_reveal':
            miner_id = data.get('miner_id')
            secret = data.get('secret')
            target_height = data.get('height')
            if not all([miner_id, secret, target_height is not None]):
                await ws.send_json({'type': 'error', 'message': 'Missing fields'})
                return
            if not (session.get('authenticated') and session.get('miner_id') == miner_id):
                await ws.send_json({'type': 'error', 'message': 'Not authenticated as miner'})
                return
            if target_height <= self.height:
                await ws.send_json({'type': 'error', 'message': 'Reveal too late'})
                return
            commits = self.consensus._lottery_commits.get(target_height, {})
            expected_commit = commits.get(miner_id)
            if not expected_commit:
                await ws.send_json({'type': 'error', 'message': 'No commit found'})
                return
            actual_commit = bootstrap.eth_keccak(bytes.fromhex(secret) + miner_id.encode() + target_height.to_bytes(8, 'big')).hex()
            if actual_commit != expected_commit:
                await ws.send_json({'type': 'error', 'message': 'Commit mismatch'})
                return
            reveals = self.consensus._lottery_reveals.setdefault(target_height, {})
            reveals[miner_id] = secret
            await self.consensus.lottery_repo.put_reveal(target_height, miner_id, secret)
            await ws.send_json({'type': 'lottery_reveal_ack', 'accepted': True})
        elif msg_type == 'get_maze_state':
            miner_id = data.get('miner_id')
            maze_id = data.get('maze_id') or miner_id
            if not miner_id:
                await ws.send_json({'type': 'error', 'message': 'Missing miner_id'})
                return
            if not isinstance(miner_id, str) or not isinstance(maze_id, str) or len(miner_id) > 128 or (len(maze_id) > 192) or (not (session.get('authenticated') and session.get('miner_id') == miner_id)):
                await ws.send_json({'type': 'error', 'message': 'Not authenticated as miner'})
                return
            if ws.closed:
                return
            row = await self.maze_repo.get_by_maze_id(maze_id)
            if not row or str(row.get('minerid') or '') != miner_id:
                await ws.send_json({'type': 'error', 'message': 'Maze not owned by miner'})
                return
            state = None
            if row:
                size = row['size']
                loop = bootstrap.asyncio.get_event_loop()
                sparse_maze = await loop.run_in_executor(self.consensus._move_executor, self.consensus._generate_deterministic_maze, row['seed'], size, int(row['walldensityppm']), int(row['turbulenceppm']), self.height)
                maze_array = _maze.sparse_to_dense(sparse_maze)
                sx, sy, sz = (row['posx'], row['posy'], row['posz'])
                gx, gy, gz = (row['goalx'], row['goaly'], row['goalz'])
                sealed = self.consensus._sealed_walls.get(maze_id, set())
                for wx, wy, wz in sealed:
                    if 0 <= wz < size and 0 <= wy < size and (0 <= wx < size):
                        maze_array[wz][wy][wx] = 1
                if not (0 <= sx < size and 0 <= sy < size and (0 <= sz < size)) or maze_array[sz][sy][sx] == 1:
                    sx, sy, sz = self.consensus._find_nearest_open(maze_array, size, sx, sy, sz)
                    await self.maze_repo.upsert({**dict(row), 'posx': sx, 'posy': sy, 'posz': sz, 'updatedat': int(bootstrap.time.time())})
                if not (0 <= gx < size and 0 <= gy < size and (0 <= gz < size)) or maze_array[gz][gy][gx] == 1:
                    gx, gy, gz = self.consensus._find_nearest_open(maze_array, size, gx, gy, gz)
                    await self.maze_repo.upsert({**dict(row), 'goalx': gx, 'goaly': gy, 'goalz': gz, 'updatedat': int(bootstrap.time.time())})
                state = {'miner_id': row['minerid'], 'size': size, 'position': (sx, sy, sz), 'goal': (gx, gy, gz), 'movenonce': row['movenonce'], 'mazeroot': row['mazeroot'], 'growthcount': row['growthcount'], 'walldensityppm': row['walldensityppm'], 'turbulenceppm': row['turbulenceppm'], 'maze': maze_array, 'ghost': list(self.consensus._ghost_tuple(row) or (0, 0, 0))}
            if not ws.closed:
                await ws.send_json({'type': 'maze_state', 'state': state})
        elif msg_type == 'get_fee':
            min_fee = gas.quote_transfer_fee(self.mempool.size())
            token_fee = gas.quote_token_creation_fee(self.mempool.size())
            await ws.send_json({'type': 'fee_info', 'min_fee': min_fee, 'base_fee': gas.SVF_FEE_BASE, 'mempool_size': self.mempool.size(), 'token_creation_fee': token_fee})
        elif msg_type == 'send_tx':
            tx_data = {'from_wallet': (data.get('wallet') or '').lower(), 'to_wallet': (data.get('to') or '').lower(), 'value': data.get('amount', 0), 'fee': data.get('fee', 0), 'nonce': data.get('nonce', 0), 'timestamp': float(data.get('timestamp')) if data.get('timestamp') else bootstrap.time.time(), 'tx_type': 'send', 'signature': data.get('signature'), 'pub_key': data.get('pub_key'), 'data': data.get('data', {})}
            tx_hash = crypto.hash_tx(tx_data)
            tx_data['tx_hash'] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({'type': 'tx_failed', 'error': 'Invalid signature'})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({'type': 'tx_accepted', 'tx_hash': tx_hash})
            else:
                await ws.send_json({'type': 'tx_failed', 'error': 'Mempool full or invalid'})
        elif msg_type == 'token_transfer':
            tx_data = {'from_wallet': (data.get('wallet') or '').lower(), 'to_wallet': (data.get('to') or '').lower(), 'value': data.get('amount', 0), 'fee': data.get('fee', 0), 'nonce': data.get('nonce', 0), 'timestamp': float(data.get('timestamp')) if data.get('timestamp') else bootstrap.time.time(), 'tx_type': 'token_transfer', 'signature': data.get('signature'), 'token_address': data.get('token_address'), 'data': data.get('data', {})}
            tx_hash = crypto.hash_tx(tx_data)
            tx_data['tx_hash'] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({'type': 'tx_failed', 'error': 'Invalid signature'})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({'type': 'tx_accepted', 'tx_hash': tx_hash})
            else:
                await ws.send_json({'type': 'tx_failed', 'error': 'Mempool full or invalid'})
        elif msg_type == 'deploy_contract':
            tx_data = {'from_wallet': (data.get('wallet') or '').lower(), 'to_wallet': (data.get('wallet') or '').lower(), 'value': 0, 'fee': data.get('fee', 0), 'nonce': data.get('nonce', 0), 'timestamp': float(data.get('timestamp')) if data.get('timestamp') else bootstrap.time.time(), 'tx_type': 'contract_deploy', 'signature': data.get('signature'), 'bytecode': data.get('bytecode', ''), 'abi': data.get('abi', {})}
            try:
                _wsv = int(tx_data.get('value', 0) or 0)
            except (TypeError, ValueError):
                _wsv = 0
            if _wsv > 0:
                tx_data['_value_moved'] = _wsv
            tx_hash = crypto.hash_tx(tx_data)
            tx_data['tx_hash'] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({'type': 'tx_failed', 'error': 'Invalid signature'})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({'type': 'tx_accepted', 'tx_hash': tx_hash})
            else:
                await ws.send_json({'type': 'tx_failed', 'error': 'Mempool full or invalid'})
        elif msg_type == 'call_contract':
            tx_data = {'from_wallet': (data.get('wallet') or '').lower(), 'to_wallet': (data.get('contract_address') or '').lower(), 'value': data.get('value', 0), 'fee': data.get('fee', 0), 'nonce': data.get('nonce', 0), 'timestamp': float(data.get('timestamp')) if data.get('timestamp') else bootstrap.time.time(), 'tx_type': 'contract_call', 'signature': data.get('signature'), 'input': data.get('input', ''), 'gas': data.get('gas_limit', config.GAS_LIMIT_DEFAULT)}
            if tx_data.get('input') is not None and (not tx_data.get('data')):
                tx_data['data'] = tx_data.pop('input')
            try:
                _wsv = int(tx_data.get('value', 0) or 0)
            except (TypeError, ValueError):
                _wsv = 0
            if _wsv > 0:
                tx_data['_value_moved'] = _wsv
            tx_hash = crypto.hash_tx(tx_data)
            tx_data['tx_hash'] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({'type': 'tx_failed', 'error': 'Invalid signature'})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({'type': 'tx_accepted', 'tx_hash': tx_hash})
            else:
                await ws.send_json({'type': 'tx_failed', 'error': 'Mempool full or invalid'})
        elif msg_type == 'get_balance':
            wallet = data.get('wallet')
            if not wallet:
                await ws.send_json({'type': 'balance', 'balance': 0, 'error': 'Missing wallet'})
                return
            bal = await self.get_balance(wallet.lower() if isinstance(wallet, str) else wallet)
            await ws.send_json({'type': 'balance', 'balance': bal})
        elif msg_type == 'get_status':
            status = {'height': self.height, 'peers': self.p2p.get_peer_count() if self.p2p else 0, 'miners': len(self.miners), 'version': config.VERSION}
            await ws.send_json({'type': 'status', 'data': status})
        elif msg_type == 'get_blocks':
            limit, offset = util._ws_page_params(data)
            blocks = []
            total = len(self.blocks)
            start = max(0, total - offset - limit)
            end = total - offset
            for b in self.blocks[start:end]:
                blocks.append({'height': b['id'], 'timestamp': b['ts'], 'miners': len(b.get('miners', [])), 'reward': b.get('reward', 0) // config.SUBS, 'hash': b['hash']})
            blocks.reverse()
            has_more = total - offset - limit > 0
            await ws.send_json({'type': 'blocks', 'data': {'blocks': blocks, 'has_more': has_more}})
        elif msg_type == 'get_transactions':
            limit, offset = util._ws_page_params(data)
            if self.db.db_type == 'sqlite':
                query = 'SELECT tx_hash, from_wallet, to_wallet, amount, timestamp, block_id, status FROM transactions WHERE block_id >= 0 ORDER BY timestamp DESC LIMIT ? OFFSET ?'
            else:
                query = 'SELECT tx_hash, from_wallet, to_wallet, amount, timestamp, block_id, status FROM transactions WHERE block_id >= 0 ORDER BY timestamp DESC LIMIT $1 OFFSET $2'
            rows = await self.db.fetch(query, limit, offset)
            txs = [{'hash': r['tx_hash'][:12], 'full_hash': r['tx_hash'], 'from': r['from_wallet'], 'to': r['to_wallet'], 'amount': r['amount'] // config.SUBS, 'timestamp': r['timestamp'], 'block': r['block_id'], 'status': r['status']} for r in rows]
            total_row = await self.db.fetchrow('SELECT COUNT(*) AS count FROM transactions WHERE block_id >= 0')
            total = total_row['count'] if total_row else 0
            has_more = total - offset - limit > 0
            await ws.send_json({'type': 'transactions', 'data': {'transactions': txs, 'has_more': has_more}})
        elif msg_type == 'get_miners':
            wallet = data.get('wallet')
            if wallet:
                miners = await self.miner_repo.get_by_wallet(wallet)
            else:
                miners = await self.miner_repo.get_active()
            miners_list = [{'miner_id': m['miner_id'], 'wallet': m['wallet'], 'active': m['active'], 'blocks': m['blocks'], 'rewards': m['rewards'] // config.SUBS, 'uptime': m['uptime'], 'last_ping': m['last_ping']} for m in miners]
            _trunc_m = len(miners_list) > 1000
            await ws.send_json({'type': 'miners', 'miners': miners_list[:1000], 'truncated': _trunc_m})
        elif msg_type == 'get_tokens':
            wallet = data.get('wallet')
            if wallet:
                tokens = await self.db.fetch('SELECT * FROM tokens WHERE owner = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM tokens WHERE owner = $1', wallet)
            else:
                tokens = await self.db.fetch('SELECT * FROM tokens')
            _toks = [dict(t) for t in tokens]
            await ws.send_json({'type': 'tokens', 'tokens': _toks[:1000], 'truncated': len(_toks) > 1000})
        elif msg_type == 'get_htlc':
            htlc_id = data.get('htlc_id')
            if not htlc_id:
                await ws.send_json({'type': 'error', 'message': 'Missing htlc_id'})
                return
            htlc = await self.htlc_repo.get(htlc_id)
            if htlc:
                await ws.send_json({'type': 'htlc', 'data': htlc})
            else:
                await ws.send_json({'type': 'htlc', 'data': None})
        elif msg_type == 'uptime_ping':
            miner_id = data.get('miner_id')
            uptime_seconds = data.get('uptime_seconds', 0)
            if miner_id:
                if self.miner_websockets.get(miner_id) is not ws or session.get('miner_id') != miner_id or (not session.get('authenticated')):
                    await ws.send_json({'type': 'error', 'message': 'uptime_ping from unauthenticated connection'})
                    return
                await self.miner_repo.update_last_ping(miner_id)
                maze_rows = await self.maze_repo.get(miner_id)
                if maze_rows:
                    for mz in maze_rows:
                        await self.maze_repo.upsert({**dict(mz), 'updatedat': int(bootstrap.time.time())})
                bootstrap.logger.debug(f'[WS] Uptime ping from {miner_id}: {uptime_seconds}s')
        elif msg_type == 'block_signed':
            miner_id = data.get('miner_id')
            signed_block = data.get('block')
            if miner_id and signed_block:
                if self.miner_websockets.get(miner_id) is not ws:
                    await ws.send_json({'type': 'error', 'message': 'block_signed from unregistered connection'})
                    return
                future = self._block_sign_futures.get(miner_id)
                if future and (not future.done()):
                    future.set_result(signed_block)
                    bootstrap.logger.debug(f'[WS] Received block_signed from {miner_id[:16]}')
                else:
                    bootstrap.logger.warning(f'[WS] block_signed from {miner_id[:16]} with no pending future')
                    _late_id = signed_block.get('id')
                    _n0 = len(self.consensus._pending_slashes) + len(self.consensus._deferred_slashes)
                    self.consensus._pending_slashes = [_ev for _ev in self.consensus._pending_slashes if not (_ev.get('reason') == 'signing_refusal' and _ev.get('miner_id') == miner_id and (_late_id is None or _ev.get('block_id') == _late_id))]
                    self.consensus._deferred_slashes = [_ev for _ev in self.consensus._deferred_slashes if not (_ev.get('reason') == 'signing_refusal' and _ev.get('miner_id') == miner_id and (_late_id is None or _ev.get('block_id') == _late_id))]
                    if len(self.consensus._pending_slashes) + len(self.consensus._deferred_slashes) != _n0:
                        bootstrap.logger.info(f'[WS] Late block_signed from {miner_id[:16]} forgave pending signing_refusal slash (block {_late_id})')
            else:
                await ws.send_json({'type': 'error', 'message': 'block_signed missing miner_id or block'})
        else:
            await ws.send_json({'type': 'error', 'message': f'Unknown message type: {msg_type}'})

    def _finality_lag_blocks(self) -> int:
        try:
            last_final = self.finality_gadget.get_last_finalized_block()
            if last_final <= 0:
                return max(0, self.height - 1)
            return max(0, self.height - 1 - last_final)
        except Exception:
            return 0

    async def _verify_chain_integrity(self, depth: int=100):
        latest = await self.block_repo.get_latest()
        if not latest:
            return
        end = latest['id']
        start = max(0, end - depth)
        blocks = await self.block_repo.get_range(start, end, limit=depth + 1)
        prev_hash = None
        for b in sorted(blocks, key=lambda x: x['id']):
            expected = crypto.calculate_block_hash({k: v for k, v in b.items() if k not in maze.CONSENSUS_EXCLUDED_FIELDS})
            if b.get('hash') != expected and b.get('id', 0) > 0:
                bootstrap.logger.error(f'[Integrity] Block {b['id']} hash mismatch')
                bootstrap.sys.exit(1)
            if prev_hash is not None and b.get('phash') != prev_hash and (b.get('id', 0) > 0):
                bootstrap.logger.error(f'[Integrity] Block {b['id']} parent mismatch')
                bootstrap.sys.exit(1)
            prev_hash = b.get('hash', '')
        bootstrap.logger.info(f'[Integrity] Verified last {len(blocks)} blocks')

    async def _restore_from_latest_snapshot(self) -> bool:
        row = await self.db.fetchrow('SELECT block_id, state_root, snapshot_data FROM state_snapshots ORDER BY block_id DESC LIMIT 1')
        if not row:
            return False
        if self.height <= int(row['block_id']) + 500:
            return False
        try:
            data = bootstrap.json.loads(row['snapshot_data'])
        except Exception:
            return False
        if not isinstance(data, dict) or not data:
            return False
        try:
            candidate = {k: v if isinstance(v, str) else bootstrap.json.dumps(v, sort_keys=True, separators=(',', ':')) for k, v in data.items()}
        except Exception:
            return False
        _probe = db.StateTrie(self.db)
        _probe._dirty = dict(candidate)
        try:
            root, _ = _probe._compute_root()
        except Exception:
            return False
        if root != row['state_root']:
            return False
        blk = await self.block_repo.get_by_id(int(row['block_id']))
        if not blk:
            return False
        _prior_dirty = dict(self.state_trie._dirty)
        self.state_trie._dirty = dict(candidate)
        _written = await self.state_trie.commit()
        if _written != root:
            self.state_trie._dirty = _prior_dirty
            return False
        self.height = int(row['block_id']) + 1
        self.last_hash = blk.get('hash', '')
        bootstrap.logger.info(f'[Snapshot] Restored state from block {row['block_id']}')
        return True

    def _persist_config(self, updates: dict) -> None:
        import yaml as _yaml
        try:
            with open(config.CONFIG_PATH, encoding='utf-8') as _f:
                _disk = _yaml.safe_load(_f) or {}
            for (_sec, _key), _val in updates.items():
                _disk.setdefault(_sec, {})[_key] = _val
            with open(config.CONFIG_PATH, 'w', encoding='utf-8') as _f:
                _yaml.safe_dump(_disk, _f, sort_keys=False)
            bootstrap.logger.warning(f'[CONFIG] wrote to {config.CONFIG_PATH}: {sorted((f'{a}.{b}' for a, b in updates))}')
        except OSError as _e:
            bootstrap.logger.error(f'[CONFIG] could not write {config.CONFIG_PATH}: {_e}')

    def _prepare_mainnet_config(self) -> None:
        _updates = {}
        _node = self.config.setdefault('node', {})
        if 'rpc_trust_loopback' not in _node:
            _node['rpc_trust_loopback'] = False
            _updates['node', 'rpc_trust_loopback'] = False
        _vm = self.config.setdefault('vm', {})
        if not bool(_vm.get('require_sandbox', False)):
            _vm['require_sandbox'] = True
            _updates['vm', 'require_sandbox'] = True
        if _updates:
            self._persist_config(_updates)
        if bootstrap._auto_install_enabled():
            bootstrap.logger.warning('[CONFIG] auto-install is enabled: pip may run at boot. Set MCX_ALLOW_AUTO_INSTALL=0 once dependencies are installed.')

    async def start(self):
        try:
            import importlib.util as _ilu
            _missing_opt = [pip_name for imp, pip_name, req in bootstrap._DEPS if not req and _ilu.find_spec(imp) is None]
        except Exception:
            _missing_opt = []
        if _missing_opt:
            bootstrap.logger.info(f'[Startup] Optional packages not installed: {_missing_opt}. Some features (Postgres, DHT, uvloop, ML-KEM-768 PQE) are disabled.')
        bootstrap.set_trace_id(f'start-{bootstrap.new_trace_id()}')
        svf_keys._svf_ensure_key_loaded(self.config)
        if bootstrap.sys.platform == 'win32' and bool((self.config.get('vm') or {}).get('require_sandbox', False)):
            bootstrap.logger.warning('[SANDBOX-WIN-1] VM sandbox isolation is Linux-only on this build')
        self._prepare_mainnet_config()
        _guard = config._mainnet_guard_failures(self.config, allow_new_genesis=bool(getattr(self, '_allow_new_genesis', False)))
        if _guard:
            for f in _guard:
                bootstrap.logger.error(f'[CONFIG-GUARD] {f}')
            bootstrap.sys.exit(1)
        config._validator_boot_mode()
        await self.db.initialize()
        await self.db.create_tables()
        await self._normalize_wallet_case()
        await self._load_state()
        await self._restore_from_latest_snapshot()
        await self._verify_chain_integrity()
        genesis_data = genesis.load_genesis_file()
        if not genesis_data:
            block0 = await self.block_repo.get_by_id(0)
            if block0:
                bootstrap.logger.error('[GENESIS] genesis.json missing but block 0 exists in DB — refusing to fabricate an unverifiable replacement (alloc map and consensus record are not recoverable from chain state). Copy genesis.json from the seed node or a running peer, then restart.')
                bootstrap.sys.exit(1)
            else:
                bootstrap.logger.warning(f'[GENESIS] No {config.GENESIS_FILE} found. Will attempt P2P discovery or create new genesis.')
        if genesis_data:
            _vok, _vwhy = genesis.genesis_export_verified(genesis_data)
            if not _vok:
                bootstrap.logger.error(f'[GENESIS] Local {config.GENESIS_FILE} failed verification: {_vwhy}; refusing to start. If this names a consensus key, your config.yaml differs from the node that created this genesis: consensus.*, vm.*, fees.*, p2p.ban_duration and consensus.validators must be IDENTICAL on every node.')
                bootstrap.sys.exit(1)
        if genesis_data:
            _cok, _cwhy = config.check_consensus_params(self.config, genesis_data)
            if not _cok:
                bootstrap.logger.error(f'[CONFIG] Consensus parameters disagree with genesis record: {_cwhy}; refusing to start')
                bootstrap.sys.exit(1)
            if _cwhy != 'ok':
                bootstrap.logger.warning(f'[CONFIG] Genesis consensus record absent ({_cwhy}); running on effective config')
        await self._bind_genesis_to_db()
        try:
            rows = await self.db.fetch('SELECT block_id,minerid,update_json FROM pending_maze_updates WHERE block_id > ?', self.height - 1)
            if rows:
                self.consensus._pending_maze_updates = [bootstrap.json.loads(r['update_json']) for r in rows]
                bootstrap.logger.info(f'[Recovery] Loaded {len(rows)} pending maze updates from DB')
        except Exception:
            pass
        self.vm_manager = vm_host.VMManager(self.db, self.contract_v2_repo, self.contract_storage_v2_repo, self.token_balance_repo, self.balance_repo, self.htlc_repo)
        self.vm_manager.node = self
        self.mempool.attach_db(self.db)
        await self._mempool_restore()
        self._ws_task = bootstrap.asyncio.create_task(self._run_websocket())
        await bootstrap.asyncio.sleep(0.5)
        self.p2p = P2P.P2PNode(self, self.db)
        await self.p2p.start()
        self.consensus = consensus.PoSWConsensus(self)
        await self.mempool.start_cleanup()
        await self.rate_limiter.start_cleanup()
        await self.subnet_rate_limiter.start_cleanup()
        await self.register_rate_limiter.start_cleanup()
        await self.rpc_rate_limiter.start_cleanup()
        _chain_ready = await self.ensure_genesis()
        if getattr(self, 'genesis_hash', None) and config._expected_genesis_pin(self.config) is None:
            self.config.setdefault('p2p', {})['expected_genesis_hash'] = str(self.genesis_hash)
            self._persist_config({('p2p', 'expected_genesis_hash'): str(self.genesis_hash)})
            bootstrap.logger.warning(f'[CONFIG] pinned genesis hash {str(self.genesis_hash)[:16]}... (joiners must set p2p.expected_genesis_hash to this value)')
        self._producing_enabled = bool(_chain_ready)
        if not _chain_ready:
            bootstrap.logger.warning('[Genesis] Block production paused until chain sync establishes state.')
        self._production_task = bootstrap.asyncio.create_task(self.consensus.production_loop())
        self._node_cleanup_task = bootstrap.asyncio.create_task(self._cleanup_loop())
        self._automation_task = bootstrap.asyncio.create_task(self._automation_loop())
        if self.config.get('node', {}).get('embedded_miner'):
            bootstrap.logger.warning('[EMBEDDED MINER] embedded_miner was removed in v10 (nodes cannot be miners) — config value ignored; run an external miner instead')
        shutdown_event = bootstrap.asyncio.Event()

        def signal_handler():
            bootstrap.asyncio.create_task(self.shutdown())
            shutdown_event.set()
        loop = bootstrap.asyncio.get_running_loop()
        if bootstrap.sys.platform != 'win32':
            loop.add_signal_handler(bootstrap.signal.SIGINT, signal_handler)
            loop.add_signal_handler(bootstrap.signal.SIGTERM, signal_handler)
        await shutdown_event.wait()
        if hasattr(self, '_ws_task'):
            self._ws_task.cancel()
            try:
                await self._ws_task
            except bootstrap.asyncio.CancelledError:
                pass
