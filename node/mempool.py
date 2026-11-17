import bootstrap
import config
import crypto
import util
import gas

class Mempool:

    def __init__(self, max_size: int=config.MEMPOOL_MAX_SIZE):
        self.max_size = max_size
        self._lock = bootstrap.asyncio.Lock()
        self._transactions: bootstrap.Dict[str, bootstrap.Dict] = {}
        self._expiry = config.MEMPOOL_EXPIRY
        self._cleanup_task = None
        self._pending_nonces: bootstrap.Dict[str, int] = {}
        self._confirmed_nonces: bootstrap.Dict[str, int] = {}
        self._nonce_lock = bootstrap.asyncio.Lock()
        self.db = None

    def attach_db(self, db):
        self.db = db

    async def _persist(self, tx: bootstrap.Dict):
        if self.db is None:
            return
        try:
            tx_hash = tx.get('tx_hash')
            if not tx_hash:
                return
            payload = bootstrap.json.dumps(tx, separators=(',', ':'))
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('INSERT OR REPLACE INTO mempool_persist (tx_hash, tx_json, stored_at) VALUES (?,?,?)', tx_hash, payload, bootstrap.time.time())
            else:
                await self.db.execute_dml('INSERT INTO mempool_persist (tx_hash, tx_json, stored_at) VALUES ($1,$2,$3) ON CONFLICT (tx_hash) DO UPDATE SET tx_json=$2, stored_at=$3', tx_hash, payload, bootstrap.time.time())
        except Exception as e:
            bootstrap.logger.debug(f'[Mempool] persist failed for {str(tx.get('tx_hash'))[:16]}: {e}')

    async def _unpersist(self, tx_hash: str):
        if self.db is None or not tx_hash:
            return
        try:
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('DELETE FROM mempool_persist WHERE tx_hash = ?', tx_hash)
            else:
                await self.db.execute_dml('DELETE FROM mempool_persist WHERE tx_hash = $1', tx_hash)
        except Exception as e:
            bootstrap.logger.debug(f'[Mempool] unpersist failed for {str(tx_hash)[:16]}: {e}')

    async def start_cleanup(self):

        async def cleanup_loop():
            while True:
                await bootstrap.asyncio.sleep(60)
                async with self._lock:
                    await self._cleanup()
        self._cleanup_task = bootstrap.asyncio.create_task(cleanup_loop())

    async def add(self, tx: bootstrap.Dict) -> bool:
        async with self._lock:
            tx_hash = tx.get('tx_hash')
            if not tx_hash or not isinstance(tx_hash, str):
                return False
            clean_hash = tx_hash.removeprefix('0x').lower()
            if len(clean_hash) != 64 or not all((c in '0123456789abcdef' for c in clean_hash)):
                return False
            sig = tx.get('signature', '')
            is_valid_hash = False
            if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
                try:
                    decoded = util.decode_raw_eth_transaction(sig)
                    if decoded.get('hash', '').lower() == tx_hash.lower() or decoded.get('hash', '').removeprefix('0x').lower() == clean_hash:
                        is_valid_hash = True
                except Exception:
                    pass
            if not is_valid_hash:
                tx_body = {k: v for k, v in tx.items() if k != 'tx_hash'}
                if crypto.hash_tx(tx_body) == tx_hash or crypto.hash_tx(tx) == tx_hash or crypto.hash_tx(tx_body) == clean_hash or (crypto.hash_tx(tx) == clean_hash):
                    is_valid_hash = True
            if not is_valid_hash:
                return False
            if tx_hash in self._transactions:
                return False
            replacement = next((h for h, old in self._transactions.items() if old.get('from_wallet') == tx.get('from_wallet') and old.get('nonce') == tx.get('nonce')), None)
            if replacement:
                old_fee = self._transactions[replacement].get('fee', 0)
                if tx.get('fee', 0) <= old_fee * config.RBF_INCREMENT:
                    return False
            if str(tx.get('tx_type', 'send')) == 'token_transfer' and int(tx.get('fee', 0) or 0) != int(gas.token_transfer_fee(tx)):
                return False
            if str(tx.get('tx_type', 'send')) == 'token_burn' and int(tx.get('fee', 0) or 0) != int(gas.token_burn_fee(tx)):
                return False
            _tt = tx.get('tx_type', 'send')
            if _tt == 'token_create':
                try:
                    _fl = gas.get_token_creation_fee(0)
                    _fv = int(tx.get('fee', 0) or 0)
                except (TypeError, ValueError):
                    return False
                if _fv < _fl:
                    return False
            val = int(tx.get('value', 0))
            fee = int(tx.get('fee', 0))
            if val < 0 or fee < 0:
                return False
            wallet = tx.get('from_wallet', '')
            tx_nonce = int(tx.get('nonce', 0)) if wallet else 0
            if wallet:
                await self._seed_confirmed_nonce(wallet)
                _confirmed = self._confirmed_nonces.get(wallet, 0)
                if tx_nonce < 0 or tx_nonce < _confirmed:
                    return False
                if tx_nonce > _confirmed + config.MEMPOOL_MAX_NONCE_GAP:
                    return False
            if len(self._transactions) >= self.max_size:
                await self._cleanup()
            if len(self._transactions) >= self.max_size:
                new_fee = int(tx.get('fee', 0))
                new_size = gas._tx_size(tx)
                new_fpb = new_fee / max(new_size, 1)
                worst_hash = None
                worst_fpb = float('inf')
                for h, old in self._transactions.items():
                    old_fpb = int(old.get('fee', 0)) / max(gas._tx_size(old), 1)
                    if old_fpb < worst_fpb:
                        worst_fpb = old_fpb
                        worst_hash = h
                if new_fpb <= worst_fpb:
                    return False
                if worst_hash:
                    evicted = self._transactions.pop(worst_hash)
                    await self._unpersist(worst_hash)
                    bootstrap.logger.debug(f'[Mempool] Evicted lowest-fee tx {worst_hash[:16]} (fpb={worst_fpb:.4f}) for higher-fee tx {tx_hash[:16]} (fpb={new_fpb:.4f})')
            if replacement:
                del self._transactions[replacement]
                await self._unpersist(replacement)
            self._transactions[tx_hash] = tx
            if wallet:
                current = self._pending_nonces.get(wallet, 0)
                confirmed = self._confirmed_nonces.get(wallet, 0)
                self._pending_nonces[wallet] = max(current, min(tx_nonce + 1, confirmed + config.MEMPOOL_MAX_NONCE_GAP))
            await self._persist(tx)
            return True

    async def remove(self, tx_hash: str) -> bool:
        async with self._lock:
            if tx_hash not in self._transactions:
                return False
            removed = self._transactions.pop(tx_hash)
            await self._unpersist(tx_hash)
            wallet = removed.get('from_wallet', '')
            if wallet:
                wallet_txs = [tx for tx in self._transactions.values() if tx.get('from_wallet') == wallet]
                if wallet_txs:
                    self._pending_nonces[wallet] = max((int(tx.get('nonce', 0)) for tx in wallet_txs)) + 1
                else:
                    self._pending_nonces.pop(wallet, None)
            return True

    async def get(self, limit: int=100) -> bootstrap.List[bootstrap.Dict]:
        async with self._lock:
            await self._cleanup()
            sorted_txs = sorted(self._transactions.values(), key=lambda t: (-t.get('fee', 0), t.get('nonce', 0)))
            return sorted_txs[:limit]

    async def _cleanup(self):
        now = bootstrap.time.time()
        to_remove = [h for h, tx in self._transactions.items() if now - tx.get('timestamp', 0) > self._expiry]
        for h in to_remove:
            removed = self._transactions.pop(h)
            await self._unpersist(h)
            wallet = removed.get('from_wallet', '')
            if wallet:
                wallet_txs = [tx for tx in self._transactions.values() if tx.get('from_wallet') == wallet]
                if wallet_txs:
                    self._pending_nonces[wallet] = max((int(tx.get('nonce', 0)) for tx in wallet_txs)) + 1
                else:
                    self._pending_nonces.pop(wallet, None)
        if to_remove:
            bootstrap.logger.debug(f'[Mempool] Removed {len(to_remove)} expired transactions')

    def size(self) -> int:
        return len(self._transactions)

    async def drain(self, timeout: float=30.0) -> bool:
        deadline = bootstrap.time.time() + timeout
        while bootstrap.time.time() < deadline:
            if not self._transactions:
                return True
            await bootstrap.asyncio.sleep(0.5)
        bootstrap.logger.warning(f'[Mempool] Drain timeout: {len(self._transactions)} txs still pending')
        return False

    def get_nonce(self, wallet: str) -> int:
        return self._pending_nonces.get(wallet, 0)

    def note_confirmed_nonce(self, wallet: str, nonce: int):
        try:
            nonce = int(nonce)
        except (TypeError, ValueError):
            return
        if wallet:
            self._confirmed_nonces[wallet] = max(self._confirmed_nonces.get(wallet, 0), nonce)

    def forget_confirmed(self, wallet: str=None):
        if wallet is None:
            self._confirmed_nonces.clear()
        else:
            self._confirmed_nonces.pop(wallet, None)

    async def _seed_confirmed_nonce(self, wallet: str):
        if not wallet or wallet in self._confirmed_nonces:
            return
        if self.db is None:
            return
        try:
            if self.db.db_type == 'sqlite':
                _q = 'SELECT COALESCE(MAX(nonce),-1)+1 FROM transactions WHERE from_wallet = ? AND block_id >= 0'
            else:
                _q = 'SELECT COALESCE(MAX(nonce),-1)+1 FROM transactions WHERE from_wallet = $1 AND block_id >= 0'
            _seed = await self.db.fetchval(_q, wallet)
            if _seed is not None:
                self._confirmed_nonces[wallet] = max(int(_seed), 0)
        except Exception:
            pass
        try:
            if self.db.db_type == 'sqlite':
                _aq = 'SELECT next_nonce FROM account_nonces WHERE wallet = ?'
            else:
                _aq = 'SELECT next_nonce FROM account_nonces WHERE wallet = $1'
            _an = await self.db.fetchval(_aq, wallet)
            if _an is not None:
                self._confirmed_nonces[wallet] = max(self._confirmed_nonces.get(wallet, 0), int(_an))
        except Exception:
            pass

class MemoryChallengeManager:

    def __init__(self):
        self._pending_challenges: bootstrap.Dict[str, bootstrap.Tuple[str, int, float]] = {}

    def generate_challenge(self, miner_id: str, memory_size: int=8 * 1024 * 1024) -> dict:
        seed = bootstrap.secrets.token_bytes(32)
        seed_b64 = bootstrap.base64.b64encode(seed).decode()
        self._pending_challenges[miner_id] = (seed_b64, memory_size, bootstrap.time.time())
        return {'type': 'memory_challenge_request', 'seed': seed_b64, 'memory_size': memory_size, 'timestamp': int(bootstrap.time.time())}

    @staticmethod
    def _fill_and_hash(seed: bytes, memory_size: int) -> bytes:
        h = bootstrap.hashlib.sha256()
        counter = 0
        produced = 0
        chunk_size = 32
        while produced < memory_size:
            block = bootstrap.hashlib.sha256(seed + counter.to_bytes(8, 'big')).digest()
            h.update(block)
            produced += chunk_size
            counter += 1
        return h.digest()

    def verify_commitment(self, miner_id: str, seed_b64: str, commitment_b64: str) -> bool:
        if miner_id not in self._pending_challenges:
            return False
        stored_seed, mem_size, created = self._pending_challenges[miner_id]
        del self._pending_challenges[miner_id]
        if stored_seed != seed_b64 or bootstrap.time.time() - created > 60:
            return False
        try:
            commitment = bootstrap.base64.b64decode(commitment_b64)
            seed_bytes = bootstrap.base64.b64decode(seed_b64)
        except Exception:
            return False
        if len(commitment) != 32:
            return False
        expected = self._fill_and_hash(seed_bytes, mem_size)
        return bootstrap.hmac.compare_digest(commitment, expected)

class RateLimiter:

    def __init__(self, max_requests: int=60, window_seconds: int=60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: bootstrap.Dict[str, bootstrap.deque] = {}
        self._lock = bootstrap.asyncio.Lock()
        self._cleanup_task = None

    async def start_cleanup(self):

        async def cleanup_loop():
            while True:
                await bootstrap.asyncio.sleep(60)
                await self._cleanup()
        self._cleanup_task = bootstrap.asyncio.create_task(cleanup_loop())

    async def _cleanup(self):
        async with self._lock:
            now = bootstrap.time.time()
            for ip in list(self._requests.keys()):
                while self._requests[ip] and now - self._requests[ip][0] > self.window:
                    self._requests[ip].popleft()
                if not self._requests[ip]:
                    del self._requests[ip]

    async def is_allowed(self, client_ip: str) -> bool:
        async with self._lock:
            now = bootstrap.time.time()
            if client_ip not in self._requests:
                self._requests[client_ip] = bootstrap.deque()
            while self._requests[client_ip] and now - self._requests[client_ip][0] > self.window:
                self._requests[client_ip].popleft()
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True

class HealthChecker:

    def __init__(self):
        self.start_time = bootstrap.time.time()
        self.last_block_time = bootstrap.time.time()
        self.blocks_produced = 0
        self.peer_count = 0
        self.miner_count = 0
        self.errors = 0
        self.status = 'starting'
        self._block_history = bootstrap.deque(maxlen=100)

    def get_status(self) -> dict:
        uptime = int(bootstrap.time.time() - self.start_time)
        block_rate = len(self._block_history) / max(uptime / 3600, 0.1)
        return {'status': self.status, 'uptime': uptime, 'uptime_hours': uptime / 3600, 'blocks_produced': self.blocks_produced, 'block_rate_per_hour': block_rate, 'peers': self.peer_count, 'miners': self.miner_count, 'errors': self.errors, 'error_rate': self.errors / max(uptime / 3600, 0.1), 'last_block': int(self.last_block_time), 'last_block_age': int(bootstrap.time.time() - self.last_block_time), 'version': config.VERSION, 'healthy': self.errors < 10 and bootstrap.time.time() - self.last_block_time < config.BLOCK_TIME * 6}

    def record_block(self, block_id: int):
        self.blocks_produced += 1
        self.last_block_time = bootstrap.time.time()
        self._block_history.append((block_id, bootstrap.time.time()))

    def record_error(self, error: str):
        self.errors += 1
        if self.errors > 100:
            self.status = 'degraded'
