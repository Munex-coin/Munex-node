import bootstrap
import config
import crypto
import util
import maze
import svf
VERIFY_STATE_ROOT = True
STATE_COMMITMENT_SCOPE = 'two-key'

async def _block_gas_used(db, block_id: int) -> int:
    try:
        if db.db_type == 'sqlite':
            _row = await db.fetchrow('SELECT COALESCE(SUM(gas_used),0) AS s FROM transaction_receipts WHERE block_id = ?', block_id)
        else:
            _row = await db.fetchrow('SELECT COALESCE(SUM(gas_used),0) AS s FROM transaction_receipts WHERE block_id = $1', block_id)
        return int((_row['s'] if _row else 0) or 0)
    except Exception:
        return 0

class _TrieNode:
    __slots__ = ('node_type', 'encoded', 'hash')

    def __init__(self, node_type, encoded, hash_val):
        self.node_type = node_type
        self.encoded = encoded
        self.hash = hash_val

class StateTrie:

    def __init__(self, db):
        self.db = db
        self._dirty: bootstrap.Dict[str, bytes] = {}
        self._node_cache: bootstrap.Dict[bytes, bytes] = {}

    async def get(self, key: str):
        if key in self._dirty:
            return bootstrap.json.loads(self._dirty[key])
        query = 'SELECT node_data FROM state_trie_nodes WHERE node_hash = ?' if self.db.db_type == 'sqlite' else 'SELECT node_data FROM state_trie_nodes WHERE node_hash = $1'
        row = await self.db.fetchrow(query, key)
        if not row:
            return None
        try:
            return bootstrap.json.loads(row['node_data'])
        except Exception:
            return None

    async def put(self, key: str, value: bootstrap.Any):
        self._dirty[str(key)] = bootstrap.json.dumps(value, sort_keys=True, separators=(',', ':'))

    def _compute_root(self) -> str:
        if not self._dirty:
            return maze.STATE_TREE_EMPTY_HASH
        pairs: bootstrap.List[bootstrap.Tuple[bytes, bytes]] = []
        for key in sorted(self._dirty):
            key_bytes = key.encode()
            value_bytes = self._dirty[key].encode() if isinstance(self._dirty[key], str) else self._dirty[key]
            leaf_rlp = util._rlp_encode_list([util._rlp_encode_bytes(key_bytes), util._rlp_encode_bytes(value_bytes)])
            pairs.append((crypto._keccak(leaf_rlp), leaf_rlp))
        pairs.sort(key=lambda p: p[0])
        level: bootstrap.List[bytes] = [lh for lh, _ in pairs]
        records: bootstrap.List[bootstrap.Tuple[str, str]] = []
        for lh, lr in pairs:
            records.append(('0x' + lh.hex(), bootstrap.json.dumps({'kind': 'leaf', 'rlp': lr.hex()}, sort_keys=True)))
        while len(level) > 1:
            carry = level.pop() if len(level) % 2 == 1 else None
            nxt: bootstrap.List[bytes] = []
            for i in range(0, len(level), 2):
                parent = crypto._keccak(level[i] + level[i + 1])
                nxt.append(parent)
                records.append(('0x' + parent.hex(), bootstrap.json.dumps({'kind': 'internal', 'left': '0x' + level[i].hex(), 'right': '0x' + level[i + 1].hex()}, sort_keys=True, separators=(',', ':'))))
            if carry is not None:
                nxt.append(carry)
            level = nxt
        return ('0x' + level[0].hex(), records)

    async def commit(self) -> str:
        if not self._dirty:
            return maze.STATE_TREE_EMPTY_HASH
        root_hash, records = self._compute_root()
        _leaf_q = 'INSERT OR REPLACE INTO state_trie_nodes (node_hash,node_data,ref_count) VALUES (?,?,1)' if self.db.db_type == 'sqlite' else 'INSERT INTO state_trie_nodes (node_hash,node_data,ref_count) VALUES ($1,$2,1) ON CONFLICT (node_hash) DO UPDATE SET node_data=$2, ref_count=state_trie_nodes.ref_count+1'
        async with await self.db.transaction():
            for _h, _d in records:
                await self.db.execute_dml(_leaf_q, _h, _d)
            return root_hash

    def mark_committed(self):
        self._dirty.clear()

def _canonical_value(v) -> str:
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return f'{v:.8f}'
    if isinstance(v, str):
        return bootstrap.json.dumps(v, sort_keys=True, separators=(',', ':'))
    if isinstance(v, (dict, list, tuple)):
        return bootstrap.json.dumps(v, sort_keys=True, separators=(',', ':'))
    return bootstrap.json.dumps(str(v), sort_keys=True, separators=(',', ':'))

def _state_root_from_snapshot(snapshot: dict) -> str:
    _t = StateTrie(None)
    _t._dirty = {k: _canonical_value(v) for k, v in snapshot.items()}
    return _t._compute_root()[0]

async def _state_snapshot_for_block(db, node, block_id: int) -> dict:
    snap: dict = {}
    snap[f'height:{block_id}'] = block_id
    ph = '?' if db.db_type == 'sqlite' else '$1'
    try:
        rows = await db.fetch('SELECT wallet, bal FROM balances')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'bal:{r['wallet']}'] = int(r['bal'] or 0)
    try:
        rows = await db.fetch('SELECT token_address, wallet, balance FROM token_balances')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'tok:{r['token_address']}:{r['wallet']}'] = int(r['balance'] or 0)
    try:
        rows = await db.fetch('SELECT contract_address, key, value FROM contract_state')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'cst:{r['contract_address']}:{r['key']}'] = r['value']
    try:
        rows = await db.fetch('SELECT contract_address, key, value FROM contract_storage_v2')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'cst2:{r['contract_address']}:{r['key']}'] = r['value']
    try:
        rows = await db.fetch('SELECT id, sender, receiver, hashlock, timelock, amount, token_address, status FROM htlc_contracts')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'htlc:{r['id']}'] = {'sender': r['sender'], 'receiver': r['receiver'], 'hashlock': r['hashlock'], 'timelock': int(r['timelock'] or 0), 'amount': int(r['amount'] or 0), 'token_address': r['token_address'] or '', 'status': r['status'] or ''}
    try:
        rows = await db.fetch('SELECT m.maze_id, m.minerid, m.walldensityppm, m.seed, m.goalx, m.goaly, m.goalz FROM minermazes m JOIN maze_attestations a ON m.maze_id = a.maze_id')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'maze:{r['maze_id']}'] = {k: int(v) if isinstance(v, (int, float)) and (not isinstance(v, bool)) else v for k, v in dict(r).items()}
    try:
        rows = await db.fetch('SELECT address, name, symbol, owner, total_supply, decimals, mintable, burnable, mining_type, mining_reward, mining_interval, mining_difficulty, stake_threshold, last_mined_block, total_mined, max_mineable_supply FROM tokens')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'toki:{r['address']}'] = {k: int(v) if isinstance(v, (int, float)) and (not isinstance(v, bool)) else v for k, v in dict(r).items() if k != 'address'}
    try:
        rows = await db.fetch('SELECT address, owner, code_hash FROM contract_v2')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'conv:{r['address']}'] = {'owner': r['owner'] or '', 'code_hash': r['code_hash'] or ''}
    try:
        rows = await db.fetch('SELECT maze_id, last_size, last_block, last_block_hash, pubkey FROM maze_attestations')
    except Exception as _e:
        raise RuntimeError(f'[state root] DB read failed: {_e}')
    for r in rows or []:
        snap[f'mazeatt:{r['maze_id']}'] = {'last_size': int(r['last_size'] or 0), 'last_block': int(r['last_block'] or 0), 'last_block_hash': r['last_block_hash'] or '', 'pubkey': r['pubkey'] or ''}
    if svf.svf_active_at(block_id):
        svf_profiles = getattr(node, 'svf_profiles', {}) or {}
        for tok, prof in sorted(svf_profiles.items()):
            try:
                _pb = svf.svf_profile_bytes(prof)
                _ph = svf.svf_profile_hash(int(config.CHAIN_ID), tok, _pb)
                snap[f'svfreg:{tok}'] = {'profile_hash': _ph.hex(), 'sample_blocks': prof.get('sample_blocks', 0), 'min_distinct_winners': prof.get('min_distinct_winners', 0), 'min_growth_blocks': prof.get('min_growth_blocks', 0), 'min_total_attestation_weight': str(prof.get('min_total_attestation_weight', 0))}
            except svf.SVFReject:
                snap[f'svfreg:{tok}'] = {'error': 'invalid_profile'}
        svf_epoch_roots = getattr(node, 'svf_epoch_roots', {}) or {}
        for epoch_id in sorted(svf_epoch_roots.keys()):
            entry = svf_epoch_roots[epoch_id]
            if isinstance(entry, (tuple, list)) and len(entry) >= 2:
                snap[f'svfepoch:{epoch_id}'] = {'root': entry[0].hex() if isinstance(entry[0], bytes) else str(entry[0]), 'count': int(entry[1])}
        svf_certs = getattr(node, 'svf_certificates', {}) or {}
        for epoch_id in sorted(svf_certs.keys()):
            cert = svf_certs[epoch_id]
            snap[f'svfcert:{epoch_id}'] = {'evidence_epoch': int(cert.get('evidence_epoch', epoch_id)), 'anchor_block_hash': cert.get('anchor_block_hash', ''), 'evidence_root': cert.get('evidence_root', ''), 'inclusion_block': int(cert.get('inclusion_block', 0)), 'usable_from': int(cert.get('usable_from', 0))}
    return snap

async def _compute_full_state_root(db, node, block_id: int) -> str:
    snap = await _state_snapshot_for_block(db, node, block_id)
    return _state_root_from_snapshot(snap)

async def _state_root_with_credit(db, node, block_id: int, credit_wallet: str, credit_amount: int) -> str:
    snap = await _state_snapshot_for_block(db, node, block_id)
    if credit_wallet and credit_amount > 0:
        snap[f'bal:{credit_wallet}'] = int(snap.get(f'bal:{credit_wallet}', 0) or 0) + int(credit_amount)
    return _state_root_from_snapshot(snap)
_pg_conn_context: bootstrap.ContextVar[bootstrap.Optional[bootstrap.Any]] = bootstrap.ContextVar('_pg_conn_context', default=None)
_sqlite_in_tx: bootstrap.ContextVar[bool] = bootstrap.ContextVar('_sqlite_in_tx', default=False)

class Database:

    def __init__(self, db_url=None, require_postgres=None):
        self.db_type = None
        self.conn = None
        self.cursor = None
        self._pool = None
        self._initialized = False
        self._pg_dsn = None
        self._pg_target_dsn = None
        self._sqlite_lock = bootstrap.asyncio.Lock()
        self.require_postgres = require_postgres if require_postgres is not None else config.CONFIG.get('database', {}).get('require_postgres', False)
        if db_url is not None and (not isinstance(db_url, str)):
            db_url = str(db_url)
        if isinstance(db_url, str):
            db_url = db_url.strip()
            if db_url.lower() in ('', 'null', 'none', '~'):
                db_url = None
        if not db_url:
            if not getattr(self, 'require_postgres', False):
                db_url = 'sqlite://microcore.db'
                bootstrap.logger.info('[DB] database.url is null/empty; using SQLite (require_postgres=false)')
        self._db_url = db_url
        if db_url:
            if db_url.startswith('sqlite://'):
                if getattr(self, 'require_postgres', False):
                    bootstrap.logger.error('[DB] Explicit SQLite URL conflicts with database.require_postgres: true. Exiting.')
                    bootstrap.sys.exit(1)
                self.db_type = 'sqlite'
                path = db_url[9:] if db_url.startswith('sqlite://') else db_url
                self.conn = bootstrap.sqlite3.connect(path, check_same_thread=False, timeout=30)
                self.conn.row_factory = bootstrap.sqlite3.Row
                self.conn.execute('PRAGMA journal_mode=WAL')
                self.conn.execute('PRAGMA synchronous=NORMAL')
                self.cursor = self.conn.cursor()
                self._initialized = True
                bootstrap.logger.info(f'[DB] SQLite forced (WAL): {path}')
                return
            if db_url and db_url.startswith('postgresql://') and (bootstrap.psycopg2 is None):
                if getattr(self, 'require_postgres', False):
                    bootstrap.logger.error('[DB] PostgreSQL required but not available. Exiting.')
                    bootstrap.sys.exit(1)
                bootstrap.logger.warning('[DB] psycopg2 unavailable — falling back to SQLite.')
                self._fallback_sqlite()
                return
            elif db_url.startswith('postgresql://'):
                self.db_type = 'postgres'
                self._pg_target_dsn = db_url
                parsed = bootstrap.urlparse(db_url)
                default_db = parsed._replace(path='/postgres').geturl()
                self._pg_dsn = default_db
                bootstrap.logger.info('[DB] PostgreSQL DSN provided.')
                return
        self._auto_detect_and_connect()

    def _auto_detect_and_connect(self):
        if bootstrap.psycopg2 is None:
            if getattr(self, 'require_postgres', False):
                bootstrap.logger.error('[DB] PostgreSQL required but not available. Exiting.')
                bootstrap.sys.exit(1)
            bootstrap.logger.warning('[DB] psycopg2 not installed — falling back to SQLite. Install with: pip install psycopg2-binary')
            self._fallback_sqlite()
            return
        pg_user = bootstrap.os.environ.get('MCX_PG_USER', 'postgres')
        pg_password = bootstrap.os.environ.get('MCX_PG_PASSWORD', 'postgres')
        pg_host = bootstrap.os.environ.get('MCX_PG_HOST', 'localhost')
        pg_port = bootstrap.os.environ.get('MCX_PG_PORT', '5432')
        if pg_user == 'postgres' and pg_password == 'postgres':
            bootstrap.logger.warning('[SECURITY] Using default PostgreSQL credentials (postgres:postgres). Set MCX_PG_USER and MCX_PG_PASSWORD environment variables for production.')
        self._pg_user = pg_user
        self._pg_password = pg_password
        self._pg_host = pg_host
        self._pg_port = pg_port
        self._pg_dsn = f'postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/postgres'
        self._pg_target_dsn = f'postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/mcx'
        try:
            conn = bootstrap.psycopg2.connect(self._pg_dsn)
            conn.close()
            self.db_type = 'postgres'
            bootstrap.logger.info('[DB] PostgreSQL detected.')
        except (bootstrap.psycopg2.OperationalError, bootstrap.psycopg2.InterfaceError) as e:
            bootstrap.logger.warning(f'[DB] PostgreSQL not reachable ({util._redact_dsn(str(e))})')
            if getattr(self, 'require_postgres', False):
                bootstrap.logger.error('[DB] PostgreSQL required but not available. Exiting.')
                bootstrap.sys.exit(1)
            bootstrap.logger.warning('[DB] Falling back to SQLite (Postgres not reachable). Set database.require_postgres: true to make this fatal.')
            self._fallback_sqlite()

    def _fallback_sqlite(self):
        bootstrap.logger.info('[DB] Falling back to SQLite.')
        self.db_type = 'sqlite'
        path = bootstrap.os.path.join(bootstrap.os.getcwd(), 'microcore.db')
        self.conn = bootstrap.sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = bootstrap.sqlite3.Row
        self.conn.execute('PRAGMA journal_mode=WAL')
        self.conn.execute('PRAGMA synchronous=NORMAL')
        self.cursor = self.conn.cursor()
        self._initialized = True
        bootstrap.logger.info(f'[DB] SQLite connected (WAL): {path}')

    async def initialize(self):
        if self.db_type == 'postgres':
            try:
                self._pool = await bootstrap.asyncpg.create_pool(self._pg_target_dsn, min_size=2, max_size=10)
                self._initialized = True
                bootstrap.logger.info('[DB] PostgreSQL connected successfully.')
                await self._apply_postgres_migrations()
                return
            except bootstrap.asyncpg.exceptions.InvalidCatalogNameError:
                bootstrap.logger.warning("[DB] Database 'mcx' does not exist. Creating...")
                conn = await bootstrap.asyncpg.connect(self._pg_dsn)
                await conn.execute('CREATE DATABASE mcx;')
                await conn.close()
                self._pool = await bootstrap.asyncpg.create_pool(self._pg_target_dsn)
                self._initialized = True
                bootstrap.logger.info('[DB] PostgreSQL created and connected.')
                await self._apply_postgres_migrations()
                return
            except Exception as e:
                bootstrap.logger.error(f'[DB] PostgreSQL connection failed: {util._redact_dsn(str(e))}')
                if getattr(self, 'require_postgres', False):
                    bootstrap.logger.error('[DB] PostgreSQL required but not available. Exiting.')
                    bootstrap.sys.exit(1)
                self._fallback_sqlite()
        else:
            self._initialized = True

    async def _apply_postgres_migrations(self):
        try:
            async with self._pool.acquire() as conn:
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS maze_id TEXT')
                await conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_minermazes_maze_id ON minermazes(maze_id) WHERE maze_id IS NOT NULL')
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS knowledge INTEGER NOT NULL DEFAULT 0')
                await conn.execute('ALTER TABLE miners ADD COLUMN IF NOT EXISTS block_signing_pub TEXT')
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS lastknowledgeheight BIGINT NOT NULL DEFAULT 0')
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghostx INTEGER')
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghosty INTEGER')
                await conn.execute('ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghostz INTEGER')
                await conn.execute('ALTER TABLE blocks ALTER COLUMN coverage TYPE DOUBLE PRECISION USING coverage::DOUBLE PRECISION')
        except Exception as e:
            bootstrap.logger.warning(f'[DB] Postgres migration (minermazes.maze_id) skipped: {e}')

    async def close(self):
        if self.db_type == 'postgres' and self._pool:
            await self._pool.close()
        elif self.db_type == 'sqlite' and self.conn:
            self.conn.close()
        bootstrap.logger.debug('[DB] Closed')

    async def execute(self, query, *args):
        if self.db_type == 'postgres':
            if '?' in query:
                query = util._pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.fetch(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.fetch(query, *args)
        else:
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                return self.cursor.fetchall()

    async def execute_dml(self, query, *args):
        if self.db_type == 'postgres':
            if '?' in query:
                query = util._pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.execute(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.execute(query, *args)
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                return str(self.cursor.rowcount)
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                self.conn.commit()
                return str(self.cursor.rowcount)

    async def fetch(self, query, *args):
        if self.db_type == 'postgres':
            if '?' in query:
                query = util._pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                return [dict(r) for r in self.cursor.fetchall()]
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                return [dict(r) for r in self.cursor.fetchall()]

    async def fetchrow(self, query, *args):
        if self.db_type == 'postgres':
            if '?' in query:
                query = util._pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return dict(row) if row else None
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return dict(row) if row else None

    async def fetchval(self, query, *args):
        if self.db_type == 'postgres':
            if '?' in query:
                query = util._pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.fetchval(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.fetchval(query, *args)
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return row[0] if row else None
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return row[0] if row else None

    async def commit(self):
        if self.db_type != 'postgres':
            if _sqlite_in_tx.get():
                self.conn.commit()
            else:
                async with self._sqlite_lock:
                    self.conn.commit()

    async def rollback(self):
        if self.db_type != 'postgres':
            if _sqlite_in_tx.get():
                self.conn.rollback()
            else:
                async with self._sqlite_lock:
                    self.conn.rollback()

    class _sqlite_transaction:

        def __init__(self, db):
            self._db = db
            self._nested = False

        async def __aenter__(self):
            if self._db.db_type == 'sqlite':
                if not _sqlite_in_tx.get():
                    await self._db._sqlite_lock.acquire()
                    _sqlite_in_tx.set(True)
                    self._db.conn.execute('BEGIN IMMEDIATE')
                    self._nested = False
                else:
                    self._nested = True
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self._db.db_type == 'sqlite':
                if not self._nested:
                    try:
                        if exc_type:
                            self._db.conn.rollback()
                        else:
                            self._db.conn.commit()
                    finally:
                        _sqlite_in_tx.set(False)
                        self._db._sqlite_lock.release()
            return False

    class _pg_transaction:

        def __init__(self, db):
            self._db = db
            self._conn = None
            self._tx = None
            self._token = None
            self._nested = False

        async def __aenter__(self):
            current_conn = _pg_conn_context.get()
            if current_conn is not None:
                self._conn = current_conn
                self._nested = True
                self._tx = self._conn.transaction()
                await self._tx.start()
            else:
                self._conn = await self._db._pool.acquire()
                self._tx = self._conn.transaction()
                await self._tx.start()
                self._token = _pg_conn_context.set(self._conn)
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            try:
                if exc_type:
                    await self._tx.rollback()
                else:
                    await self._tx.commit()
            finally:
                if not self._nested:
                    if self._token is not None:
                        _pg_conn_context.reset(self._token)
                    await self._db._pool.release(self._conn)
            return False

    async def transaction(self):
        if getattr(self, 'db_type', 'sqlite') == 'postgres':
            return self._pg_transaction(self)
        return self._sqlite_transaction(self)

    async def create_tables(self):
        if self.db_type == 'postgres':
            async with self._pool.acquire() as conn:
                await conn.execute('\n                    CREATE TABLE IF NOT EXISTS miners (\n                        miner_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, pub TEXT NOT NULL,\n                        rewards BIGINT DEFAULT 0, blocks BIGINT DEFAULT 0, slashes INTEGER DEFAULT 0,\n                        uptime INTEGER DEFAULT 0, today_uptime INTEGER DEFAULT 0, type TEXT DEFAULT \'web\',\n                        liquidity BIGINT DEFAULT 0, fees BIGINT DEFAULT 0, last_ping DOUBLE PRECISION DEFAULT 0,\n                        banned_until DOUBLE PRECISION DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(),\n                        last_block BIGINT DEFAULT 0, consecutive_misses INTEGER DEFAULT 0, total_uptime INTEGER DEFAULT 0,\n                        ip_address TEXT DEFAULT \'\', node_id TEXT DEFAULT \'\', version TEXT DEFAULT \'\',\n                        active BOOLEAN DEFAULT TRUE, confirmed_balance BIGINT DEFAULT 0, password_hash TEXT DEFAULT \'\',\n                        private_key_encrypted TEXT DEFAULT \'\', gas_collected BIGINT DEFAULT 0, maze_wins INTEGER DEFAULT 0,\n                        block_signing_pub TEXT\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_miners_wallet ON miners(wallet);\n                    CREATE INDEX IF NOT EXISTS idx_miners_active ON miners(active);\n\n                    CREATE TABLE IF NOT EXISTS nodes (\n                        node_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, ip TEXT DEFAULT \'\', port INTEGER DEFAULT 0,\n                        last_seen TIMESTAMP DEFAULT NOW(), height BIGINT DEFAULT 0, active BOOLEAN DEFAULT TRUE,\n                        rewards_earned BIGINT DEFAULT 0, version TEXT DEFAULT \'\', mining_enabled BOOLEAN DEFAULT TRUE,\n                        staking_enabled BOOLEAN DEFAULT TRUE, last_sync TIMESTAMP DEFAULT NOW(),\n                        is_multisig_signer BOOLEAN DEFAULT FALSE, public_key TEXT DEFAULT \'\'\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);\n\n                    CREATE TABLE IF NOT EXISTS blocks (\n                        id BIGINT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, phash TEXT NOT NULL,\n                        miners TEXT[] DEFAULT \'{}\', hash TEXT NOT NULL, reward BIGINT DEFAULT 0,\n                        tx_count INTEGER DEFAULT 0, merkle_root TEXT DEFAULT \'\', nonce BIGINT DEFAULT 0,\n                        difficulty INTEGER DEFAULT 1, version TEXT DEFAULT \'\', challenge TEXT DEFAULT \'\',\n                        coverage REAL DEFAULT 1, total_tx_value BIGINT DEFAULT 0, total_fees BIGINT DEFAULT 0,\n                        tx_hashes TEXT[] DEFAULT \'{}\', finalized BOOLEAN DEFAULT FALSE\n                    );\n                    ALTER TABLE blocks ADD COLUMN IF NOT EXISTS proof JSONB DEFAULT \'{}\';\n                    CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(id);\n                    CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);\n                    CREATE INDEX IF NOT EXISTS idx_blocks_finalized ON blocks(finalized);\n\n                    CREATE TABLE IF NOT EXISTS transactions (\n                        tx_hash TEXT PRIMARY KEY, from_wallet TEXT NOT NULL, to_wallet TEXT NOT NULL,\n                        amount BIGINT NOT NULL, fee BIGINT DEFAULT 0, timestamp DOUBLE PRECISION NOT NULL,\n                        block_id BIGINT DEFAULT -1, status TEXT DEFAULT \'pending\', tx_type TEXT DEFAULT \'send\',\n                        signature TEXT DEFAULT \'\', nonce BIGINT DEFAULT 0, confirmations INTEGER DEFAULT 0,\n                        data JSONB DEFAULT \'{}\', confirmed BOOLEAN DEFAULT FALSE, token_address TEXT DEFAULT \'\',\n                        contract_address TEXT DEFAULT \'\', function TEXT DEFAULT \'\', params JSONB DEFAULT \'[]\'\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_id);\n                    CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_wallet);\n                    CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_wallet);\n                    CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);\n\n                    CREATE TABLE IF NOT EXISTS balances (wallet TEXT PRIMARY KEY, bal BIGINT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW());\n                    CREATE TABLE IF NOT EXISTS tokens (address TEXT PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL, owner TEXT NOT NULL, total_supply BIGINT NOT NULL, decimals INTEGER DEFAULT 18, created_at TIMESTAMP DEFAULT NOW(), fee_paid BIGINT NOT NULL, mintable BOOLEAN DEFAULT TRUE, burnable BOOLEAN DEFAULT FALSE, mining_type TEXT DEFAULT \'\', mining_reward BIGINT DEFAULT 0, mining_interval INTEGER DEFAULT 1, mining_difficulty INTEGER DEFAULT 1, stake_threshold BIGINT DEFAULT 0, last_mined_block BIGINT DEFAULT 0, total_mined BIGINT DEFAULT 0, max_mineable_supply BIGINT DEFAULT 1000000000000000);\n                    CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner);\n                    CREATE INDEX IF NOT EXISTS idx_tokens_symbol ON tokens(symbol);\n\n                    CREATE TABLE IF NOT EXISTS token_balances (token_address TEXT NOT NULL, wallet TEXT NOT NULL, balance BIGINT DEFAULT 0, PRIMARY KEY (token_address, wallet));\n                    CREATE INDEX IF NOT EXISTS idx_token_balances_wallet ON token_balances(wallet);\n\n                    CREATE TABLE IF NOT EXISTS contracts (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi JSONB NOT NULL, created_at TIMESTAMP DEFAULT NOW(), tx_hash TEXT NOT NULL);\n                    CREATE TABLE IF NOT EXISTS contract_state (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));\n                    CREATE INDEX IF NOT EXISTS idx_contract_state_key ON contract_state(key);\n\n                    CREATE TABLE IF NOT EXISTS contract_events (id SERIAL PRIMARY KEY, contract_address TEXT NOT NULL, event_name TEXT NOT NULL, data JSONB NOT NULL, block_id BIGINT NOT NULL, tx_hash TEXT NOT NULL, timestamp TIMESTAMP DEFAULT NOW());\n                    CREATE INDEX IF NOT EXISTS idx_contract_events_address ON contract_events(contract_address);\n                    CREATE INDEX IF NOT EXISTS idx_contract_events_block ON contract_events(block_id);\n\n                    CREATE TABLE IF NOT EXISTS slashing_events (id SERIAL PRIMARY KEY, miner_id TEXT NOT NULL, amount BIGINT DEFAULT 0, reason TEXT DEFAULT \'\', timestamp TIMESTAMP DEFAULT NOW(), block_id BIGINT DEFAULT -1);\n                    CREATE INDEX IF NOT EXISTS idx_slashing_miner ON slashing_events(miner_id);\n\n                    CREATE TABLE IF NOT EXISTS signed_blocks (\n                        miner_id TEXT NOT NULL,\n                        block_id BIGINT NOT NULL,\n                        block_hash TEXT NOT NULL,\n                        signed_at TIMESTAMP DEFAULT NOW(),\n                        PRIMARY KEY (miner_id, block_id)\n                    );\n\n                    CREATE TABLE IF NOT EXISTS lottery_commits (\n                        height BIGINT NOT NULL,\n                        miner_id TEXT NOT NULL,\n                        "commit" TEXT NOT NULL,\n                        PRIMARY KEY (height, miner_id)\n                    );\n\n                    CREATE TABLE IF NOT EXISTS lottery_reveals (\n                        height BIGINT NOT NULL,\n                        miner_id TEXT NOT NULL,\n                        secret TEXT NOT NULL,\n                        PRIMARY KEY (height, miner_id)\n                    );\n\n                    CREATE TABLE IF NOT EXISTS validator_history (id SERIAL PRIMARY KEY, miner_id TEXT NOT NULL, block_id BIGINT NOT NULL, timestamp TIMESTAMP DEFAULT NOW(), reward BIGINT DEFAULT 0);\n                    CREATE INDEX IF NOT EXISTS idx_validator_miner ON validator_history(miner_id);\n                    CREATE INDEX IF NOT EXISTS idx_validator_block ON validator_history(block_id);\n\n                    CREATE TABLE IF NOT EXISTS network_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);\n                    CREATE TABLE IF NOT EXISTS memory_challenges (miner_id TEXT PRIMARY KEY, seed TEXT NOT NULL, commitment TEXT NOT NULL, memory_size INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), last_verified TIMESTAMP DEFAULT NOW(), passes INTEGER DEFAULT 0, failures INTEGER DEFAULT 0);\n\n                    CREATE TABLE IF NOT EXISTS token_stakes (token_address TEXT NOT NULL, wallet TEXT NOT NULL, stake_amount BIGINT DEFAULT 0, staked_at TIMESTAMP DEFAULT NOW(), last_reward_block BIGINT DEFAULT 0, PRIMARY KEY (token_address, wallet));\n                    CREATE INDEX IF NOT EXISTS idx_token_stakes_token ON token_stakes(token_address);\n\n                    CREATE TABLE IF NOT EXISTS multisig_wallets (address TEXT PRIMARY KEY, public_keys JSONB NOT NULL, threshold INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW());\n                    CREATE TABLE IF NOT EXISTS signing_challenges (wallet TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires TIMESTAMP NOT NULL);\n                    CREATE TABLE IF NOT EXISTS mempool_persist (tx_hash TEXT PRIMARY KEY, tx_json TEXT NOT NULL, stored_at DOUBLE PRECISION NOT NULL);\n\n                    CREATE TABLE IF NOT EXISTS transaction_receipts (tx_hash TEXT PRIMARY KEY, block_id BIGINT NOT NULL, status INTEGER DEFAULT 1, gas_used BIGINT DEFAULT 0, logs JSONB DEFAULT \'[]\', contract_address TEXT DEFAULT \'\', result TEXT DEFAULT \'\');\n                    CREATE INDEX IF NOT EXISTS idx_receipts_block ON transaction_receipts(block_id);\n\n                    CREATE TABLE IF NOT EXISTS finality_checkpoints (block_id BIGINT PRIMARY KEY, hash TEXT NOT NULL, finalized_at TIMESTAMP DEFAULT NOW(), epoch INTEGER NOT NULL);\n                    CREATE INDEX IF NOT EXISTS idx_finality_epoch ON finality_checkpoints(epoch);\n\n                    CREATE TABLE IF NOT EXISTS contract_v2 (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi JSONB NOT NULL, created_at TIMESTAMP DEFAULT NOW(), tx_hash TEXT NOT NULL, storage_root TEXT DEFAULT \'\', code_hash TEXT NOT NULL);\n                    CREATE INDEX IF NOT EXISTS idx_contract_v2_owner ON contract_v2(owner);\n\n                    CREATE TABLE IF NOT EXISTS contract_storage_v2 (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));\n                    CREATE INDEX IF NOT EXISTS idx_contract_storage_v2_address ON contract_storage_v2(contract_address);\n                    -- B6 (MCX73): write-ahead journal for VM-flush state mutations (storage, balances, token balances) so a later reorg restores pre-block values.\n                    CREATE TABLE IF NOT EXISTS contract_exec_journal (seq BIGSERIAL, block_id BIGINT NOT NULL, namespace TEXT NOT NULL, addr TEXT NOT NULL, key TEXT NOT NULL, old_value TEXT, new_value TEXT);\n                    ALTER TABLE contract_exec_journal ADD COLUMN IF NOT EXISTS seq BIGSERIAL;\n                    CREATE INDEX IF NOT EXISTS idx_contract_exec_journal_block ON contract_exec_journal(block_id);\n\n                    CREATE TABLE IF NOT EXISTS htlc_contracts (id TEXT PRIMARY KEY, sender TEXT NOT NULL, receiver TEXT NOT NULL, hashlock TEXT NOT NULL, timelock BIGINT NOT NULL, amount BIGINT NOT NULL, token_address TEXT DEFAULT \'\', status TEXT DEFAULT \'open\', created_at TIMESTAMP DEFAULT NOW(), claimed_at TIMESTAMP, refunded_at TIMESTAMP);\n                    CREATE INDEX IF NOT EXISTS idx_htlc_sender ON htlc_contracts(sender);\n                    CREATE INDEX IF NOT EXISTS idx_htlc_receiver ON htlc_contracts(receiver);\n                    CREATE INDEX IF NOT EXISTS idx_htlc_status ON htlc_contracts(status);\n                    CREATE TABLE IF NOT EXISTS shards (\n                        shard_id TEXT PRIMARY KEY,\n                        kind INTEGER NOT NULL,\n                        data_hash TEXT NOT NULL,\n                        tenant TEXT NOT NULL,\n                        total BIGINT NOT NULL,\n                        idx BIGINT NOT NULL,\n                        parent_id TEXT,\n                        miner_id TEXT,\n                        x BIGINT,\n                        y BIGINT,\n                        z BIGINT,\n                        occupied_since_block BIGINT,\n                        status TEXT NOT NULL DEFAULT \'unplaced\',\n                        created_at_block BIGINT NOT NULL,\n                        updated_at_block BIGINT NOT NULL\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_shards_tenant ON shards(tenant);\n                    CREATE INDEX IF NOT EXISTS idx_shards_miner ON shards(miner_id);\n                    CREATE INDEX IF NOT EXISTS idx_shards_status ON shards(status);\n                    CREATE TABLE IF NOT EXISTS state_trie_nodes (\n                        node_hash TEXT PRIMARY KEY, node_data TEXT NOT NULL, ref_count INTEGER DEFAULT 1\n                    );\n                    CREATE TABLE IF NOT EXISTS block_state_roots (\n                        block_id BIGINT PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT NOT NULL\n                    );\n                    # SVF v1 persistent consensus state (§8.2, §8.3)\n                    CREATE TABLE IF NOT EXISTS svf_profiles (\n                        token_address TEXT PRIMARY KEY,\n                        chain_id BIGINT NOT NULL,\n                        runtime_code_hash TEXT NOT NULL,\n                        template_id TEXT NOT NULL,\n                        profile_schema_version INTEGER NOT NULL,\n                        canonical_profile_bytes TEXT NOT NULL,\n                        profile_hash TEXT NOT NULL,\n                        registrant TEXT NOT NULL,\n                        registration_tx_hash TEXT NOT NULL,\n                        registration_block_height BIGINT NOT NULL,\n                        effective_epoch BIGINT NOT NULL,\n                        status TEXT NOT NULL DEFAULT \'ACTIVE\'\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_svf_profiles_hash ON svf_profiles(profile_hash);\n                    CREATE TABLE IF NOT EXISTS svf_evidence (\n                        epoch_id BIGINT NOT NULL,\n                        height BIGINT NOT NULL,\n                        block_hash TEXT NOT NULL,\n                        winner_pubkey TEXT NOT NULL,\n                        attested_size INTEGER NOT NULL,\n                        attestation_weight TEXT NOT NULL,\n                        growth_present INTEGER NOT NULL DEFAULT 0,\n                        record_hash TEXT NOT NULL,\n                        PRIMARY KEY (epoch_id, height)\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_svf_evidence_epoch ON svf_evidence(epoch_id);\n                    CREATE TABLE IF NOT EXISTS svf_epoch_roots (\n                        epoch_id BIGINT PRIMARY KEY,\n                        root_hash TEXT NOT NULL,\n                        record_count INTEGER NOT NULL,\n                        complete INTEGER NOT NULL DEFAULT 0\n                    );\n                    CREATE TABLE IF NOT EXISTS svf_certificates (\n                        evidence_epoch BIGINT PRIMARY KEY,\n                        chain_id BIGINT NOT NULL,\n                        committee_epoch BIGINT NOT NULL,\n                        window_start_height BIGINT NOT NULL,\n                        window_end_height BIGINT NOT NULL,\n                        anchor_block_hash TEXT NOT NULL,\n                        evidence_root TEXT NOT NULL,\n                        group_public_key_id TEXT NOT NULL,\n                        threshold_signature TEXT NOT NULL,\n                        inclusion_block BIGINT NOT NULL,\n                        usable_from BIGINT NOT NULL\n                    );\n                    CREATE TABLE IF NOT EXISTS account_nonces (\n                        wallet TEXT PRIMARY KEY,\n                        next_nonce BIGINT NOT NULL\n                    );\n                    CREATE TABLE IF NOT EXISTS state_snapshots (\n                        block_id BIGINT PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT DEFAULT \'\', snapshot_data TEXT NOT NULL, created_at BIGINT NOT NULL\n                    );\n                    CREATE TABLE IF NOT EXISTS pending_maze_updates (\n                        block_id BIGINT NOT NULL, minerid TEXT NOT NULL, update_json TEXT NOT NULL,\n                        PRIMARY KEY (block_id, minerid)\n                    );\n                    CREATE TABLE IF NOT EXISTS minermazes (\n                        maze_id TEXT PRIMARY KEY,\n                        minerid TEXT NOT NULL,\n                        size INTEGER NOT NULL,\n                        walldensityppm INTEGER NOT NULL,\n                        seed TEXT NOT NULL,\n                        posx INTEGER NOT NULL,\n                        posy INTEGER NOT NULL,\n                        posz INTEGER NOT NULL,\n                        goalx INTEGER NOT NULL,\n                        goaly INTEGER NOT NULL,\n                        goalz INTEGER NOT NULL,\n                        movenonce BIGINT NOT NULL DEFAULT 0,\n                        consecutivewallhits INTEGER NOT NULL DEFAULT 0,\n                        turbulenceppm INTEGER NOT NULL DEFAULT 0,\n                        growthcount BIGINT NOT NULL DEFAULT 0,\n                        knowledge INTEGER NOT NULL DEFAULT 0,\n                        lastgoalheight BIGINT NOT NULL DEFAULT 0,\n                        lastactiveheight BIGINT NOT NULL DEFAULT 0,\n                        mazeroot TEXT NOT NULL,\n                        invitedguest TEXT,\n                        guestlock BOOLEAN NOT NULL DEFAULT FALSE,\n                        lastknowledgeheight BIGINT NOT NULL DEFAULT 0,\n                        createdat BIGINT NOT NULL,\n                        updatedat BIGINT NOT NULL,\n                        ghostx INTEGER,\n                        ghosty INTEGER,\n                        ghostz INTEGER\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid);\n                    CREATE TABLE IF NOT EXISTS maze_attestations (\n                        maze_id TEXT PRIMARY KEY,\n                        last_size BIGINT NOT NULL,\n                        last_block BIGINT NOT NULL,\n                        last_block_hash TEXT NOT NULL,\n                        pubkey TEXT NOT NULL\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_maze_attestations_last_block ON maze_attestations(last_block);\n                    CREATE TABLE IF NOT EXISTS maze_proofs (\n                        maze_id TEXT NOT NULL,\n                        new_size BIGINT NOT NULL,\n                        proof_json TEXT NOT NULL,\n                        updated_block BIGINT NOT NULL,\n                        PRIMARY KEY (maze_id, new_size)\n                    );\n                    CREATE TABLE IF NOT EXISTS automations (\n                        id TEXT PRIMARY KEY,\n                        name TEXT NOT NULL,\n                        owner TEXT NOT NULL,\n                        trigger_type TEXT NOT NULL,\n                        trigger_config JSONB NOT NULL,\n                        action_type TEXT NOT NULL,\n                        action_config JSONB NOT NULL,\n                        enabled BOOLEAN DEFAULT TRUE,\n                        created_at TIMESTAMP DEFAULT NOW(),\n                        last_run_at TIMESTAMP,\n                        run_count INTEGER DEFAULT 0,\n                        last_result TEXT DEFAULT \'\',\n                        -- R6-automation-last-block-persist: firing height\n                        last_block_run BIGINT DEFAULT 0\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_automations_owner ON automations(owner);\n                    -- AUTO-REPLAY-SEEN-1 (mainnet audit): durable replay\n                    -- guard surviving restarts (memory set does not).\n                    CREATE TABLE IF NOT EXISTS automation_replay_seen (\n                        sig_hash TEXT PRIMARY KEY, seen_at DOUBLE PRECISION NOT NULL\n                    );\n\n                    CREATE TABLE IF NOT EXISTS schema_version (\n                        version INTEGER PRIMARY KEY,\n                        applied_at TIMESTAMP DEFAULT NOW()\n                    );\n                    CREATE TABLE IF NOT EXISTS peer_bans (\n                        address TEXT PRIMARY KEY,\n                        node_id TEXT,\n                        reason TEXT NOT NULL DEFAULT \'\',\n                        banned_at TIMESTAMP DEFAULT NOW(),\n                        expires_at DOUBLE PRECISION NOT NULL\n                    );\n                    CREATE INDEX IF NOT EXISTS idx_peer_bans_expires ON peer_bans(expires_at);\n                ')
                await conn.execute('INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT (version) DO NOTHING', config.SCHEMA_VERSION)
        else:
            self.cursor.executescript('\n                CREATE TABLE IF NOT EXISTS miners (miner_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, pub TEXT NOT NULL, rewards INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, slashes INTEGER DEFAULT 0, uptime INTEGER DEFAULT 0, today_uptime INTEGER DEFAULT 0, type TEXT DEFAULT \'web\', liquidity INTEGER DEFAULT 0, fees INTEGER DEFAULT 0, last_ping REAL DEFAULT 0, banned_until REAL DEFAULT 0, created_at REAL DEFAULT 0, last_block INTEGER DEFAULT 0, consecutive_misses INTEGER DEFAULT 0, total_uptime INTEGER DEFAULT 0, ip_address TEXT DEFAULT \'\', node_id TEXT DEFAULT \'\', version TEXT DEFAULT \'\', active INTEGER DEFAULT 1, confirmed_balance INTEGER DEFAULT 0, password_hash TEXT DEFAULT \'\', private_key_encrypted TEXT DEFAULT \'\', gas_collected INTEGER DEFAULT 0, maze_wins INTEGER DEFAULT 0, block_signing_pub TEXT);\n                CREATE INDEX IF NOT EXISTS idx_miners_wallet ON miners(wallet);\n                CREATE INDEX IF NOT EXISTS idx_miners_active ON miners(active);\n                CREATE TABLE IF NOT EXISTS nodes (node_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, ip TEXT DEFAULT \'\', port INTEGER DEFAULT 0, last_seen REAL DEFAULT 0, height INTEGER DEFAULT 0, active INTEGER DEFAULT 1, rewards_earned INTEGER DEFAULT 0, version TEXT DEFAULT \'\', mining_enabled INTEGER DEFAULT 1, staking_enabled INTEGER DEFAULT 1, last_sync REAL DEFAULT 0, is_multisig_signer INTEGER DEFAULT 0, public_key TEXT DEFAULT \'\');\n                CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);\n                CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY, ts REAL NOT NULL, phash TEXT NOT NULL, miners TEXT DEFAULT \'\', hash TEXT NOT NULL, reward INTEGER DEFAULT 0, tx_count INTEGER DEFAULT 0, merkle_root TEXT DEFAULT \'\', nonce INTEGER DEFAULT 0, difficulty INTEGER DEFAULT 1, version TEXT DEFAULT \'\', challenge TEXT DEFAULT \'\', coverage REAL DEFAULT 1, total_tx_value INTEGER DEFAULT 0, total_fees INTEGER DEFAULT 0, tx_hashes TEXT DEFAULT \'\', finalized INTEGER DEFAULT 0);\n                CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(id);\n                CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);\n                CREATE INDEX IF NOT EXISTS idx_blocks_finalized ON blocks(finalized);\n                CREATE TABLE IF NOT EXISTS transactions (tx_hash TEXT PRIMARY KEY, from_wallet TEXT NOT NULL, to_wallet TEXT NOT NULL, amount INTEGER NOT NULL, fee INTEGER DEFAULT 0, timestamp REAL NOT NULL, block_id INTEGER DEFAULT -1, status TEXT DEFAULT \'pending\', tx_type TEXT DEFAULT \'send\', signature TEXT DEFAULT \'\', nonce INTEGER DEFAULT 0, confirmations INTEGER DEFAULT 0, data TEXT DEFAULT \'{}\', confirmed INTEGER DEFAULT 0, token_address TEXT DEFAULT \'\', contract_address TEXT DEFAULT \'\', function TEXT DEFAULT \'\', params TEXT DEFAULT \'[]\');\n                CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_id);\n                CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_wallet);\n                CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_wallet);\n                CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);\n                CREATE TABLE IF NOT EXISTS balances (wallet TEXT PRIMARY KEY, bal INTEGER DEFAULT 0);\n                CREATE TABLE IF NOT EXISTS tokens (address TEXT PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL, owner TEXT NOT NULL, total_supply INTEGER NOT NULL, decimals INTEGER DEFAULT 18, created_at REAL NOT NULL, fee_paid INTEGER NOT NULL, mintable INTEGER DEFAULT 1, burnable INTEGER DEFAULT 0, mining_type TEXT DEFAULT \'\', mining_reward INTEGER DEFAULT 0, mining_interval INTEGER DEFAULT 1, mining_difficulty INTEGER DEFAULT 1, stake_threshold INTEGER DEFAULT 0, last_mined_block INTEGER DEFAULT 0, total_mined INTEGER DEFAULT 0, max_mineable_supply INTEGER DEFAULT 0);\n                CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner);\n                CREATE INDEX IF NOT EXISTS idx_tokens_symbol ON tokens(symbol);\n                CREATE TABLE IF NOT EXISTS token_balances (token_address TEXT NOT NULL, wallet TEXT NOT NULL, balance INTEGER NOT NULL, PRIMARY KEY (token_address, wallet));\n                CREATE INDEX IF NOT EXISTS idx_token_balances_wallet ON token_balances(wallet);\n                CREATE TABLE IF NOT EXISTS contracts (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi TEXT NOT NULL, created_at REAL NOT NULL, tx_hash TEXT NOT NULL);\n                CREATE TABLE IF NOT EXISTS contract_state (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));\n                CREATE INDEX IF NOT EXISTS idx_contract_state_key ON contract_state(key);\n                CREATE TABLE IF NOT EXISTS contract_events (id INTEGER PRIMARY KEY AUTOINCREMENT, contract_address TEXT NOT NULL, event_name TEXT NOT NULL, data TEXT NOT NULL, block_id INTEGER NOT NULL, tx_hash TEXT NOT NULL, timestamp REAL NOT NULL);\n                CREATE INDEX IF NOT EXISTS idx_contract_events_address ON contract_events(contract_address);\n                CREATE INDEX IF NOT EXISTS idx_contract_events_block ON contract_events(block_id);\n                CREATE TABLE IF NOT EXISTS slashing_events (id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id TEXT NOT NULL, amount INTEGER DEFAULT 0, reason TEXT DEFAULT \'\', timestamp REAL NOT NULL, block_id INTEGER DEFAULT -1);\n                CREATE INDEX IF NOT EXISTS idx_slashing_miner ON slashing_events(miner_id);\n\n                CREATE TABLE IF NOT EXISTS signed_blocks (\n                    miner_id TEXT NOT NULL,\n                    block_id INTEGER NOT NULL,\n                    block_hash TEXT NOT NULL,\n                    signed_at REAL NOT NULL,\n                    PRIMARY KEY (miner_id, block_id)\n                );\n\n                CREATE TABLE IF NOT EXISTS lottery_commits (\n                    height INTEGER NOT NULL,\n                    miner_id TEXT NOT NULL,\n                    "commit" TEXT NOT NULL,\n                    PRIMARY KEY (height, miner_id)\n                );\n\n                CREATE TABLE IF NOT EXISTS lottery_reveals (\n                    height INTEGER NOT NULL,\n                    miner_id TEXT NOT NULL,\n                    secret TEXT NOT NULL,\n                    PRIMARY KEY (height, miner_id)\n                );\n\n                CREATE TABLE IF NOT EXISTS validator_history (id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id TEXT NOT NULL, block_id INTEGER NOT NULL, timestamp REAL NOT NULL, reward INTEGER DEFAULT 0);\n                CREATE INDEX IF NOT EXISTS idx_validator_miner ON validator_history(miner_id);\n                CREATE INDEX IF NOT EXISTS idx_validator_block ON validator_history(block_id);\n                CREATE TABLE IF NOT EXISTS network_state (key TEXT PRIMARY KEY, value TEXT);\n                CREATE TABLE IF NOT EXISTS memory_challenges (miner_id TEXT PRIMARY KEY, seed TEXT NOT NULL, commitment TEXT NOT NULL, memory_size INTEGER NOT NULL, created_at REAL NOT NULL, last_verified REAL DEFAULT 0, passes INTEGER DEFAULT 0, failures INTEGER DEFAULT 0);\n                CREATE TABLE IF NOT EXISTS token_stakes (token_address TEXT NOT NULL, wallet TEXT NOT NULL, stake_amount INTEGER NOT NULL, staked_at REAL NOT NULL, last_reward_block INTEGER DEFAULT 0, PRIMARY KEY (token_address, wallet));\n                CREATE INDEX IF NOT EXISTS idx_token_stakes_token ON token_stakes(token_address);\n                CREATE TABLE IF NOT EXISTS multisig_wallets (address TEXT PRIMARY KEY, public_keys TEXT NOT NULL, threshold INTEGER NOT NULL, created_at REAL NOT NULL);\n                CREATE TABLE IF NOT EXISTS signing_challenges (wallet TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires REAL NOT NULL);\n                CREATE TABLE IF NOT EXISTS mempool_persist (tx_hash TEXT PRIMARY KEY, tx_json TEXT NOT NULL, stored_at REAL NOT NULL);\n                CREATE TABLE IF NOT EXISTS transaction_receipts (tx_hash TEXT PRIMARY KEY, block_id INTEGER NOT NULL, status INTEGER DEFAULT 1, gas_used INTEGER DEFAULT 0, logs TEXT DEFAULT \'[]\', contract_address TEXT DEFAULT \'\', result TEXT DEFAULT \'\');\n                CREATE INDEX IF NOT EXISTS idx_receipts_block ON transaction_receipts(block_id);\n                CREATE TABLE IF NOT EXISTS finality_checkpoints (block_id INTEGER PRIMARY KEY, hash TEXT NOT NULL, finalized_at REAL NOT NULL, epoch INTEGER NOT NULL);\n                CREATE INDEX IF NOT EXISTS idx_finality_epoch ON finality_checkpoints(epoch);\n                CREATE TABLE IF NOT EXISTS contract_v2 (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi TEXT NOT NULL, created_at REAL NOT NULL, tx_hash TEXT NOT NULL, storage_root TEXT DEFAULT \'\', code_hash TEXT NOT NULL);\n                CREATE INDEX IF NOT EXISTS idx_contract_v2_owner ON contract_v2(owner);\n                CREATE TABLE IF NOT EXISTS contract_storage_v2 (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));\n                CREATE INDEX IF NOT EXISTS idx_contract_storage_v2_address ON contract_storage_v2(contract_address);\n                -- B6 (MCX73): write-ahead journal for VM-flush state mutations (storage, balances, token balances) so a later reorg restores pre-block values.\n                CREATE TABLE IF NOT EXISTS contract_exec_journal (block_id INTEGER NOT NULL, namespace TEXT NOT NULL, addr TEXT NOT NULL, key TEXT NOT NULL, old_value TEXT, new_value TEXT);\n                CREATE INDEX IF NOT EXISTS idx_contract_exec_journal_block ON contract_exec_journal(block_id);\n                CREATE TABLE IF NOT EXISTS htlc_contracts (id TEXT PRIMARY KEY, sender TEXT NOT NULL, receiver TEXT NOT NULL, hashlock TEXT NOT NULL, timelock INTEGER NOT NULL, amount INTEGER NOT NULL, token_address TEXT DEFAULT \'\', status TEXT DEFAULT \'open\', created_at REAL NOT NULL, claimed_at REAL, refunded_at REAL);\n                CREATE INDEX IF NOT EXISTS idx_htlc_sender ON htlc_contracts(sender);\n                CREATE INDEX IF NOT EXISTS idx_htlc_receiver ON htlc_contracts(receiver);\n                CREATE INDEX IF NOT EXISTS idx_htlc_status ON htlc_contracts(status);\n                CREATE TABLE IF NOT EXISTS state_trie_nodes (node_hash TEXT PRIMARY KEY, node_data TEXT NOT NULL, ref_count INTEGER DEFAULT 1);\n                CREATE TABLE IF NOT EXISTS block_state_roots (block_id INTEGER PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT NOT NULL);\n                -- SVF v1 persistent consensus state (sqlite): the same four\n                -- tables as the postgres branch. Without them every SVF DB\n                -- operation on the default sqlite backend fails with\n                -- \'no such table\' (registration, evidence, roots, certs).\n                CREATE TABLE IF NOT EXISTS svf_profiles (\n                    token_address TEXT PRIMARY KEY,\n                    chain_id INTEGER NOT NULL,\n                    runtime_code_hash TEXT NOT NULL,\n                    template_id TEXT NOT NULL,\n                    profile_schema_version INTEGER NOT NULL,\n                    canonical_profile_bytes TEXT NOT NULL,\n                    profile_hash TEXT NOT NULL,\n                    registrant TEXT NOT NULL,\n                    registration_tx_hash TEXT NOT NULL,\n                    registration_block_height INTEGER NOT NULL,\n                    effective_epoch INTEGER NOT NULL,\n                    status TEXT NOT NULL DEFAULT \'ACTIVE\'\n                );\n                CREATE INDEX IF NOT EXISTS idx_svf_profiles_hash ON svf_profiles(profile_hash);\n                CREATE TABLE IF NOT EXISTS svf_evidence (\n                    epoch_id INTEGER NOT NULL,\n                    height INTEGER NOT NULL,\n                    block_hash TEXT NOT NULL,\n                    winner_pubkey TEXT NOT NULL,\n                    attested_size INTEGER NOT NULL,\n                    attestation_weight TEXT NOT NULL,\n                    growth_present INTEGER NOT NULL DEFAULT 0,\n                    record_hash TEXT NOT NULL,\n                    PRIMARY KEY (epoch_id, height)\n                );\n                CREATE INDEX IF NOT EXISTS idx_svf_evidence_epoch ON svf_evidence(epoch_id);\n                CREATE TABLE IF NOT EXISTS svf_epoch_roots (\n                    epoch_id INTEGER PRIMARY KEY,\n                    root_hash TEXT NOT NULL,\n                    record_count INTEGER NOT NULL,\n                    complete INTEGER NOT NULL DEFAULT 0\n                );\n                CREATE TABLE IF NOT EXISTS svf_certificates (\n                    evidence_epoch INTEGER PRIMARY KEY,\n                    chain_id INTEGER NOT NULL,\n                    committee_epoch INTEGER NOT NULL,\n                    window_start_height INTEGER NOT NULL,\n                    window_end_height INTEGER NOT NULL,\n                    anchor_block_hash TEXT NOT NULL,\n                    evidence_root TEXT NOT NULL,\n                    group_public_key_id TEXT NOT NULL,\n                    threshold_signature TEXT NOT NULL,\n                    inclusion_block INTEGER NOT NULL,\n                    usable_from INTEGER NOT NULL\n                );\n                CREATE TABLE IF NOT EXISTS account_nonces (\n                    wallet TEXT PRIMARY KEY,\n                    next_nonce INTEGER NOT NULL\n                );\n                CREATE TABLE IF NOT EXISTS state_snapshots (block_id INTEGER PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT DEFAULT \'\', snapshot_data TEXT NOT NULL, created_at INTEGER NOT NULL);\n                CREATE TABLE IF NOT EXISTS pending_maze_updates (\n                    block_id INTEGER NOT NULL,\n                    minerid TEXT NOT NULL,\n                    update_json TEXT NOT NULL,\n                    PRIMARY KEY (block_id, minerid)\n                );\n                CREATE TABLE IF NOT EXISTS minermazes (\n                    maze_id TEXT PRIMARY KEY,\n                    minerid TEXT NOT NULL,\n                    size INTEGER NOT NULL,\n                    walldensityppm INTEGER NOT NULL,\n                    seed TEXT NOT NULL,\n                    posx INTEGER NOT NULL,\n                    posy INTEGER NOT NULL,\n                    posz INTEGER NOT NULL,\n                    goalx INTEGER NOT NULL,\n                    goaly INTEGER NOT NULL,\n                    goalz INTEGER NOT NULL,\n                    movenonce BIGINT NOT NULL DEFAULT 0,\n                    consecutivewallhits INTEGER NOT NULL DEFAULT 0,\n                    turbulenceppm INTEGER NOT NULL DEFAULT 0,\n                    growthcount BIGINT NOT NULL DEFAULT 0,\n                    knowledge INTEGER NOT NULL DEFAULT 0,\n                    lastgoalheight BIGINT NOT NULL DEFAULT 0,\n                    lastactiveheight BIGINT NOT NULL DEFAULT 0,\n                    mazeroot TEXT NOT NULL,\n                    invitedguest TEXT,\n                    guestlock INTEGER NOT NULL DEFAULT 0,\n                    lastknowledgeheight BIGINT NOT NULL DEFAULT 0,\n                    createdat REAL NOT NULL,\n                    updatedat REAL NOT NULL,\n                    ghostx INTEGER,\n                    ghosty INTEGER,\n                    ghostz INTEGER\n                );\n                CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid);\n                CREATE TABLE IF NOT EXISTS maze_attestations (\n                    maze_id TEXT PRIMARY KEY,\n                    last_size INTEGER NOT NULL,\n                    last_block INTEGER NOT NULL,\n                    last_block_hash TEXT NOT NULL,\n                    pubkey TEXT NOT NULL\n                );\n                CREATE INDEX IF NOT EXISTS idx_maze_attestations_last_block ON maze_attestations(last_block);\n                CREATE TABLE IF NOT EXISTS maze_proofs (\n                    maze_id TEXT NOT NULL,\n                    new_size INTEGER NOT NULL,\n                    proof_json TEXT NOT NULL,\n                    updated_block INTEGER NOT NULL,\n                    PRIMARY KEY (maze_id, new_size)\n                );\n                CREATE TABLE IF NOT EXISTS automations (\n                    id TEXT PRIMARY KEY,\n                    name TEXT NOT NULL,\n                    owner TEXT NOT NULL,\n                    trigger_type TEXT NOT NULL,\n                    trigger_config TEXT NOT NULL,\n                    action_type TEXT NOT NULL,\n                    action_config TEXT NOT NULL,\n                    enabled INTEGER DEFAULT 1,\n                    created_at REAL NOT NULL,\n                    last_run_at REAL,\n                    run_count INTEGER DEFAULT 0,\n                    last_result TEXT DEFAULT \'\',\n                    -- R6-automation-last-block-persist: firing height\n                    last_block_run INTEGER DEFAULT 0\n                );\n                CREATE INDEX IF NOT EXISTS idx_automations_owner ON automations(owner);\n                -- AUTO-REPLAY-SEEN-1 (mainnet audit): durable replay\n                -- guard surviving restarts (memory set does not).\n                CREATE TABLE IF NOT EXISTS automation_replay_seen (\n                    sig_hash TEXT PRIMARY KEY, seen_at REAL NOT NULL\n                );\n                CREATE TABLE IF NOT EXISTS peer_bans (\n                    address TEXT PRIMARY KEY,\n                    node_id TEXT,\n                    reason TEXT NOT NULL DEFAULT \'\',\n                    banned_at REAL NOT NULL,\n                    expires_at REAL NOT NULL\n                );\n                CREATE INDEX IF NOT EXISTS idx_peer_bans_expires ON peer_bans(expires_at);\n                CREATE TABLE IF NOT EXISTS schema_version (\n                    version INTEGER PRIMARY KEY,\n                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP\n                );\n            ')
            self.cursor.execute('PRAGMA table_info(blocks)')
            columns = [row[1] for row in self.cursor.fetchall()]
            if 'proof' not in columns:
                self.cursor.execute("ALTER TABLE blocks ADD COLUMN proof TEXT DEFAULT '{}'")
            self.cursor.execute('PRAGMA table_info(minermazes)')
            mcols = [row[1] for row in self.cursor.fetchall()]
            if 'maze_id' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN maze_id TEXT')
                self.cursor.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_minermazes_maze_id ON minermazes(maze_id)')
            if 'knowledge' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN knowledge INTEGER NOT NULL DEFAULT 0')
            if 'lastknowledgeheight' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN lastknowledgeheight BIGINT NOT NULL DEFAULT 0')
            if 'ghostx' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN ghostx INTEGER')
            if 'ghosty' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN ghosty INTEGER')
            if 'ghostz' not in mcols:
                self.cursor.execute('ALTER TABLE minermazes ADD COLUMN ghostz INTEGER')
            self.cursor.execute('PRAGMA table_info(minermazes)')
            pk_cols = [row[1] for row in self.cursor.fetchall() if row[5] == 1]
            if pk_cols and pk_cols[0] != 'maze_id':
                bootstrap.logger.info('[DB] Migrating minermazes: maze_id → PRIMARY KEY')
                self.cursor.execute('\n                    CREATE TABLE IF NOT EXISTS minermazes_new (\n                        maze_id TEXT PRIMARY KEY, minerid TEXT NOT NULL,\n                        size INTEGER NOT NULL, walldensityppm INTEGER NOT NULL,\n                        seed TEXT NOT NULL, posx INTEGER NOT NULL, posy INTEGER NOT NULL, posz INTEGER NOT NULL,\n                        goalx INTEGER NOT NULL, goaly INTEGER NOT NULL, goalz INTEGER NOT NULL,\n                        movenonce BIGINT NOT NULL DEFAULT 0, consecutivewallhits INTEGER NOT NULL DEFAULT 0,\n                        turbulenceppm INTEGER NOT NULL DEFAULT 0, growthcount BIGINT NOT NULL DEFAULT 0,\n                        knowledge INTEGER NOT NULL DEFAULT 0, lastgoalheight BIGINT NOT NULL DEFAULT 0,\n                        lastactiveheight BIGINT NOT NULL DEFAULT 0, mazeroot TEXT NOT NULL,\n                        invitedguest TEXT, guestlock INTEGER NOT NULL DEFAULT 0,\n                        lastknowledgeheight BIGINT NOT NULL DEFAULT 0,\n                        createdat REAL NOT NULL, updatedat REAL NOT NULL,\n                        ghostx INTEGER, ghosty INTEGER, ghostz INTEGER\n                    )\n                ')
                self.cursor.execute('\n                    INSERT OR IGNORE INTO minermazes_new\n                    SELECT COALESCE(maze_id, minerid), minerid, size, walldensityppm, seed,\n                           posx, posy, posz, goalx, goaly, goalz,\n                           movenonce, consecutivewallhits, turbulenceppm, growthcount,\n                           knowledge, lastgoalheight, lastactiveheight, mazeroot,\n                           invitedguest, guestlock, lastknowledgeheight, createdat, updatedat,\n                           ghostx, ghosty, ghostz\n                    FROM minermazes\n                ')
                self.cursor.execute('DROP TABLE IF EXISTS minermazes')
                self.cursor.execute('ALTER TABLE minermazes_new RENAME TO minermazes')
                self.cursor.execute('CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid)')
                bootstrap.logger.info('[DB] Migration complete: maze_id is now PRIMARY KEY')
            self.cursor.execute('PRAGMA table_info(miners)')
            mncols = [row[1] for row in self.cursor.fetchall()]
            if 'block_signing_pub' not in mncols:
                self.cursor.execute('ALTER TABLE miners ADD COLUMN block_signing_pub TEXT')
            self.cursor.execute('INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)', (config.SCHEMA_VERSION, bootstrap.time.time()))
            self.conn.commit()
        bootstrap.logger.info(f'[DB] Tables ready for {self.db_type}')

class SyncDB:

    def __init__(self, db_url):
        self.db_url = db_url
        self.conn = None
        if db_url.startswith('sqlite://'):
            path = db_url[9:]
            self.conn = bootstrap.sqlite3.connect(path, check_same_thread=False)
            self.conn.row_factory = bootstrap.sqlite3.Row
        elif db_url.startswith('postgresql://'):
            import psycopg2
            self.conn = psycopg2.connect(db_url)
            self.conn.autocommit = True
        else:
            raise ValueError('Unsupported DB URL')

    def _translate(self, query: str) -> str:
        if self.db_url.startswith('postgresql://') and '?' in query:
            out, in_q, prev = ([], False, '')
            for c in query:
                if in_q:
                    out.append(c)
                    if c == "'" and prev != '\\':
                        in_q = False
                elif c == "'":
                    in_q = True
                    out.append(c)
                elif c == '?':
                    out.append('%s')
                else:
                    out.append(c)
                prev = c
            return ''.join(out)
        return query

    def execute(self, query, params=()):
        if params is None:
            params = ()
        elif not isinstance(params, (tuple, list)):
            params = (params,)
        cur = self.conn.cursor()
        cur.execute(self._translate(query), tuple(params))
        return cur

    def fetchall(self, query, params=()):
        if params is None:
            params = ()
        elif not isinstance(params, (tuple, list)):
            params = (params,)
        cur = self.conn.cursor()
        cur.execute(self._translate(query), tuple(params))
        return cur.fetchall()

    def fetchone(self, query, params=()):
        if params is None:
            params = ()
        elif not isinstance(params, (tuple, list)):
            params = (params,)
        cur = self.conn.cursor()
        cur.execute(self._translate(query), tuple(params))
        return cur.fetchone()

    def rollback(self):
        self.conn.rollback()

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()
