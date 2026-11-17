import bootstrap
import config
import crypto
import svf_keys
import svf
import db
import vm

def _vm_require_sandbox_effective() -> bool:
    _env = bootstrap.os.environ.get('MCX_VM_REQUIRE_SANDBOX', '').strip().lower()
    if _env in ('1', 'true', 'yes', 'on'):
        return True
    if _env in ('0', 'false', 'no', 'off'):
        return False
    return bool(config.VM_REQUIRE_SANDBOX)

def export_vm_sandbox_env(config) -> str:
    try:
        _want = bool((config or {}).get('vm', {}).get('require_sandbox', False))
    except Exception:
        _want = False
    bootstrap.os.environ['MCX_VM_REQUIRE_SANDBOX'] = '1' if _want else '0'
    return bootstrap.os.environ['MCX_VM_REQUIRE_SANDBOX']

def _drop_vm_privileges() -> bool:
    try:
        if hasattr(bootstrap.os, 'geteuid') and bootstrap.os.geteuid() == 0:
            bootstrap.os.setgid(int(bootstrap.os.environ.get('MCX_VM_GID', '65534')))
            bootstrap.os.setuid(int(bootstrap.os.environ.get('MCX_VM_UID', '65534')))
            return True
        return False
    except (OSError, PermissionError, ValueError) as _du_e:
        if _vm_require_sandbox_effective():
            bootstrap.sys.stderr.write(f'[VM] FATAL: privilege drop failed ({_du_e}) with require_sandbox=true; refusing to run\n')
            bootstrap.sys.stderr.flush()
            bootstrap.sys.exit(1)
        bootstrap.sys.stderr.write(f'[VM] WARNING: privilege drop failed ({_du_e}); continuing chrooted as current user\n')
        bootstrap.sys.stderr.flush()
        return False

def _apply_vm_worker_limits() -> None:
    if not bootstrap.HAVE_RESOURCE:
        return
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_AS, (config.VM_RLIMIT_AS_BYTES, config.VM_RLIMIT_AS_BYTES))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass
_VM_SYNC_DB: bootstrap.Dict[str, bootstrap.Any] = {}
_VM_SANDBOXED = False

def run_vm_in_subprocess(bytecode_hex: str, caller: str, origin: str, value: int, gas_limit: int, contract_address: str, input_data_hex: str, static: bool=False, storage_cache: dict=None, code_cache: dict=None, balance_cache: dict=None, token_balance_cache: dict=None, htlc_repo_conn_info: tuple=None, block_height: int=0, block_ts: float=None) -> bootstrap.Tuple[bool, str, int, bootstrap.List[bootstrap.Dict], dict, dict, dict]:
    _svf_key_path = bootstrap.os.environ.get('MCX_SVF_FILE', '')
    for _sensitive_key in list(bootstrap.os.environ.keys()):
        if any((_k in _sensitive_key.upper() for _k in ('PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL'))):
            try:
                del bootstrap.os.environ[_sensitive_key]
            except Exception:
                pass
    if _svf_key_path and (svf_keys.SVF_GROUP_PUBLIC_KEY is None or svf_keys.SVF_KEY_FILE != _svf_key_path):
        try:
            svf_keys._svf_load_key_file(_svf_key_path)
        except Exception:
            pass
    _pb = bootstrap.os.environ.get('MCX_PRUNE_BLOCKS', '')
    if _pb:
        try:
            config.PRUNE_BLOCKS = int(_pb)
        except (TypeError, ValueError):
            pass
    db_url = bootstrap.os.environ.get('MCX_DB_URL', '')
    if not db_url:
        db_host = bootstrap.os.environ.get('MCX_DB_HOST', 'localhost')
        db_port = bootstrap.os.environ.get('MCX_DB_PORT', '5432')
        db_user = bootstrap.os.environ.get('MCX_DB_USER', 'postgres')
        db_pass = bootstrap.os.environ.get('MCX_DB_PASS', 'postgres')
        db_name = bootstrap.os.environ.get('MCX_DB_NAME', 'mcx')
        if bootstrap.os.environ.get('MCX_DB_HOST'):
            db_url = f'postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}'
        else:
            db_url = 'sqlite://microcore.db'
    sync_db = None
    if bootstrap.HAVE_RESOURCE:
        _apply_vm_worker_limits()
        _vm_cached = _VM_SYNC_DB.get('db')
        if _vm_cached is not None and _vm_cached[0] == db_url:
            sync_db = _vm_cached[1]
        else:
            if _vm_cached is not None:
                try:
                    _vm_cached[1].conn.close()
                except Exception:
                    pass
            sync_db = db.SyncDB(db_url)
            _VM_SYNC_DB['db'] = (db_url, sync_db)
        try:
            if db_url.startswith('sqlite://'):
                sync_db.execute('SELECT name FROM sqlite_master LIMIT 1').fetchone()
            else:
                sync_db.execute('SELECT 1').fetchone()
        except Exception:
            pass
        try:
            crypto.keccak_256(b'')
        except Exception:
            pass
        global _VM_SANDBOXED
        if not _VM_SANDBOXED:
            try:
                sandbox_dir = '/tmp/mcx_vm_sandbox'
                bootstrap.os.makedirs(sandbox_dir, exist_ok=True)
                bootstrap.os.chroot(sandbox_dir)
                bootstrap.os.chdir('/')
                _drop_vm_privileges()
                _VM_SANDBOXED = True
            except (OSError, PermissionError) as _chroot_e:
                if _vm_require_sandbox_effective():
                    bootstrap.sys.stderr.write(f'[VM] FATAL: chroot failed ({_chroot_e}) with require_sandbox=true; refusing to run\n')
                    bootstrap.sys.stderr.flush()
                    bootstrap.sys.exit(1)
                pass
            try:
                bootstrap.os.setsid()
            except OSError:
                pass
    elif bootstrap.sys.platform == 'win32':
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            cur_handle = kernel32.GetCurrentProcess()
            kernel32.SetProcessWorkingSetSize(cur_handle, config.VM_RLIMIT_AS_BYTES, config.VM_RLIMIT_AS_BYTES * 2)
        except Exception:
            pass
    if sync_db is None:
        sync_db = db.SyncDB(db_url)

    class SyncHTLCRepo:

        def __init__(self, db):
            self.db = db
            self.ph = '?' if db.db_url.startswith('sqlite://') else '%s'

        def create(self, htlc):
            cur = self.db.conn.cursor()
            cur.execute(f'INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES ({self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph})', (htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address', ''), htlc.get('status', 'open'), bootstrap.time.time()))
            self.db.conn.commit()

        def get(self, htlc_id):
            cur = self.db.conn.cursor()
            cur.execute(f'SELECT * FROM htlc_contracts WHERE id = {self.ph}', (htlc_id,))
            row = cur.fetchone()
            if row is None:
                return None
            if isinstance(row, dict):
                return row
            columns = [desc[0] for desc in cur.description]
            return dict(zip(columns, row))

        def update_status(self, htlc_id, status, claimed_at=None, refunded_at=None):
            cur = self.db.conn.cursor()
            cur.execute(f'UPDATE htlc_contracts SET status={self.ph}, claimed_at={self.ph}, refunded_at={self.ph} WHERE id={self.ph}', (status, claimed_at, refunded_at, htlc_id))
            self.db.conn.commit()
    htlc_repo = SyncHTLCRepo(sync_db) if sync_db else None

    class DummyRepoProvider:

        def __call__(self):
            return sync_db
    engine = vm.VMExecutionEngine(DummyRepoProvider())
    engine.code_cache = code_cache if code_cache else {}
    engine.balance_cache = balance_cache if balance_cache else {}
    token_cache = {}
    if sync_db:
        cur = sync_db.execute('SELECT token_address, wallet, balance FROM token_balances')
        for token_addr, wallet, bal in cur.fetchall():
            token_cache[token_addr, wallet] = bal
    engine.token_balance_cache = token_cache if token_balance_cache is None else token_balance_cache
    engine.htlc_repo = htlc_repo
    engine.set_block_height(int(block_height or 0))
    engine.set_block_timestamp(block_ts)
    bytecode = bytes.fromhex(bytecode_hex)
    input_data = bytes.fromhex(input_data_hex)
    success, ret, gas_used, logs = engine.execute(bytecode, caller, origin, value, gas_limit, contract_address, input_data, static, initial_storage=storage_cache if storage_cache else {})
    storage_map = {}
    if engine.storage_address:
        storage_map[engine.storage_address] = dict(engine.storage_cache)
    for _addr, _slots in engine.sub_storage.items():
        storage_map.setdefault(_addr, {}).update(_slots)
    return (success, ret.hex(), gas_used, logs, storage_map, engine.balance_cache, engine.token_balance_cache, getattr(engine, '_pending_svf_db_exec', []))

class VMManager:

    def __init__(self, db: db.Database, contract_v2_repo, contract_storage_v2_repo, token_balance_repo, balance_repo, htlc_repo):
        self.db = db
        self.contract_v2_repo = contract_v2_repo
        self.contract_storage_v2_repo = contract_storage_v2_repo
        self.token_balance_repo = token_balance_repo
        self.balance_repo = balance_repo
        self.htlc_repo = htlc_repo
        self.timeout = config.VM_TIMEOUT
        try:
            bootstrap.mp.set_start_method('spawn', force=True)
        except RuntimeError as _le:
            bootstrap.logger.warning(f'[VM] set_start_method(spawn) refused: {str(_le or '?')[:16]}')
        self.pool = self._new_pool()
        self._code_cache: bootstrap.Dict[str, bytes] = {}
        self._code_cache_valid = False

    def _current_block_height(self) -> int:
        return int(getattr(getattr(self, 'node', None), 'height', 0) or 0)

    def _new_pool(self) -> bootstrap.ProcessPoolExecutor:
        return bootstrap.ProcessPoolExecutor(max_workers=4)

    async def _run_vm_subprocess(self, args: tuple, timeout: float):
        loop = bootstrap.asyncio.get_event_loop()
        try:
            return await bootstrap.asyncio.wait_for(loop.run_in_executor(self.pool, run_vm_in_subprocess, *args), timeout=timeout)
        except bootstrap.BrokenProcessPool as _e:
            _old_id = id(self.pool)
            try:
                self.pool.shutdown(wait=False)
            except Exception as _se:
                bootstrap.logger.debug(f'[VM] R4-pool-rebuild: old pool shutdown raised {_se}')
            self.pool = self._new_pool()
            bootstrap.logger.warning(f'[VM] R4-pool-rebuild: pool {_old_id} broken ({_e}); rebuilt {id(self.pool)}, retrying once')
            return await bootstrap.asyncio.wait_for(loop.run_in_executor(self.pool, run_vm_in_subprocess, *args), timeout=timeout)

    async def _journal_write(self, block_id: int, namespace: str, addr: str, key: str, old_value, new_value) -> None:
        try:
            if block_id is None or int(block_id) < 0:
                return
        except (TypeError, ValueError) as _le:
            bootstrap.logger.warning(f'[VM] journal write block_id invalid for {str(namespace or '?')[:16]}:{str(addr or '?')[:16]}: {str(_le or '?')[:16]}')
            return
        if namespace == 'balance' and isinstance(addr, str):
            addr = addr.lower()

        def _s(v):
            return None if v is None else str(v)
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES (?,?,?,?,?,?)', int(block_id), namespace, str(addr), str(key), _s(old_value), _s(new_value))
        else:
            await self.db.execute_dml('INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES ($1,$2,$3,$4,$5,$6)', int(block_id), namespace, str(addr), str(key), _s(old_value), _s(new_value))

    async def execute(self, contract_address: str, caller: str, origin: str, value: int, gas_limit: int, input_data: bytes, static: bool=False, init_code_hex: str=None, block_id: int=-1, block_ts: float=None) -> bootstrap.Tuple[bool, bytes, int, bootstrap.List[bootstrap.Dict]]:
        if init_code_hex is not None:
            bytecode = init_code_hex
        else:
            contract = await self.contract_v2_repo.get(contract_address)
            if not contract:
                return (False, b'', 0, [])
            bytecode = contract['bytecode']
        storage_rows = await self.contract_storage_v2_repo.get_all(contract_address)
        storage_cache = {key: int(value) for key, value in storage_rows.items()}
        if not self._code_cache_valid:
            all_contracts = await self.contract_v2_repo.get_all()
            self._code_cache = {c['address']: bytes.fromhex(c['bytecode']) for c in all_contracts}
            self._code_cache_valid = True
        code_cache = self._code_cache
        input_hex = input_data.hex()
        bytecode_hex = bytecode
        bootstrap.os.environ['MCX_DB_URL'] = self.db._pg_target_dsn if self.db.db_type == 'postgres' else 'sqlite://microcore.db'
        loop = bootstrap.asyncio.get_event_loop()
        block_height = self._current_block_height()
        _exec_ts = block_ts
        if _exec_ts is None and block_height:
            try:
                if self.db.db_type == 'sqlite':
                    _ts_row = await self.db.fetchrow('SELECT ts FROM blocks WHERE id = ?', block_height)
                else:
                    _ts_row = await self.db.fetchrow('SELECT ts FROM blocks WHERE id = $1', block_height)
                if _ts_row is not None:
                    try:
                        _exec_ts = _ts_row['ts']
                    except (TypeError, KeyError, IndexError):
                        _exec_ts = _ts_row[0]
            except Exception:
                _exec_ts = None
        if _exec_ts is None and static:
            _exec_ts = bootstrap.time.time()
        try:
            balance_cache = {}
            for addr in {caller, origin, contract_address}:
                if addr:
                    balance_cache[addr] = await self.balance_repo.get(addr)
            if svf_keys.SVF_KEY_FILE:
                bootstrap.os.environ['MCX_SVF_FILE'] = svf_keys.SVF_KEY_FILE
            bootstrap.os.environ['MCX_PRUNE_BLOCKS'] = str(int(config.PRUNE_BLOCKS))
            result = await self._run_vm_subprocess((bytecode_hex, caller, origin, value, gas_limit, contract_address, input_hex, static, storage_cache, code_cache, balance_cache, None, None, block_height, _exec_ts), timeout=self.timeout)
            _svf_pending_ops = []
            success, ret_hex, gas_used, logs, updated_storage, updated_balance, updated_token_balance = result[:7]
            if len(result) > 7 and isinstance(result[7], list):
                _svf_pending_ops = result[7]
            if not success:
                bootstrap.logger.warning(f'[VM] Execution failed for {contract_address}: gas={gas_used}/{gas_limit} ret={ret_hex!r} logs={logs!r}')
                return (False, b'', gas_used, logs)
            if not static:
                async with await self.db.transaction():
                    if updated_storage:
                        main_slots = updated_storage.get(contract_address, {})
                        for key, val in main_slots.items():
                            if val != storage_cache.get(key, 0):
                                _old = storage_cache[key] if key in storage_cache else None
                                await self._journal_write(block_id, 'storage', contract_address, key, _old, str(val))
                                await self.contract_storage_v2_repo.set(contract_address, key, str(val))
                        for addr, slots in updated_storage.items():
                            if addr == contract_address:
                                continue
                            for key, val in slots.items():
                                try:
                                    _old_o = await self.contract_storage_v2_repo.get(addr, key)
                                except Exception:
                                    _old_o = None
                                await self._journal_write(block_id, 'storage', addr, key, _old_o, str(val))
                                await self.contract_storage_v2_repo.set(addr, key, str(val))
                    if updated_balance:
                        for addr, bal in updated_balance.items():
                            current = await self.balance_repo.get(addr)
                            if current != bal:
                                await self._journal_write(block_id, 'balance', addr, 'bal', current, bal)
                                await self.balance_repo.set(addr, bal)
                    if updated_token_balance:
                        for (token_addr, wallet), bal in updated_token_balance.items():
                            current = await self.token_balance_repo.get(token_addr, wallet)
                            if current != bal:
                                await self._journal_write(block_id, 'token_balance', token_addr, wallet, current, bal)
                                await self.token_balance_repo.set(token_addr, wallet, bal)
                    if _svf_pending_ops:
                        for _svf_q, _svf_params in _svf_pending_ops:
                            await self.db.execute_dml(_svf_q, *_svf_params)
                            if 'INSERT INTO svf_profiles' in str(_svf_q):
                                try:
                                    _svf_tok = str(_svf_params[0]).lower()
                                    _svf_prof = svf.svf_parse_profile(bytes.fromhex(str(_svf_params[5])))
                                    _node = getattr(self, 'node', None)
                                    if _node is not None and hasattr(_node, 'svf_profiles'):
                                        _node.svf_profiles[_svf_tok] = _svf_prof
                                except Exception:
                                    pass
            return (success, bytes.fromhex(ret_hex) if ret_hex else b'', gas_used, logs)
        except bootstrap.asyncio.TimeoutError:
            bootstrap.logger.warning(f'[VM] Execution timed out for contract {contract_address}')
            return (False, b'', 0, [])
        except Exception as e:
            bootstrap.logger.error(f'[VM] Execution error: {e}', exc_info=True)
            return (False, b'', 0, [])

    def close(self):
        try:
            self.pool.shutdown(wait=False)
        except Exception as _le:
            bootstrap.logger.warning(f'[VM] pool shutdown failed: {str(_le or '?')[:16]}')
