import bootstrap
import config
import crypto
import util
import maze
import maze as _maze
import gas
import svf_keys
import svf
import db
import repos
import core

class ConsensusRng:

    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0

    def bytes(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            output.extend(bootstrap.eth_keccak(b'MCXPOGRNGV1' + self.seed + self.counter.to_bytes(8, 'big')))
            self.counter += 1
        return bytes(output[:length])

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError('upper must be positive')
        limit = (1 << 256) - (1 << 256) % upper
        while True:
            value = int.from_bytes(self.bytes(32), 'big')
            if value < limit:
                return value % upper

class PoSWConsensus:
    DIRS = maze.DIRS_3D

    def __init__(self, node):
        self.node = node
        self.round_active = False
        self.block_id = -1
        self.epoch = 0
        self._move_locks: bootstrap.Dict[str, bootstrap.asyncio.Lock] = {}
        self._inflight_moves: dict = {}
        self._move_queues: dict = {}
        self._move_executor = bootstrap.ThreadPoolExecutor(max_workers=4, thread_name_prefix='move')
        self._watchdog_task = None
        self._height_last_advanced = bootstrap.time.time()
        self._catch_times = bootstrap.deque(maxlen=20)
        self.block_times = bootstrap.deque(maxlen=20)
        self.db = node.db
        self.block_repo = node.block_repo
        self.tx_repo = node.tx_repo
        self.miner_repo = node.miner_repo
        self.balance_repo = node.balance_repo
        self.network_state_repo = node.network_state_repo
        self.receipt_repo = node.receipt_repo
        self.maze_repo = node.maze_repo
        self.maze_attestation_repo = getattr(node, 'maze_attestation_repo', None) or repos.MazeAttestationRepo(self.db)
        self.maze_proof_repo = getattr(node, 'maze_proof_repo', None) or repos.MazeProofRepo(self.db)
        self.mempool = node.mempool
        self.finality_repo = node.finality_repo
        self.vm_manager = node.vm_manager
        self.epoch_length = config.EPOCH_LENGTH
        self._pending_pow: bootstrap.Dict[str, bootstrap.Tuple[str, int, float]] = {}
        self._pending_maze_updates: bootstrap.List[bootstrap.Dict] = []
        self._pending_slashes: bootstrap.List[bootstrap.Dict] = []
        self._deferred_slashes: bootstrap.List[bootstrap.Dict] = []
        self._pending_svf_certificates: bootstrap.List[bootstrap.Dict] = []
        self._maze_visited: bootstrap.Dict[str, bootstrap.Set[bootstrap.Tuple[int, int, int]]] = {}
        self._sealed_walls: bootstrap.Dict[str, set] = {}
        self._goal_move_nonce: bootstrap.Dict[str, int] = {}
        self._goal_prev_pos: bootstrap.Dict[str, bootstrap.Tuple[int, int, int]] = {}
        self._goal_recent: bootstrap.Dict[str, bootstrap.deque] = {}
        self._goal_flee_cooldown: bootstrap.Dict[str, int] = {}
        self._pos_history: bootstrap.Dict[str, bootstrap.deque] = {}
        self._oscillating_mazes: bootstrap.Set[str] = set()
        self._ghost_frozen_target: bootstrap.Dict[str, bootstrap.Tuple[int, int, int]] = {}
        self._ghost_cycle: bootstrap.Dict[str, list] = {}
        self._ghost_cycle_idx: bootstrap.Dict[str, int] = {}
        self._maze_cache: bootstrap.OrderedDict = bootstrap.OrderedDict()
        self._maze_cache_max = 256
        self._global_avg_size: float = 5.0
        self._lottery_commits: bootstrap.Dict[int, bootstrap.Dict[str, str]] = {}
        self._lottery_reveals: bootstrap.Dict[int, bootstrap.Dict[str, str]] = {}
        self.lottery_repo = getattr(node, 'lottery_repo', None) or repos.LotteryRepo(self.db)
        self.slash_repo = getattr(node, 'slash_repo', None) or repos.SlashRepo(self.db)
        self._signing_refusals: bootstrap.Dict[str, int] = {}

    def _lock_for(self, maze_id: str) -> bootstrap.asyncio.Lock:
        return self._move_locks.setdefault(maze_id, bootstrap.asyncio.Lock())

    async def _committed_maze_rows(self) -> list:
        rows = await self.maze_repo.get_all()
        attested = {str(r.get('maze_id', '')).lower() for r in await self.maze_attestation_repo.get_all() or []}
        out = []
        for _r in rows or []:
            if isinstance(_r, dict) and str(_r.get('maze_id', '')).lower() in attested:
                out.append(_r)
        return out

    async def _final_maze_rows(self, pending_updates) -> list:
        rows = await self._committed_maze_rows()
        by_id = {}
        order = []
        for _r in rows or []:
            if not isinstance(_r, dict):
                continue
            _mid = str(_r.get('maze_id') or '')
            if not _mid:
                continue
            if _mid not in by_id:
                order.append(_mid)
            by_id[_mid] = dict(_r)
        for _u in pending_updates or []:
            if not isinstance(_u, dict):
                continue
            _mid = str(_u.get('maze_id') or _u.get('miner_id') or '')
            if not _mid:
                continue
            _row = by_id.get(_mid)
            if _row is None:
                _row = {'maze_id': _mid, 'minerid': str(_u.get('miner_id') or _mid), 'size': config.MIN_MAZE_SIZE, 'walldensityppm': maze.MIN_WALL_DENSITY_PPM, 'seed': '', 'goalx': 0, 'goaly': 0, 'goalz': 0}
                by_id[_mid] = _row
                order.append(_mid)
            if 'seed' in _u:
                _row['seed'] = _u['seed']
            if 'new_density' in _u:
                _row['walldensityppm'] = _u['new_density']
            if 'goal' in _u and isinstance(_u['goal'], (list, tuple)) and (len(_u['goal']) == 3):
                _row['goalx'], _row['goaly'], _row['goalz'] = _u['goal']
            if 'new_size' in _u:
                _sz = maze._valid_maze_size(_u['new_size'])
                if _sz is not None and _sz <= int(_row.get('size', config.MIN_MAZE_SIZE)) + 1:
                    _row['size'] = _sz
            if 'mazeroot' in _u:
                _row['mazeroot'] = _u['mazeroot']
            if 'spawn' in _u and isinstance(_u['spawn'], (list, tuple)) and (len(_u['spawn']) == 3):
                _row['posx'], _row['posy'], _row['posz'] = _u['spawn']
            if 'turbulenceppm' in _u:
                _row['turbulenceppm'] = _u['turbulenceppm']
            if 'new_growthcount' in _u:
                _row['growthcount'] = _u['new_growthcount']
            if 'knowledge' in _u:
                _row['knowledge'] = _u['knowledge']
            if 'miner_id' in _u and _u['miner_id']:
                _row['minerid'] = _u['miner_id']
        return [by_id[_m] for _m in order]

    async def _ancestor_timestamps(self, block_id: int) -> list:
        _anc = []
        for _h in range(max(0, int(block_id) - util.MEDIAN_WINDOW_BLOCKS), int(block_id)):
            _ar = await self.block_repo.get_by_id(_h)
            if _ar and _ar.get('ts'):
                _anc.append(_ar.get('ts'))
        return _anc

    async def _produce_timestamp_ok(self, block_id: int, ts) -> bool:
        try:
            _ts = float(ts)
            _bid = int(block_id)
        except (TypeError, ValueError, OverflowError):
            return False
        if _bid <= 0:
            return True
        try:
            _anc = await self._ancestor_timestamps(_bid)
            if not _anc:
                if maze._seal_ts_log_due('missing'):
                    bootstrap.logger.error(f'[SEAL-TS-FAILCLOSED-1] block {block_id}: no ancestor timestamps found — timestamp unverifiable, deferring seal')
                return False
            return util._block_timestamp_ok(_ts, _anc)
        except (OverflowError, ArithmeticError):
            return False

    @staticmethod
    def _maze_weight(size: int) -> int:
        if size <= 5:
            return 0
        return size ** 3 - 125

    def _apply_shrink(self, row: dict, current_height: int=None) -> dict:
        last_height = int(row.get('lastactiveheight', 0))
        height = current_height if current_height is not None else 0
        if height <= last_height:
            return row
        raw_steps = (height - last_height) // config.SHRINK_INTERVAL
        if raw_steps <= 0:
            return row
        size = int(row['size'])
        if size <= config.MIN_MAZE_SIZE:
            return row
        per_step = maze.OFFLINE_DECAY_RATE * maze.GLOBAL_SHRINK_FACTOR
        total_loss = per_step * raw_steps
        if total_loss < 1.0:
            return row
        loss = int(total_loss)
        new_size = max(config.MIN_MAZE_SIZE, size - loss)
        actual_loss = size - new_size
        if actual_loss <= 0:
            return row
        new_row = dict(row)
        new_row['size'] = new_size
        _nmax = new_size - 1
        for _k in ('posx', 'posy', 'posz', 'goalx', 'goaly', 'goalz'):
            new_row[_k] = max(0, min(int(row.get(_k, 0)), _nmax))
        if (new_row['posx'], new_row['posy'], new_row['posz']) == (new_row['goalx'], new_row['goaly'], new_row['goalz']):
            new_row['posx'] = max(0, new_row['goalx'] - 1)
        new_row['walldensityppm'] = max(maze.MIN_WALL_DENSITY_PPM, int(row['walldensityppm']) - actual_loss * 15000)
        new_row['turbulenceppm'] = max(0, int(row['turbulenceppm'] * 0.85 ** actual_loss))
        return new_row

    def _compute_new_maze_params(self, row: dict, catch_height: int, entropy: bytes) -> dict:
        newsize = int(row['size']) + 1
        avg = self._global_avg_size
        newdensity = int(maze.BASE_DENSITY_PPM + avg ** 1.5 * 200)
        newturb = int(maze.BASE_TURBULENCE_PPM + avg ** 1.5 * 50)
        newseed = bootstrap.eth_keccak(b'MCXPOGGROWTHV1' + bytes.fromhex(row['seed']) + entropy + row['minerid'].encode() + int(row['growthcount'] + 1).to_bytes(8, 'big')).hex()
        return {'size': newsize, 'walldensityppm': newdensity, 'turbulenceppm': newturb, 'seed': newseed, 'growthcount': int(row['growthcount']) + 1, 'consecutivewallhits': 0, 'lastgoalheight': catch_height}

    def _select_open_cell(self, maze, seed_bytes: bytes, exclude: bootstrap.Tuple[int, int, int]=None) -> bootstrap.Tuple[int, int, int]:
        open_cells = _maze.Maze3DGenerator.open_cells(maze)
        if not open_cells:
            return (0, 0, 0)
        if exclude and len(open_cells) > 1:
            open_cells = [c for c in open_cells if c != exclude]
        idx = int.from_bytes(bootstrap.eth_keccak(b'MCXPOGGOALV1' + seed_bytes), 'big') % len(open_cells)
        return open_cells[idx]

    def _select_spawn(self, maze, prev_pos: bootstrap.Tuple[int, int, int], seed_bytes: bytes) -> bootstrap.Tuple[int, int, int]:
        open_cells = _maze.Maze3DGenerator.open_cells(maze)
        if not open_cells:
            return (0, 0, 0)
        if prev_pos in open_cells:
            return prev_pos
        return open_cells[int.from_bytes(bootstrap.eth_keccak(b'MCXPOGSPAWNV1' + seed_bytes), 'big') % len(open_cells)]

    def _generate_deterministic_maze(self, seed_hex: str, size: int, density_ppm: int, turb_ppm: int, block_height: int=0) -> maze.SparseMaze:
        _size = _maze._valid_maze_size(size)
        if _size is None:
            raise ValueError(f'refusing to generate maze with invalid size {size!r}')
        size = _size
        cache_key = (seed_hex, size, density_ppm, turb_ppm)
        if cache_key in self._maze_cache:
            self._maze_cache.move_to_end(cache_key)
            return self._maze_cache[cache_key]
        rng = ConsensusRng(bytes.fromhex(seed_hex))
        density = density_ppm / 1000000.0
        maze = [[[True] * size for _ in range(size)] for _ in range(size)]

        def carve(x0, y0, z0, x1, y1, z1):
            width, depth, height = (x1 - x0, y1 - y0, z1 - z0)
            if min(width, depth, height) <= 2:
                for z in range(z0, z1):
                    for y in range(y0, y1):
                        for x in range(x0, x1):
                            maze[z][y][x] = False
                return
            axis = 0
            max_dim = width
            if depth > max_dim:
                axis = 1
                max_dim = depth
            if height > max_dim:
                axis = 2
            bounds = [(x0, x1), (y0, y1), (z0, z1)]
            low, high = bounds[axis]
            split = rng.randbelow(high - low - 2) + low + 1
            bounds_a = [list(b) for b in bounds]
            bounds_b = [list(b) for b in bounds]
            bounds_a[axis][1] = split
            bounds_b[axis][0] = split + 1
            carve(bounds_a[0][0], bounds_a[1][0], bounds_a[2][0], bounds_a[0][1], bounds_a[1][1], bounds_a[2][1])
            carve(bounds_b[0][0], bounds_b[1][0], bounds_b[2][0], bounds_b[0][1], bounds_b[1][1], bounds_b[2][1])
            px = rng.randbelow(x1 - x0) + x0
            py = rng.randbelow(y1 - y0) + y0
            pz = rng.randbelow(z1 - z0) + z0
            passage = [px, py, pz]
            passage[axis] = split
            maze[passage[2]][passage[1]][passage[0]] = False
            adj = list(passage)
            adj[axis] += 1
            maze[adj[2]][adj[1]][adj[0]] = False
        carve(0, 0, 0, size, size, size)
        maze[0][0][0] = False
        maze[size - 1][size - 1][size - 1] = False
        if not _maze.Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
            bootstrap.logger.warning(f'[Maze] BSP carve not connected for size={size}, retrying with dense fill fallback')
            maze = [[[True] * size for _ in range(size)] for _ in range(size)]
            for z in range(size):
                for y in range(size):
                    for x in range(size):
                        maze[z][y][x] = False
            maze[0][0][0] = False
            maze[size - 1][size - 1][size - 1] = False
        density_ratio = max(0.25, min(0.9, density_ppm / 1000000.0))
        open_cells = [(x, y, z) for z in range(size) for y in range(size) for x in range(size) if not maze[z][y][x] and (x, y, z) not in ((0, 0, 0), (size - 1, size - 1, size - 1))]
        for i in range(len(open_cells) - 1, 0, -1):
            j = rng.randbelow(i + 1)
            open_cells[i], open_cells[j] = (open_cells[j], open_cells[i])
        extra = int(len(open_cells) * density_ratio)
        for x, y, z in open_cells[:extra]:
            maze[z][y][x] = True
            if not _maze.Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                maze[z][y][x] = False
        corridor_threshold = 2
        corridor_chance = 95
        for axis in range(3):
            for a in range(size):
                for b in range(size):
                    run = 0
                    for c in range(size):
                        coords = [0, 0, 0]
                        coords[axis] = c
                        coords[(axis + 1) % 3] = a
                        coords[(axis + 2) % 3] = b
                        x, y, z = coords
                        if not maze[z][y][x]:
                            run += 1
                            if run >= corridor_threshold and rng.randbelow(100) < corridor_chance:
                                if (x, y, z) not in [(0, 0, 0), (size - 1, size - 1, size - 1)]:
                                    maze[z][y][x] = True
                                    if not _maze.Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                                        maze[z][y][x] = False
                                    run = 0
                        else:
                            run = 0
        if not _maze.Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
            bootstrap.logger.warning(f'[Maze] Final connectivity check failed for size={size}, reverting extra walls')
            maze = [[[False] * size for _ in range(size)] for _ in range(size)]
            for z in range(size):
                for y in range(size):
                    for x in range(size):
                        maze[z][y][x] = False
            maze[0][0][0] = False
            maze[size - 1][size - 1][size - 1] = False
        sparse = _maze.dense_to_sparse(maze)
        if len(self._maze_cache) >= self._maze_cache_max:
            self._maze_cache.popitem(last=False)
        self._maze_cache[cache_key] = sparse
        return sparse

    def _calculate_maze_root(self, maze) -> str:
        if isinstance(maze, _maze.SparseMaze):
            flat = bytearray()
            for z in range(maze.size):
                for y in range(maze.size):
                    for x in range(maze.size):
                        flat.append(1 if (x, y, z) in maze.walls else 0)
        else:
            flat = bytearray()
            for z in range(len(maze)):
                for y in range(len(maze[z])):
                    for x in range(len(maze[z][y])):
                        flat.append(1 if maze[z][y][x] else 0)
        return bootstrap.eth_keccak(bytes(flat)).hex()

    async def get_active_miners(self) -> bootstrap.List[bootstrap.Dict]:
        miners = await self.miner_repo.get_active()
        return [miner for miner in miners if miner.get('miner_id') in self.node.miner_websockets]

    async def get_active_miner_ids(self) -> bootstrap.List[str]:
        miners = await self.get_active_miners()
        return [m['miner_id'] for m in miners]

    @staticmethod
    def _ghost_tuple(row) -> bootstrap.Optional[tuple]:
        if not row:
            return None
        gx, gy, gz = (row.get('ghostx'), row.get('ghosty'), row.get('ghostz'))
        if gx is None or gy is None or gz is None:
            return None
        return (int(gx), int(gy), int(gz))

    @staticmethod
    def _set_ghost(d: dict, ghost) -> None:
        if ghost is None:
            d['ghostx'] = None
            d['ghosty'] = None
            d['ghostz'] = None
        else:
            d['ghostx'] = int(ghost[0])
            d['ghosty'] = int(ghost[1])
            d['ghostz'] = int(ghost[2])

    @staticmethod
    def _move_auth_bytes(miner_id: str, maze_id_val: str, growthcount, move_nonce, direction: str) -> bytes:
        return crypto.canonical_json_bytes({'domain': 'MCXPOGMOVEV1', 'chainid': config.CHAIN_ID, 'minerid': miner_id, 'mazeid': maze_id_val, 'mazeversion': int(growthcount), 'movenonce': int(move_nonce), 'direction': direction})

    async def process_move(self, miner_id: str, maze_id: str, direction: str, signature: str, move_nonce: int=None) -> bootstrap.Tuple[bool, str, dict]:
        async with self._lock_for(maze_id):
            if direction not in self.DIRS:
                return (False, 'Invalid direction', {})
            miner = await self.miner_repo.get(miner_id)
            if not miner:
                return (False, 'Unknown miner', {})
            row = await self.maze_repo.get_for_miner(miner_id, maze_id)
            if not row:
                return (False, 'No maze state', {})
            if str(row.get('minerid') or '') != str(miner_id):
                bootstrap.logger.warning(f'[MAZE-OWNER-1] move rejected: signer {str(miner_id)[:16]} does not own maze {str(maze_id)[:16]}')
                return (False, 'Maze not owned by signer', {})
            expected_nonce = int(row['movenonce']) + 1
            if move_nonce is not None and move_nonce != expected_nonce:
                return (False, f'Nonce mismatch: expected {expected_nonce}, got {move_nonce}', {})
            move_nonce = expected_nonce
            auth_msg = self._move_auth_bytes(miner_id, maze_id, row['growthcount'], move_nonce, direction)
            if not crypto.verify_signature_bytes(miner['pub'], auth_msg, signature):
                bootstrap.logger.warning(f'[SIG FAIL] minerid={miner_id} mazeid={row.get('maze_id')} growthcount={row['growthcount']} movenonce={move_nonce} dir={direction} chainid={config.CHAIN_ID}')
                bootstrap.logger.warning(f'[SIG FAIL] pub={miner['pub']} sig={signature[:32]}... auth_msg={auth_msg}')
                return (False, 'Invalid signature', {})
            if maze_id in self._pending_pow:
                seed, difficulty, ts = self._pending_pow[maze_id]
                if bootstrap.time.time() - ts > 60:
                    self._pending_pow.pop(maze_id, None)
                else:
                    return (False, 'Wall hit', {'type': 'wall_hit', 'seed': seed, 'difficulty': difficulty})
            size = int(row['size'])
            sx, sy, sz = (int(row['posx']), int(row['posy']), int(row['posz']))
            dx, dy, dz = self.DIRS[direction]
            nx, ny, nz = (sx + dx, sy + dy, sz + dz)
            maze_seed = bytes.fromhex(row['seed'])
            loop = bootstrap.asyncio.get_event_loop()
            maze = await loop.run_in_executor(None, self._generate_deterministic_maze, row['seed'], size, int(row['walldensityppm']), int(row['turbulenceppm']), self.node.height)
            if not (0 <= nx < size and 0 <= ny < size and (0 <= nz < size)):
                return (False, 'Out of bounds', {})
            if maze[nz][ny][nx]:
                wall_seed = bootstrap.eth_keccak(b'MCXPOGWALLV1' + bytes.fromhex(row['mazeroot']) + miner_id.encode() + move_nonce.to_bytes(8, 'big') + bytes((nx, ny, nz))).hex()
                difficulty = int(POW_BASE_DIFFICULTY + max(0, self._global_avg_size - 5) * _maze.GROWTH_DIFFICULTY_EXP)
                row['consecutivewallhits'] = int(row['consecutivewallhits']) + 1
                await self.maze_repo.upsert({**dict(row), 'updatedat': int(bootstrap.time.time())})
                self._pending_pow[maze_id] = (wall_seed, difficulty, bootstrap.time.time())
                ghost_pos = self._ghost_tuple(row)
                if ghost_pos:
                    gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, (sx, sy, sz))
                    if gdx is not None:
                        new_gpos = (ghost_pos[0] + gdx, ghost_pos[1] + gdy, ghost_pos[2] + gdz)
                        self._set_ghost(row, new_gpos)
                        await self.maze_repo.upsert({**dict(row), 'updatedat': int(bootstrap.time.time())})
                        if new_gpos == (sx, sy, sz):
                            restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                            if restart_ev:
                                self._set_ghost(row, self._ghost_tuple(restart_ev))
                                await self.maze_repo.upsert({**dict(row), **restart_ev})
                                ghost_update = {'maze_id': row.get('maze_id') or miner_id, 'miner_id': miner_id, 'height': self.node.height, 'old_size': size, 'new_size': restart_ev.get('size', size), 'old_density': int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM)), 'new_density': restart_ev.get('walldensityppm', int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM))), 'seed': restart_ev.get('seed', row['seed']), 'mazeroot': restart_ev.get('mazeroot', row.get('mazeroot', '')), 'goal': [restart_ev.get('goalx', row['goalx']), restart_ev.get('goaly', row['goaly']), restart_ev.get('goalz', row['goalz'])], 'spawn': [restart_ev.get('posx', row['posx']), restart_ev.get('posy', row['posy']), restart_ev.get('posz', row['posz'])], 'turbulenceppm': restart_ev.get('turbulenceppm', 0)}
                                self._pending_maze_updates.append(ghost_update)
                resp_ghost = self._ghost_tuple(row)
                return (False, 'Wall hit', {'type': 'wall_hit', 'seed': wall_seed, 'difficulty': difficulty, 'ghost': list(resp_ghost) if resp_ghost else None, 'position': [sx, sy, sz], 'size': size, 'movenonce': int(row['movenonce']), 'growthcount': int(row['growthcount'])})
            gx, gy, gz = (int(row['goalx']), int(row['goaly']), int(row['goalz']))
            updated = dict(row)
            updated['posx'] = nx
            updated['posy'] = ny
            updated['posz'] = nz
            updated['movenonce'] = move_nonce
            updated['consecutivewallhits'] = 0
            updated['lastactiveheight'] = self.node.height
            updated['updatedat'] = int(bootstrap.time.time())
            pos_hist = self._pos_history.setdefault(maze_id, bootstrap.deque(maxlen=6))
            pos_hist.append((nx, ny, nz))
            detected = False
            if len(pos_hist) >= 4:
                a, b, c, d = list(pos_hist)[-4:]
                if a == c and b == d and (a != b):
                    detected = True
            if not detected and len(pos_hist) >= 6:
                p1, p2, p3, p4, p5, p6 = list(pos_hist)[-6:]
                if p1 == p4 and p2 == p5 and (p3 == p6) and (len({p1, p2, p3}) == 3):
                    detected = True
            if detected:
                self._oscillating_mazes.add(maze_id)
            elif (nx, ny, nz) != (sx, sy, sz):
                self._oscillating_mazes.discard(maze_id)
            caught = nx == gx and ny == gy and (nz == gz)
            state_info = {'type': 'mazemove', 'minerid': miner_id, 'position': (nx, ny, nz), 'movenonce': move_nonce, 'caught': caught}
            if caught:
                new_params = self._compute_new_maze_params(dict(row), self.node.height, bootstrap.eth_keccak(direction.encode() + move_nonce.to_bytes(8, 'big')))
                updated.update(new_params)
                knowledge_val = int(row.get('knowledge', 0)) + max(1, int(size * 0.5))
                new_density_ppm = min(900000, int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM)) + knowledge_val * 15000 + size * 4000)
                updated['knowledge'] = knowledge_val
                updated['walldensityppm'] = new_density_ppm
                new_maze = await loop.run_in_executor(None, self._generate_deterministic_maze, new_params['seed'], new_params['size'], new_density_ppm, new_params['turbulenceppm'], self.node.height)
                new_root = self._calculate_maze_root(new_maze)
                new_spawn = self._select_spawn(new_maze, (nx, ny, nz), bytes.fromhex(new_params['seed']))
                new_goal = self._select_open_cell(new_maze, bytes.fromhex(new_params['seed']), exclude=new_spawn)
                updated['mazeroot'] = new_root
                updated['goalx'], updated['goaly'], updated['goalz'] = new_goal
                updated['posx'], updated['posy'], updated['posz'] = new_spawn
                state_info['newsize'] = new_params['size']
                state_info['newgoal'] = new_goal
                state_info['newspawn'] = new_spawn
                state_info['new_growthcount'] = new_params['growthcount']
                state_info['new_movenonce'] = updated['movenonce']
                maze_update_event = {'maze_id': row.get('maze_id') or miner_id, 'miner_id': miner_id, 'height': self.node.height, 'old_size': size, 'new_size': new_params['size'], 'old_density': int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM)), 'new_density': new_density_ppm, 'old_growthcount': int(row['growthcount']), 'new_growthcount': new_params.get('growthcount', int(row['growthcount'])), 'knowledge': knowledge_val, 'seed': new_params['seed'], 'mazeroot': new_root, 'goal': list(new_goal), 'spawn': list(new_spawn), 'turbulenceppm': new_params.get('turbulenceppm', 0), 'caught_at_nonce': move_nonce, 'caught_by_direction': direction, 'parent_mazeroot': row['mazeroot'], 'parent_size': size, 'parent_pos': [sx, sy, sz], 'parent_goal': [gx, gy, gz], 'parent_seed': row['seed'], 'parent_density': int(row['walldensityppm']), 'parent_turbulence': int(row['turbulenceppm']), 'parent_pos_attested': [int(row['posx']), int(row['posy']), int(row['posz'])], 'parent_movenonce': int(row['movenonce'])}
                self._pending_maze_updates.append(maze_update_event)
                new_maze_id = row.get('maze_id') or miner_id
                self._maze_visited.pop(new_maze_id, None)
                self._goal_prev_pos.pop(new_maze_id, None)
                self._goal_recent.pop(new_maze_id, None)
                self._pos_history.pop(new_maze_id, None)
                self._oscillating_mazes.discard(new_maze_id)
                self._ghost_frozen_target.pop(new_maze_id, None)
                self._ghost_cycle.pop(new_maze_id, None)
                self._ghost_cycle_idx.pop(new_maze_id, None)
                if new_params['size'] > 5:
                    _new_ghost = (new_params['size'] - 1, new_params['size'] - 1, new_params['size'] - 1) if new_spawn == (0, 0, 0) else (0, 0, 0)
                else:
                    _new_ghost = None
                self._set_ghost(updated, _new_ghost)
                self._set_ghost(row, _new_ghost)
                self._sealed_walls.pop(new_maze_id, None)
                try:
                    cur_block = self.node.height + 1
                    await self.node.db.execute_dml('INSERT OR REPLACE INTO pending_maze_updates (block_id,minerid,update_json) VALUES (?,?,?)', cur_block, miner_id, bootstrap.json.dumps(maze_update_event, default=str))
                except Exception:
                    pass
            else:
                maze_id = row.get('maze_id') or miner_id
                self._maze_visited.setdefault(maze_id, set()).add((nx, ny, nz))
                flee_interval = max(5, size * 2)
                last_flee = self._goal_flee_cooldown.get(maze_id, 0)
                if move_nonce - last_flee >= flee_interval:
                    prev_goal = self._goal_prev_pos.get(maze_id)
                    new_goal = self._maybe_flee_goal(maze, (nx, ny, nz), (gx, gy, gz), maze_id, size, move_nonce)
                    if new_goal is not None and new_goal != (gx, gy, gz) and (new_goal != prev_goal):
                        updated['goalx'], updated['goaly'], updated['goalz'] = new_goal
                        state_info['goal'] = new_goal
                        state_info['goal_moved'] = True
                        self._goal_flee_cooldown[maze_id] = move_nonce
                ghost_pos = self._ghost_tuple(row)
                if ghost_pos and ghost_pos != (gx, gy, gz):
                    if ghost_pos == (nx, ny, nz):
                        restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                        if restart_ev:
                            updated.update(restart_ev)
                            state_info['caught'] = True
                    elif maze_id in self._oscillating_mazes:
                        if maze_id not in self._ghost_cycle:
                            cycle_cells = []
                            for p in self._pos_history.get(maze_id, []):
                                if p not in cycle_cells:
                                    cycle_cells.append(p)

                            def _manh(a, b):
                                return abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
                            farthest_idx = max(range(len(cycle_cells)), key=lambda i: _manh(ghost_pos, cycle_cells[i]))
                            self._ghost_cycle[maze_id] = cycle_cells
                            self._ghost_cycle_idx[maze_id] = farthest_idx
                            self._ghost_frozen_target[maze_id] = cycle_cells[farthest_idx]
                        cycle_cells = self._ghost_cycle[maze_id]
                        idx = self._ghost_cycle_idx[maze_id]
                        target = cycle_cells[idx]
                        if ghost_pos == target:
                            idx = (idx + 1) % len(cycle_cells)
                            self._ghost_cycle_idx[maze_id] = idx
                            target = cycle_cells[idx]
                        moved = False
                        for _ in range(2):
                            gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, target)
                            if gdx is None:
                                break
                            ghost_pos = (ghost_pos[0] + gdx, ghost_pos[1] + gdy, ghost_pos[2] + gdz)
                            self._set_ghost(updated, ghost_pos)
                            self._set_ghost(row, ghost_pos)
                            moved = True
                            if ghost_pos == (nx, ny, nz):
                                break
                        if moved:
                            state_info['ghost'] = ghost_pos
                        if ghost_pos == (nx, ny, nz):
                            restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                            if restart_ev:
                                updated.update(restart_ev)
                                state_info['caught'] = True
                                ghost_update = {'maze_id': row.get('maze_id') or miner_id, 'miner_id': miner_id, 'height': self.node.height, 'old_size': size, 'new_size': restart_ev.get('size', size), 'old_density': int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM)), 'new_density': restart_ev.get('walldensityppm', int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM))), 'seed': restart_ev.get('seed', row['seed']), 'mazeroot': restart_ev.get('mazeroot', row.get('mazeroot', '')), 'goal': [restart_ev.get('goalx', row['goalx']), restart_ev.get('goaly', row['goaly']), restart_ev.get('goalz', row['goalz'])], 'spawn': [restart_ev.get('posx', row['posx']), restart_ev.get('posy', row['posy']), restart_ev.get('posz', row['posz'])], 'turbulenceppm': restart_ev.get('turbulenceppm', 0)}
                                self._pending_maze_updates.append(ghost_update)
                    else:
                        self._ghost_frozen_target.pop(maze_id, None)
                        self._ghost_cycle.pop(maze_id, None)
                        self._ghost_cycle_idx.pop(maze_id, None)
                        gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, (nx, ny, nz))
                        if gdx is not None:
                            new_ghost = (ghost_pos[0] + gdx, ghost_pos[1] + gdy, ghost_pos[2] + gdz)
                            self._set_ghost(updated, new_ghost)
                            self._set_ghost(row, new_ghost)
                            state_info['ghost'] = new_ghost
                            if new_ghost == (nx, ny, nz):
                                restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                                if restart_ev:
                                    updated.update(restart_ev)
                                    state_info['caught'] = True
                                    ghost_update = {'maze_id': row.get('maze_id') or miner_id, 'miner_id': miner_id, 'height': self.node.height, 'old_size': size, 'new_size': restart_ev.get('size', size), 'old_density': int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM)), 'new_density': restart_ev.get('walldensityppm', int(row.get('walldensityppm', _maze.MIN_WALL_DENSITY_PPM))), 'seed': restart_ev.get('seed', row['seed']), 'mazeroot': restart_ev.get('mazeroot', row.get('mazeroot', '')), 'goal': [restart_ev.get('goalx', row['goalx']), restart_ev.get('goaly', row['goaly']), restart_ev.get('goalz', row['goalz'])], 'spawn': [restart_ev.get('posx', row['posx']), restart_ev.get('posy', row['posy']), restart_ev.get('posz', row['posz'])], 'turbulenceppm': restart_ev.get('turbulenceppm', 0)}
                                    self._pending_maze_updates.append(ghost_update)
                if size > 6:
                    seal_interval = max(3, size * 2)
                    if move_nonce % seal_interval == 0:
                        sealed_set = self._sealed_walls.setdefault(maze_id, set())
                        dense_maze = _maze.sparse_to_dense(maze)
                        seal_candidates = []
                        for ddx, ddy, ddz in _maze.DIRS_3D.values():
                            cx, cy, cz = (nx + ddx, ny + ddy, nz + ddz)
                            if 0 <= cx < size and 0 <= cy < size and (0 <= cz < size) and (not dense_maze[cz][cy][cx]):
                                if (cx, cy, cz) != (nx, ny, nz) and (cx, cy, cz) != (gx, gy, gz) and ((cx, cy, cz) != ghost_pos):
                                    if (cx, cy, cz) != (sx, sy, sz):
                                        seal_candidates.append((cx, cy, cz))
                        sealed = 0
                        temp_blocked = set()
                        dense_maze = _maze.sparse_to_dense(maze)
                        mutated_maze = [row_layer[:] for row_layer in dense_maze]
                        _maze.mutate_maze_walls(mutated_maze, int(row['movenonce']), size, {(nx, ny, nz), (gx, gy, gz)})
                        for cx, cy, cz in seal_candidates:
                            if sealed >= 1:
                                break
                            seal_key = bootstrap.eth_keccak(f'SEALV1{row['seed']}{cx}{cy}{cz}{move_nonce}'.encode()).hex()
                            if int(seal_key[:8], 16) % 100 < 25:
                                test_blocked = sealed_set | temp_blocked | {(cx, cy, cz)}
                                if self._path_exists(mutated_maze, size, (nx, ny, nz), (gx, gy, gz), test_blocked):
                                    sealed_set.add((cx, cy, cz))
                                    temp_blocked.add((cx, cy, cz))
                                    sealed += 1
                                    state_info.setdefault('sealed_walls', []).append([cx, cy, cz])
                                    open_candidates = []
                                    seal_rng = ConsensusRng(bootstrap.eth_keccak(f'OPENRNGV1{row['seed']}{move_nonce}'.encode()))
                                    for _ in range(20):
                                        rx = seal_rng.randbelow(size)
                                        ry = seal_rng.randbelow(size)
                                        rz = seal_rng.randbelow(size)
                                        if dense_maze[rz][ry][rx] == 1 and (rx, ry, rz) != (cx, cy, cz):
                                            for ddx2, ddy2, ddz2 in _maze.DIRS_3D.values():
                                                ax, ay, az = (rx + ddx2, ry + ddy2, rz + ddz2)
                                                if 0 <= ax < size and 0 <= ay < size and (0 <= az < size) and (not dense_maze[az][ay][ax]):
                                                    open_key = bootstrap.eth_keccak(f'OPENV1{row['seed']}{rx}{ry}{rz}{move_nonce}'.encode()).hex()
                                                    if int(open_key[:8], 16) % 100 < 15:
                                                        open_candidates.append((rx, ry, rz))
                                                    break
                                    if open_candidates:
                                        ox, oy, oz = open_candidates[seal_rng.randbelow(len(open_candidates))]
                                        sealed_set.discard((ox, oy, oz))
                                        state_info.setdefault('opened_walls', []).append([ox, oy, oz])
            await self.maze_repo.upsert(updated)
            return (True, 'Move accepted', state_info)

    def _maybe_flee_goal(self, maze, miner_pos, goal_pos, maze_id, size, move_nonce) -> bootstrap.Optional[bootstrap.Tuple[int, int, int]]:
        gx, gy, gz = goal_pos
        mnx, mny, mnz = miner_pos

        def cell_ok(x, y, z):
            return 0 <= x < size and 0 <= y < size and (0 <= z < size) and (not maze[z][y][x])
        dist_from_miner = {}
        q = bootstrap.deque()
        q.append((mnx, mny, mnz))
        dist_from_miner[mnx, mny, mnz] = 0
        while q:
            cx, cy, cz = q.popleft()
            for ddx, ddy, ddz in _maze.DIRS_3D.values():
                nnx, nny, nnz = (cx + ddx, cy + ddy, cz + ddz)
                if cell_ok(nnx, nny, nnz) and (nnx, nny, nnz) not in dist_from_miner:
                    dist_from_miner[nnx, nny, nnz] = dist_from_miner[cx, cy, cz] + 1
                    q.append((nnx, nny, nnz))
        if not dist_from_miner or len(dist_from_miner) <= 1:
            return None
        max_d = max((d for pos, d in dist_from_miner.items() if pos != (mnx, mny, mnz)))
        target_pool = [pos for pos, d in dist_from_miner.items() if d == max_d and pos != (mnx, mny, mnz)]
        if not target_pool:
            return None
        recent = self._goal_recent.get(maze_id, bootstrap.deque(maxlen=4))
        fresh_targets = [t for t in target_pool if t not in recent]
        if fresh_targets:
            target = fresh_targets[move_nonce % len(fresh_targets)]
        else:
            target = target_pool[move_nonce % len(target_pool)]
        if (gx, gy, gz) == target:
            return None
        dist_from_target = {}
        q2 = bootstrap.deque()
        q2.append(target)
        dist_from_target[target] = 0
        while q2:
            cx, cy, cz = q2.popleft()
            for ddx, ddy, ddz in _maze.DIRS_3D.values():
                nnx, nny, nnz = (cx + ddx, cy + ddy, cz + ddz)
                if cell_ok(nnx, nny, nnz) and (nnx, nny, nnz) not in dist_from_target:
                    dist_from_target[nnx, nny, nnz] = dist_from_target[cx, cy, cz] + 1
                    q2.append((nnx, nny, nnz))
        best_next = None
        best_dist = 9999
        for ddx, ddy, ddz in _maze.DIRS_3D.values():
            nx, ny, nz = (gx + ddx, gy + ddy, gz + ddz)
            if cell_ok(nx, ny, nz) and (nx, ny, nz) != (mnx, mny, mnz):
                d = dist_from_target.get((nx, ny, nz), 9999)
                if d < best_dist:
                    best_dist = d
                    best_next = (nx, ny, nz)
        if best_next is not None:
            self._goal_prev_pos[maze_id] = (gx, gy, gz)
            recent = self._goal_recent.setdefault(maze_id, bootstrap.deque(maxlen=4))
            recent.append(best_next)
            return best_next
        return None

    def _path_exists(self, maze, size, start, goal, extra_blocked=None):
        if start == goal:
            return True
        if extra_blocked and goal in extra_blocked:
            return False
        q = bootstrap.deque()
        q.append(start)
        visited = {start}
        if extra_blocked:
            visited |= extra_blocked
        while q:
            cx, cy, cz = q.popleft()
            for ddx, ddy, ddz in _maze.DIRS_3D.values():
                nx, ny, nz = (cx + ddx, cy + ddy, cz + ddz)
                if (nx, ny, nz) == goal:
                    return True
                if 0 <= nx < size and 0 <= ny < size and (0 <= nz < size) and ((nx, ny, nz) not in visited) and (maze[nz][ny][nx] == 0):
                    visited.add((nx, ny, nz))
                    q.append((nx, ny, nz))
        return False

    def _bfs_next_step(self, maze, size, src, dst):
        if src == dst:
            return (None, None, None)
        visited = {src}
        q = bootstrap.deque([(src, None)])
        while q:
            (cx, cy, cz), first_step = q.popleft()
            for ddx, ddy, ddz in _maze.DIRS_3D.values():
                nx, ny, nz = (cx + ddx, cy + ddy, cz + ddz)
                if (nx, ny, nz) in visited:
                    continue
                if not (0 <= nx < size and 0 <= ny < size and (0 <= nz < size)):
                    continue
                if maze[nz][ny][nx]:
                    continue
                step = (ddx, ddy, ddz) if first_step is None else first_step
                if (nx, ny, nz) == dst:
                    return step
                visited.add((nx, ny, nz))
                q.append(((nx, ny, nz), step))
        return (None, None, None)

    async def _restart_position(self, row, maze_id, miner_id, current_size):
        new_size = max(config.MIN_MAZE_SIZE, current_size - 1)
        if new_size >= current_size:
            return None
        shrink_amount = current_size - new_size
        old_density = int(row.get('walldensityppm', maze.MIN_WALL_DENSITY_PPM))
        new_density = old_density + shrink_amount * 6000
        new_turb = int(row.get('turbulenceppm', 0)) + shrink_amount * 8000
        move_nonce = int(row.get('movenonce', 0))
        seed = bootstrap.eth_keccak(b'SHRINKGHOSTV2' + bytes.fromhex(row['mazeroot']) + move_nonce.to_bytes(8, 'big') + new_size.to_bytes(4, 'big')).hex()
        loop = bootstrap.asyncio.get_event_loop()
        new_maze = await loop.run_in_executor(self._move_executor, self._generate_deterministic_maze, seed, new_size, new_density, new_turb, self.node.height)
        root_seed = bytes.fromhex(seed)
        new_spawn = self._select_open_cell(new_maze, root_seed)
        new_goal = self._select_open_cell(new_maze, root_seed, exclude=new_spawn)
        ghost_start = (new_size - 1, new_size - 1, new_size - 1) if new_spawn == (0, 0, 0) else (0, 0, 0)
        self._sealed_walls.pop(maze_id, None)
        self._maze_visited.pop(maze_id, None)
        self._goal_prev_pos.pop(maze_id, None)
        self._goal_recent.pop(maze_id, None)
        self._pos_history.pop(maze_id, None)
        self._oscillating_mazes.discard(maze_id)
        self._ghost_frozen_target.pop(maze_id, None)
        self._ghost_cycle.pop(maze_id, None)
        self._ghost_cycle_idx.pop(maze_id, None)
        bootstrap.logger.info(f'[GHOST SHRINK] Miner {miner_id[:16]} caught → size {current_size}→{new_size}, relocated to {new_spawn}')
        return {'size': new_size, 'seed': seed, 'mazeroot': self._calculate_maze_root(new_maze), 'posx': new_spawn[0], 'posy': new_spawn[1], 'posz': new_spawn[2], 'goalx': new_goal[0], 'goaly': new_goal[1], 'goalz': new_goal[2], 'walldensityppm': new_density, 'turbulenceppm': new_turb, 'ghostx': ghost_start[0] if new_size > 5 else None, 'ghosty': ghost_start[1] if new_size > 5 else None, 'ghostz': ghost_start[2] if new_size > 5 else None}

    def get_state(self, miner_id: str) -> bootstrap.Optional[dict]:
        return getattr(self, '_cached_states', {}).get(miner_id)

    def _pow_active(self, maze_id: str) -> bool:
        ent = self._pending_pow.get(maze_id)
        if ent is None:
            return False
        if bootstrap.time.time() - ent[2] > 60:
            self._pending_pow.pop(maze_id, None)
            return False
        return True

    def _find_nearest_open(self, maze, size, x, y, z):
        q = bootstrap.deque()
        visited = set()
        start = (x, y, z)
        q.append((start, 0))
        visited.add(start)
        while q:
            (cx, cy, cz), dist = q.popleft()
            if 0 <= cx < size and 0 <= cy < size and (0 <= cz < size):
                if maze[cz][cy][cx] == 0:
                    return (cx, cy, cz)
            for dx, dy, dz in [(1, 0, 0), (-1, 0, 0), (0, 1, 0), (0, -1, 0), (0, 0, 1), (0, 0, -1)]:
                nx, ny, nz = (cx + dx, cy + dy, cz + dz)
                if (nx, ny, nz) not in visited:
                    visited.add((nx, ny, nz))
                    q.append(((nx, ny, nz), dist + 1))
        return (x, y, z)

    async def _load_or_create_maze(self, miner_id: str, maze_id: str=None) -> dict:
        if not maze_id:
            maze_id = miner_id
        _owned = await self.maze_repo.get_by_miner_id(miner_id)
        if _owned:
            maze_id = str(_owned[0].get('maze_id') or maze_id)
        else:
            _wallet_row = await self.maze_repo.get_by_maze_id(maze_id)
            if _wallet_row:
                _prev = _wallet_row.get('minerid')
                if _prev and _prev != miner_id:
                    _prev_ws = self.node.miner_websockets.get(_prev)
                    if _prev_ws is not None:
                        maze_id = bootstrap.eth_keccak(b'MCXMAZEV2' + maze_id.encode() + b'|' + miner_id.encode()).hex()
                        bootstrap.logger.info(f'[MAZE] new maze {maze_id[:16]} for second miner {miner_id[:16]} on shared wallet')
        existing = await self.maze_repo.get_by_maze_id(maze_id)
        if existing:
            row = dict(existing)
            if _maze._valid_maze_size(row.get('size')) is None:
                bootstrap.logger.error(f'[MAZE-QUARANTINE] {maze_id[:16]} has invalid size {row.get('size')!r} (minimum {config.MIN_MAZE_SIZE}); excluded from lottery/weight until repaired out-of-band')
                return row
            prev_miner = row.get('minerid')
            if prev_miner and prev_miner != miner_id:
                prev_ws = self.node.miner_websockets.get(prev_miner)
                if prev_ws is not None:
                    bootstrap.logger.warning(f'[MAZE] {maze_id[:16]} already bound to active miner {prev_miner[:16]}, rejecting {miner_id[:16]}')
                    return None
            row['minerid'] = miner_id
            if row['minerid'] != existing['minerid']:
                await self.maze_repo.upsert(row)
            try:
                _sz = int(row['size'])
                _px, _py, _pz = (int(row['posx']), int(row['posy']), int(row['posz']))
                _gx, _gy, _gz = (int(row['goalx']), int(row['goaly']), int(row['goalz']))
                _inb = lambda v: 0 <= v < _sz
                _need = not (_inb(_px) and _inb(_py) and _inb(_pz) and _inb(_gx) and _inb(_gy) and _inb(_gz))
                if not _need and (_px, _py, _pz) == (_gx, _gy, _gz):
                    _need = True
                if not _need:
                    loop_h = bootstrap.asyncio.get_event_loop()
                    _maze_h = await loop_h.run_in_executor(self._move_executor, self._generate_deterministic_maze, row['seed'], _sz, int(row['walldensityppm']), int(row['turbulenceppm']), self.node.height)
                    if _maze_h[_pz][_py][_px] or _maze_h[_gz][_gy][_gx]:
                        _need = True
                    else:
                        _step = self._bfs_next_step(_maze_h, _sz, (_px, _py, _pz), (_gx, _gy, _gz))
                        if _step[0] is None:
                            _need = True
                if _need:
                    loop_h = bootstrap.asyncio.get_event_loop()
                    _maze_h = await loop_h.run_in_executor(self._move_executor, self._generate_deterministic_maze, row['seed'], _sz, int(row['walldensityppm']), int(row['turbulenceppm']), self.node.height)
                    _seed_b = bytes.fromhex(row['seed'])
                    _new_spawn = self._select_spawn(_maze_h, (_px, _py, _pz) if _inb(_px) and _inb(_py) and _inb(_pz) else (0, 0, 0), _seed_b)
                    _new_goal = self._select_open_cell(_maze_h, _seed_b, exclude=_new_spawn)
                    row['posx'], row['posy'], row['posz'] = _new_spawn
                    row['goalx'], row['goaly'], row['goalz'] = _new_goal
                    await self.maze_repo.upsert(row)
                    bootstrap.logger.warning(f'[MAZE-SELF-HEAL] {maze_id[:16]} size={_sz}: repaired pos ({_px},{_py},{_pz})→{_new_spawn}, goal ({_gx},{_gy},{_gz})→{_new_goal}')
            except Exception as _heal_exc:
                bootstrap.logger.warning(f'[MAZE-SELF-HEAL] {maze_id[:16]} skipped: {_heal_exc}')
            if self._ghost_tuple(row) is None:
                size = int(row['size'])
                if size > 5:
                    sx, sy, sz = (int(row['posx']), int(row['posy']), int(row['posz']))
                    self._set_ghost(row, (size - 1, size - 1, size - 1) if (sx, sy, sz) == (0, 0, 0) else (0, 0, 0))
                    await self.maze_repo.upsert(row)
                self._sealed_walls.setdefault(maze_id, set())
                self._ghost_frozen_target.pop(maze_id, None)
                self._ghost_cycle.pop(maze_id, None)
                self._ghost_cycle_idx.pop(maze_id, None)
            return row
        seed = bootstrap.eth_keccak(b'MCXPOGSEEDV1' + maze_id.encode()).hex()
        loop = bootstrap.asyncio.get_event_loop()
        maze = await loop.run_in_executor(self._move_executor, self._generate_deterministic_maze, seed, config.MIN_MAZE_SIZE, _maze.MIN_WALL_DENSITY_PPM, 0, self.node.height)
        root = self._calculate_maze_root(maze)
        spawn = self._select_spawn(maze, (0, 0, 0), bytes.fromhex(seed))
        goal = self._select_open_cell(maze, bytes.fromhex(seed), exclude=spawn)
        now = int(bootstrap.time.time())
        row = {'minerid': miner_id, 'maze_id': maze_id, 'size': config.MIN_MAZE_SIZE, 'walldensityppm': _maze.MIN_WALL_DENSITY_PPM, 'seed': seed, 'posx': spawn[0], 'posy': spawn[1], 'posz': spawn[2], 'goalx': goal[0], 'goaly': goal[1], 'goalz': goal[2], 'movenonce': 0, 'consecutivewallhits': 0, 'turbulenceppm': 0, 'growthcount': 0, 'lastgoalheight': 0, 'lastactiveheight': self.node.height, 'mazeroot': root, 'invitedguest': None, 'guestlock': False, 'createdat': now, 'updatedat': now}
        if config.MIN_MAZE_SIZE > 5:
            ghost_start = (config.MIN_MAZE_SIZE - 1, config.MIN_MAZE_SIZE - 1, config.MIN_MAZE_SIZE - 1) if spawn == (0, 0, 0) else (0, 0, 0)
            self._set_ghost(row, ghost_start)
        await self.maze_repo.upsert(row)
        self._sealed_walls[maze_id] = set()
        return row

    def _svf_prepare_pending_certificate(self, block_id: int) -> None:
        self._pending_svf_certificates = []
        try:
            if not svf_keys.SVF_KEY_IS_TEST or svf_keys.SVF_KEY_DKG is None:
                return
            if svf_keys.SVF_GROUP_PUBLIC_KEY is None:
                return
            _store = getattr(self.node, 'svf_evidence_store', {}) or {}
            _roots = getattr(self.node, 'svf_epoch_roots', {}) or {}
            _certs = getattr(self.node, 'svf_certificates', {}) or {}
            for _epoch in sorted(_store.keys(), reverse=True):
                if _epoch in _certs:
                    continue
                _recs = [r for r in _store.get(_epoch) or [] if r is not None]
                if len(_recs) != svf.SVF_EPOCH_BLOCKS:
                    continue

                def _bid(r):
                    return r['block_id'] if isinstance(r, dict) else r.block_id
                _sorted = sorted(_recs, key=_bid)
                if [int(_bid(r)) for r in _sorted] != list(range(_epoch * svf.SVF_EPOCH_BLOCKS, _epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS)):
                    continue
                _end = _epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1
                if not _end + int(config.PRUNE_BLOCKS) < int(block_id):
                    continue
                _root_entry = _roots.get(_epoch)
                if _root_entry is None:
                    continue
                _root = _root_entry[0] if isinstance(_root_entry, (tuple, list)) else _root_entry
                if not isinstance(_root, bytes) or len(_root) != 32:
                    continue
                _anchor = None
                for _b in getattr(self.node, 'blocks', []) or []:
                    if int(_b.get('id', -1)) == _end:
                        _anchor = _b.get('hash')
                        break
                if not _anchor:
                    continue
                _cert = svf_keys._svf_committee_generate_certificate(svf_keys.SVF_KEY_DKG, _root, int(config.CHAIN_ID), svf_keys.SVF_COMMITTEE_EPOCH, int(_epoch), _epoch * svf.SVF_EPOCH_BLOCKS, _end, str(_anchor))
                self._pending_svf_certificates = [_cert]
                bootstrap.logger.info(f'[SVF] block {block_id}: prepared certificate for epoch {_epoch}')
                return
        except Exception as _e:
            bootstrap.logger.warning(f'[SVF] certificate preparation failed for block {block_id}: {_e}')
            self._pending_svf_certificates = []

    async def _stage_block_candidate(self, block_id, prev_hash, winner_miner_id, maze_attestation, _att_proof, _stamped_ts, computed_shrink_factor, _seal_wallet, _seal_pre_bal, tx_list=None, slashes=None, pending_snap=None, final_rows=None, lottery_draw=None):
        winner_miner = None
        pending_txs = list(tx_list) if tx_list is not None else await self.mempool.get(limit=min(config.MAX_TX_PER_BLOCK, config.MAX_BLOCK_TXS))
        executed_txs = []
        total_fees = 0
        had_contract_deploy = False
        _blk_gas = 0
        for tx_data in pending_txs:
            if len(executed_txs) >= config.MAX_BLOCK_TXS:
                break
            try:
                _g = gas._tx_declared_gas(tx_data)
            except (TypeError, ValueError, OverflowError) as _le:
                bootstrap.logger.warning(f'[PoSW] declared gas unparseable tx {str(tx_data.get('tx_hash') or '?')[:16]}: {str(_le or '?')[:16]}')
                continue
            if _blk_gas + _g > config.MAX_BLOCK_GAS:
                continue
            try:
                success, result = await self.node.execute_transaction(tx_data, block_id, block_ts=_stamped_ts)
            except Exception as exc:
                bootstrap.logger.warning(f'[Mempool] tx {str(tx_data.get('tx_hash'))[:16]} raised {type(exc).__name__}: {exc}')
                continue
            if success:
                _sealed = dict(tx_data)
                _sealed['_fee_charged'] = int(result.get('fee_charged', tx_data.get('fee', 0)) or 0)
                _sealed['_gas_used'] = int(result.get('gas_used', 0) or 0)
                executed_txs.append(_sealed)
                _blk_gas += _g
                total_fees += _sealed['_fee_charged']
                if tx_data.get('tx_type') == 'contract_deploy':
                    had_contract_deploy = True
            else:
                _derr = ''
                if isinstance(result, dict):
                    _derr = str(result.get('error', '') or '')
                elif isinstance(result, str):
                    _derr = result
                if _derr.startswith('out of gas: intrinsic') or _derr.startswith('fee field below gas limit') or _derr.startswith('out of gas: code deposit') or ('exceeds tx fee cap' in _derr):
                    _drop_n = int(tx_data.get('nonce', 0) or 0)
                    _drop_w = str(tx_data.get('from_wallet') or '')
                    try:
                        await self.mempool.remove(tx_data.get('tx_hash'))
                        for _otx in await self.mempool.get(limit=10000):
                            if str(_otx.get('from_wallet') or '') == _drop_w and int(_otx.get('nonce', 0) or 0) > _drop_n:
                                await self.mempool.remove(_otx.get('tx_hash'))
                    except Exception:
                        pass
                    bootstrap.logger.warning(f'[Mempool] tx {str(tx_data.get('tx_hash'))[:16]} dropped from mempool (deterministic failure): {_derr}')
                else:
                    bootstrap.logger.warning(f'[Mempool] tx {str(tx_data.get('tx_hash'))[:16]} execution failed (stays in mempool): {result}')
        if had_contract_deploy and self.node.vm_manager:
            self.node.vm_manager._code_cache_valid = False
        base_reward = gas.get_block_reward(block_id)
        if self.node.total_minted + base_reward > config.MAX_SUPPLY:
            base_reward = max(0, config.MAX_SUPPLY - self.node.total_minted)
        producer_base_reward = base_reward
        total_reward = producer_base_reward + total_fees
        self.node.state_trie._dirty.clear()
        await self.node.state_trie.put('height', block_id)
        reward_credited = False
        async with await self.node.db.transaction():
            if winner_miner_id:
                winner_miner = await self.miner_repo.get(winner_miner_id)
                if winner_miner:
                    _seal_w = winner_miner['wallet']
                    if _seal_w == _seal_wallet:
                        _pre_bal = _seal_pre_bal
                    else:
                        _pre_bal = int(await self.balance_repo.get(_seal_w) or 0)
                    await self.node.state_trie.put(f'balance:{_seal_w}', _pre_bal + total_reward)
                    reward_credited = True
            snapshot_dirty = dict(self.node.state_trie._dirty) if self.node.state_trie._dirty else {}
            _pending_snap = list(pending_snap) if pending_snap is not None else list(self._pending_maze_updates)
            _final_rows = list(final_rows) if final_rows is not None else await self._final_maze_rows(_pending_snap)
            _final_state = maze._build_maze_state(_final_rows, maze_attestation)
            _snap = await db._state_snapshot_for_block(self.node.db, self.node, block_id)
            for _fr in _final_rows or []:
                _mid = str(_fr.get('maze_id') or '')
                if not _mid:
                    continue
                if f'maze:{_mid}' not in _snap:
                    continue
                _snap[f'maze:{_mid}'] = {'maze_id': _mid, 'minerid': str(_fr.get('minerid') or ''), 'walldensityppm': int(_fr.get('walldensityppm') or 0), 'seed': str(_fr.get('seed') or ''), 'goalx': int(_fr.get('goalx') or 0), 'goaly': int(_fr.get('goaly') or 0), 'goalz': int(_fr.get('goalz') or 0)}
            _credit_w = winner_miner['wallet'] if winner_miner_id else ''
            if _credit_w and int(total_reward) > 0:
                _snap[f'bal:{_credit_w}'] = int(_snap.get(f'bal:{_credit_w}', 0) or 0) + int(total_reward)
            state_root = db._state_root_from_snapshot(_snap)
            _full_snap = _snap
            snapshot_dirty = {k: db._canonical_value(v) for k, v in _full_snap.items()}
        self.node.state_trie.mark_committed()
        computed_merkle_root = crypto.compute_merkle_root([tx['tx_hash'] for tx in executed_txs])
        _reward_wallet = ''
        if winner_miner_id:
            _rwm = await self.miner_repo.get(winner_miner_id)
            if _rwm:
                _reward_wallet = _rwm.get('wallet', '')
        self._svf_prepare_pending_certificate(block_id)
        unsigned_block = {'id': block_id, 'ts': _stamped_ts, 'phash': prev_hash, 'miners': [winner_miner_id] if winner_miner_id else [], 'reward': total_reward if winner_miner_id else 0, 'tx_count': len(executed_txs), 'merkle_root': computed_merkle_root, 'nonce': 0, 'difficulty': 0, 'version': config.VERSION, 'challenge': '', 'coverage': 1.0, 'total_tx_value': sum((tx.get('value', 0) for tx in executed_txs)), 'total_fees': total_fees, 'tx_hashes': [tx['tx_hash'] for tx in executed_txs], 'transactions': executed_txs, 'winner': winner_miner_id, 'maze_attestation': maze_attestation, 'reward_wallet': _reward_wallet, 'state_root': state_root, 'maze_updates': list(_pending_snap), 'attestation_proof': list(_att_proof), 'maze_state': _final_state, 'slashes': list(slashes) if slashes is not None else list(self._pending_slashes), 'global_shrink_factor': computed_shrink_factor, 'svf_epoch_certificates': list(self._pending_svf_certificates) if hasattr(self, '_pending_svf_certificates') else [], 'lottery_draw': lottery_draw}
        return {'unsigned_block': unsigned_block, 'executed_txs': executed_txs, 'total_fees': total_fees, 'total_reward': total_reward, 'state_root': state_root, '_pending_snap': _pending_snap, '_final_rows': _final_rows, '_final_state': _final_state, '_att_proof': _att_proof, 'reward_credited': reward_credited, 'winner_miner': winner_miner, 'snapshot_dirty': snapshot_dirty, '_full_snap': _full_snap, 'computed_merkle_root': computed_merkle_root, '_reward_wallet': _reward_wallet, 'base_reward': base_reward, 'producer_base_reward': producer_base_reward, 'had_contract_deploy': had_contract_deploy, '_blk_gas': _blk_gas}

    async def produce_block(self) -> bool:
        now = bootstrap.time.time()
        if now < self.node._next_block_time:
            return False
        latest = await self.block_repo.get_latest()
        if latest and latest['id'] >= self.node.height:
            self.node.height = latest['id'] + 1
            self.node.last_hash = latest['hash']
            latest_ts = latest.get('ts', now)
            if hasattr(latest_ts, 'timestamp'):
                latest_ts = latest_ts.timestamp()
            self.node._next_block_time = max(now, float(latest_ts) + config.BLOCK_TIME)
            return False
        block_id = self.node.height
        prev_hash = self.node.last_hash
        _p2p = getattr(self.node, 'p2p', None)
        if _p2p is not None:
            try:
                async with _p2p._lock:
                    _ahead_h = max([int(getattr(_p, 'height', 0) or 0) for _p in _p2p.peers.values()] or [0])
            except Exception:
                _ahead_h = 0
            if _ahead_h > block_id:
                bootstrap.logger.warning(f'[SEAL-STALE-TIP-1] block {block_id}: peer height {_ahead_h} already ahead — syncing instead of sealing')
                _now_ts = bootstrap.time.time()
                _last = float(getattr(self.node, '_last_stale_sync_ts', 0.0) or 0.0)
                _task = getattr(self.node, '_stale_sync_task', None)
                if _now_ts - _last >= 5.0 and (_task is None or getattr(_task, 'done', lambda: True)()):
                    self.node._last_stale_sync_ts = _now_ts
                    self.node._stale_sync_task = bootstrap.asyncio.create_task(_p2p.sync_with_peers())
                self.node._next_block_time = max(bootstrap.time.time() + 5.0, self.node._next_block_time)
                return False
        try:
            _stamped_ts = util._clamp_producer_timestamp(now, await self._ancestor_timestamps(block_id))
        except Exception as _ts_err:
            bootstrap.logger.error(f'[SEAL-TS-FAILCLOSED-1] block {block_id}: timestamp stamp error ({type(_ts_err).__name__}: {str(_ts_err)[:120]!r}) — deferring seal')
            self.node._next_block_time = max(bootstrap.time.time() + 1.0, self.node._next_block_time)
            return False
        try:
            _ts_ok = await self._produce_timestamp_ok(block_id, _stamped_ts)
        except Exception as _ts_err:
            bootstrap.logger.error(f'[SEAL-TS-FAILCLOSED-1] block {block_id}: timestamp gate error ({type(_ts_err).__name__}: {str(_ts_err)[:120]!r}) — deferring seal')
            _ts_ok = False
        if not _ts_ok:
            if maze._seal_ts_log_due('caller'):
                bootstrap.logger.warning(f'[SEAL-TS] block {block_id}: candidate ts outside the median window — deferring seal')
            self.node._next_block_time = max(bootstrap.time.time() + 1.0, self.node._next_block_time)
            return False
        async with self.node.blockexecutionlock:
            candidate_rows = []
            _seen = set()
            all_atts = await self.maze_attestation_repo.get_all()
            if not all_atts:
                bootstrap.logger.info(f'[IDEA5-ELECT-BOOTSTRAP-1] no chain attestations yet for block {block_id}')
            _live_sizes = {}
            try:
                for _r in await self.maze_repo.get_all() or []:
                    _live_sizes[str(_r.get('maze_id', ''))] = int(_r.get('size', 0))
            except Exception:
                _live_sizes = {}
            for _att in all_atts or []:
                _mid = str(_att.get('maze_id', ''))
                _size = int(_live_sizes.get(_mid, 0) or _att.get('last_size', 0))
                if _mid:
                    _seen.add(_mid)
                if _size > config.MIN_MAZE_SIZE:
                    candidate_rows.append({'maze_id': _mid, 'size': _size})
            for _mid in list(self.node.miner_websockets):
                for _row in await self.maze_repo.get_by_miner_id(_mid) or []:
                    if str(_row.get('maze_id', '')) in _seen:
                        continue
                    if int(_row.get('size', 0)) > config.MIN_MAZE_SIZE:
                        candidate_rows.append(_row)
                        _seen.add(str(_row.get('maze_id', '')))
            candidate_rows = [r for r in candidate_rows if str(r.get('maze_id', ''))]
            if candidate_rows:
                total_size = sum((int(r['size']) for r in candidate_rows))
                avg_size = total_size / len(candidate_rows)
                computed_shrink_factor = max(1.0, avg_size / 10)
            else:
                computed_shrink_factor = 1.0
            if self._oscillating_mazes:
                bootstrap.logger.info(f'[PoSW] Oscillating mazes detected (ghost will catch): {list(self._oscillating_mazes)}')
            bootstrap.logger.info(f'[PoSW] IDEA5-ELIG candidates: {[(str(r['maze_id'])[:16], int(r['size'])) for r in candidate_rows]}')
            _pos = []
            for _row in candidate_rows:
                _w = maze._maze_att_weight(int(_row.get('size', 0)))
                if _w > 0:
                    _pos.append((_w, _row))
            _total_w = sum((_w for _w, _ in _pos))
            passing = []
            if _total_w > 0:
                _remaining = sorted(_pos, key=lambda p: str(p[1].get('maze_id', '')))
                _rem_w = _total_w
                _k = 0
                while _remaining:
                    _draw = maze._maze_ticket(prev_hash, block_id, f'__draw__{_k}', _stamped_ts) % _rem_w
                    _acc = 0
                    _pick = len(_remaining) - 1
                    for _i, (_w, _row) in enumerate(_remaining):
                        _acc += _w
                        if _draw < _acc:
                            _pick = _i
                            break
                    _w_pick, _row_pick = _remaining.pop(_pick)
                    _rem_w -= _w_pick
                    passing.append((_k, _row_pick))
                    _k += 1
            passing.sort(key=lambda p: p[0])
            if not passing:
                bootstrap.logger.info(f'[MISSED] No eligible lottery candidate for block {block_id} — skipping round, chain waits for a miner')
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            prev_ts = now
            if latest is not None:
                prev_ts = latest.get('ts', now)
                if hasattr(prev_ts, 'timestamp'):
                    prev_ts = prev_ts.timestamp()
                try:
                    prev_ts = float(prev_ts)
                except (TypeError, ValueError):
                    prev_ts = now
            elapsed = max(0.0, now - prev_ts)
            raw_rank = int(max(0.0, elapsed - config.BLOCK_TIME) // config.SLOT_TIMEOUT)
            rank = min(raw_rank, len(passing) - 1)
            winner_row = passing[rank][1]
            winner = winner_row['maze_id']
            winner_miner_id = winner_row.get('minerid')
            winner_elect_size = int(winner_row['size'])
            if winner_miner_id is None:
                _wrow = await self.maze_repo.get_by_maze_id(winner)
                if _wrow:
                    winner_row = _wrow
                    winner_miner_id = _wrow.get('minerid')
            bootstrap.logger.info(f'[PoSW] Winner: {winner}, rank={rank} (IDEA5-LIVENESS-1), miner={(winner_miner_id[:16] if winner_miner_id else None)}')
            if not winner_miner_id or winner_miner_id not in self.node.miner_websockets:
                _hosted = []
                for _t, _row in passing:
                    _mid_h = _row.get('minerid')
                    if _mid_h is None:
                        _hr = await self.maze_repo.get_by_maze_id(str(_row.get('maze_id', '')))
                        _mid_h = _hr.get('minerid') if _hr else None
                    if _mid_h and _mid_h in self.node.miner_websockets:
                        _hosted.append((_t, _row, _mid_h))
                if _hosted and raw_rank >= 1:
                    _hosted.sort(key=lambda p: p[0])
                    _t, _row, _mid_h = _hosted[0]
                    winner_row = _row
                    winner_miner_id = _mid_h
                    winner_elect_size = int(_row['size'])
                    _liv = await self.maze_repo.get_by_maze_id(str(_row.get('maze_id', '')))
                    if _liv:
                        winner_row = _liv
                    winner = winner_row['maze_id']
                    bootstrap.logger.info(f'[PoSW] IDEA5-LIVENESS-1/2 takeover (raw rank {raw_rank}): unhosted winner -> {str(winner)[:16]}')
                elif _hosted:
                    bootstrap.logger.info(f'[PoSW] Winner unhosted; grace period (raw rank {raw_rank}) — waiting for its host to seal block {block_id}')
                    self.node._next_block_time = bootstrap.time.time() + 1.0
                    return False
                else:
                    _live_peer = False
                    try:
                        if winner_miner_id:
                            _rows = await self.db.fetch('SELECT proof FROM blocks WHERE id >= ? ORDER BY id DESC LIMIT 20', max(0, int(block_id) - 20))
                            for _r in _rows or []:
                                _pj = _r.get('proof') if isinstance(_r, dict) else _r[0]
                                try:
                                    _pw = (bootstrap.json.loads(_pj) or {}).get('winner')
                                except Exception:
                                    _pw = None
                                if _pw and str(_pw) == str(winner_miner_id):
                                    _live_peer = True
                                    break
                    except Exception:
                        _live_peer = False
                    if _live_peer:
                        bootstrap.logger.info(f'[PoSW] Winner {str(winner)[:16]} is hosted by live peer {str(winner_miner_id)[:16]} (won a recent block) — deferring, not skipping block {block_id}')
                        self.node._next_block_time = bootstrap.time.time() + 1.0
                        return False
                    bootstrap.logger.warning(f'[PoSW] Winner {str(winner)[:16]} (rank {rank}/raw {raw_rank}) not hosted here — skipping block {block_id} (IDEA5-LIVENESS-1)')
                    if raw_rank < len(passing):
                        _next = prev_ts + config.BLOCK_TIME + (raw_rank + 1) * config.SLOT_TIMEOUT + 0.5
                    else:
                        _next = bootstrap.time.time() + config.SLOT_TIMEOUT
                    self.node._next_block_time = max(bootstrap.time.time() + 0.5, _next)
                    return False
            _prev_att = await self.maze_attestation_repo.get(winner)
            if _prev_att and int(_prev_att.get('last_block', -1)) >= block_id:
                bootstrap.logger.warning(f'[SEAL-SELF-VERIFY-1] block {block_id} local attestation for {str(winner)[:16]} already at {int(_prev_att.get('last_block', -1))} (>= id) — peers reject (ATTEST-CAP-STRICT), skipping')
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            if _prev_att:
                _att_cap = int(_prev_att.get('last_size', config.MIN_MAZE_SIZE)) + config.ATTEST_GROWTH_PER_BLOCK * (block_id - int(_prev_att['last_block']))
            else:
                _att_cap = config.MIN_MAZE_SIZE + config.ATTEST_FRESH_BUFFER
            maze_attestation = {'maze_id': winner, 'pubkey': winner, 'size': min(max(int(winner_row['size']), winner_elect_size), _att_cap), 'block': block_id}
            bootstrap.logger.info(f'[IDEA5-ATTEST] {str(winner)[:16]} size={maze_attestation['size']} cap={_att_cap} prior={('none' if not _prev_att else _prev_att.get('last_block'))}')
            if int(maze_attestation['size']) < config.MIN_MAZE_SIZE:
                bootstrap.logger.warning(f'[SEAL-SELF-VERIFY-1] block {block_id} sealed attestation size {maze_attestation['size']} < {config.MIN_MAZE_SIZE} — peers would reject, skipping')
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            _att_proof = []
            try:
                _att_sz = int(maze_attestation['size'])
                if _att_sz > config.MIN_MAZE_SIZE + config.ATTEST_FRESH_BUFFER:
                    _prov_entry = None
                    for _u in self._pending_maze_updates or []:
                        if not isinstance(_u, dict):
                            continue
                        _um = str(_u.get('maze_id') or _u.get('miner_id') or '')
                        if _um == str(winner) and maze._valid_maze_size(_u.get('new_size')) == _att_sz:
                            _prov_entry = dict(_u)
                            break
                    _stored_entry = None
                    try:
                        _pr = await self.node.maze_proof_repo.get_for_size(str(winner), _att_sz)
                        if _pr:
                            _pj = _pr.get('proof_json', '') if isinstance(_pr, dict) else ''
                            _stored_entry = bootstrap.json.loads(_pj) if isinstance(_pj, str) and _pj else None
                    except Exception:
                        _stored_entry = None
                    if _prov_entry is None and isinstance(_stored_entry, dict) and (maze._valid_maze_size(_stored_entry.get('new_size')) == _att_sz):
                        _prov_entry = _stored_entry
                    _is_reattest = False
                    if _prov_entry is None:
                        try:
                            _pa = await self.maze_attestation_repo.get(str(winner))
                        except Exception:
                            _pa = None
                        if _pa is not None and int(_pa.get('last_size', 0) or 0) >= _att_sz:
                            _is_reattest = True
                    if _prov_entry is not None:
                        _att_proof = [_prov_entry]
                    elif _is_reattest:
                        _att_proof = []
                    else:
                        _clamp = config.MIN_MAZE_SIZE + config.ATTEST_FRESH_BUFFER
                        if isinstance(_stored_entry, dict):
                            _ps = maze._valid_maze_size(_stored_entry.get('new_size'))
                            if _ps is not None:
                                _clamp = max(_clamp, int(_ps))
                        if _att_sz > _clamp:
                            bootstrap.logger.warning(f'[SEAL-WORK-PROOF-1] block {block_id} clamp attestation size {_att_sz} -> {_clamp} (no proven catch in pending/proof store)')
                            maze_attestation['size'] = int(_clamp)
                            _att_sz = int(_clamp)
                            if isinstance(_stored_entry, dict) and maze._valid_maze_size(_stored_entry.get('new_size')) == _att_sz:
                                _att_proof = [_stored_entry]
                            else:
                                try:
                                    _cp = await self.node.maze_proof_repo.get_for_size(str(winner), _att_sz)
                                    if _cp:
                                        _cpj = _cp.get('proof_json', '') if isinstance(_cp, dict) else ''
                                        _centry = bootstrap.json.loads(_cpj) if isinstance(_cpj, str) and _cpj else None
                                        if isinstance(_centry, dict) and maze._valid_maze_size(_centry.get('new_size')) == _att_sz:
                                            _att_proof = [_centry]
                                except Exception:
                                    pass
                            if int(maze_attestation['size']) < config.MIN_MAZE_SIZE:
                                bootstrap.logger.warning(f'[SEAL-WORK-PROOF-1] block {block_id} attestation size below floor after clamp — skipping')
                                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                                return False
            except Exception as _wp_e:
                bootstrap.logger.warning(f'[SEAL-WORK-PROOF-1] block {block_id} check failed ({_wp_e}) — skipping seal')
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            try:
                _mpr2 = getattr(self.node, 'maze_proof_repo', None)
                for _u in list(self._pending_maze_updates or []):
                    if not isinstance(_u, dict):
                        continue
                    _ns = maze._valid_maze_size(_u.get('new_size'))
                    if _ns is None or _ns <= config.MIN_MAZE_SIZE:
                        continue
                    if _u.get('caught_at_nonce') is not None:
                        continue
                    _umid = str(_u.get('maze_id') or _u.get('miner_id') or '')
                    if not _umid:
                        continue
                    _rec = None
                    for _pu in self._pending_maze_updates or []:
                        if not isinstance(_pu, dict):
                            continue
                        if _pu is _u:
                            continue
                        _pum = str(_pu.get('maze_id') or _pu.get('miner_id') or '')
                        if _pum != _umid:
                            continue
                        if maze._valid_maze_size(_pu.get('new_size')) != _ns:
                            continue
                        if _pu.get('caught_at_nonce') is not None:
                            _rec = dict(_pu)
                            break
                    if _rec is None and _mpr2 is not None:
                        try:
                            _pr2 = await _mpr2.get_for_size(_umid, _ns)
                            if _pr2:
                                _pj2 = _pr2.get('proof_json', '') if isinstance(_pr2, dict) else ''
                                _rec = bootstrap.json.loads(_pj2) if isinstance(_pj2, str) and _pj2 else None
                        except Exception:
                            _rec = None
                    if not isinstance(_rec, dict) or _rec.get('caught_at_nonce') is None:
                        bootstrap.logger.warning(f'[BLOCKED-CONSENSUS] block {block_id} growth for maze {_umid[:16]} to size {_ns} has no catch record in maze_proofs — cannot carry the proof; seal skipped')
                        self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                        return False
                    for _fk in ('caught_at_nonce', 'caught_by_direction', 'parent_seed', 'parent_size', 'parent_density', 'parent_turbulence', 'parent_mazeroot', 'parent_pos', 'parent_goal', 'parent_pos_attested', 'parent_movenonce'):
                        if _u.get(_fk) is None and _rec.get(_fk) is not None:
                            _u[_fk] = _rec.get(_fk)
                    bootstrap.logger.info(f'[SEAL-GROWTH-PROOF-1] block {block_id} maze {_umid[:16]} size {_ns} proof attached from maze_proofs (nonce {_rec.get('caught_at_nonce')})')
            except Exception as _gp_e:
                bootstrap.logger.warning(f'[SEAL-GROWTH-PROOF-1] block {block_id} proof lookup failed ({_gp_e}) — skipping seal')
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            _seal_wallet = ''
            _seal_pre_bal = 0
            try:
                if winner_miner_id:
                    _swm = await self.miner_repo.get(winner_miner_id)
                    if _swm and _swm.get('wallet'):
                        _seal_wallet = _swm['wallet']
                        _seal_pre_bal = int(await self.balance_repo.get(_seal_wallet) or 0)
            except Exception as e:
                bootstrap.logger.warning(f'[Produce] balance lookup failed for block {block_id}: {e}')
            _lottery_draw = None
            if True:
                _ld_cands = []
                for _lw, _lrow in sorted(_pos, key=lambda p: str(p[1].get('maze_id', ''))):
                    _ld_cands.append({'maze_id': str(_lrow.get('maze_id', '')), 'size': int(_lrow.get('size', 0)), 'weight': int(_lw)})
                _ld_widx = None
                for _li, (_lt, _lrow) in enumerate(passing):
                    if str(_lrow.get('maze_id', '')) == str(winner):
                        _ld_widx = _li
                        break
                if _ld_widx is None:
                    bootstrap.logger.warning(f'[PoSW] Lottery winner {str(winner)[:16]} not in passing for block {block_id} - skipping seal')
                    self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                    return False
                _lottery_draw = {'candidates': _ld_cands, 'rank': int(rank), 'winner_index': int(_ld_widx), 'takeover': bool(int(_ld_widx) != int(rank))}
            staged = None
            try:
                async with await self.node.db.transaction():
                    staged = await self._stage_block_candidate(block_id, prev_hash, winner_miner_id, maze_attestation, _att_proof, _stamped_ts, computed_shrink_factor, _seal_wallet, _seal_pre_bal, lottery_draw=_lottery_draw)
                    raise core._StageRollback()
            except core._StageRollback:
                pass
            unsigned_block = staged['unsigned_block']
            executed_txs = staged['executed_txs']
            total_fees = staged['total_fees']
            total_reward = staged['total_reward']
            state_root = staged['state_root']
            _pending_snap = staged['_pending_snap']
            _final_state = staged['_final_state']
            _att_proof = staged['_att_proof']
            reward_credited = staged['reward_credited']
            winner_miner = staged['winner_miner']
            snapshot_dirty = staged['snapshot_dirty']
            _full_snap = staged['_full_snap']
            computed_merkle_root = staged['computed_merkle_root']
            _reward_wallet = staged['_reward_wallet']
            base_reward = staged['base_reward']
            producer_base_reward = staged['producer_base_reward']
            had_contract_deploy = staged['had_contract_deploy']
            _blk_gas = staged['_blk_gas']

            async def _rollback_producer_credit():
                if not reward_credited or winner_miner is None:
                    return
                try:
                    _cur = int(await self.balance_repo.get(winner_miner['wallet']) or 0)
                    await self.node.state_trie.put(f'balance:{winner_miner['wallet']}', _cur)
                    await self.node.state_trie.commit()
                    bootstrap.logger.warning(f'[SIGN-FAIL-ROLLBACK] Reverted trie credit {total_reward} for {winner_miner['wallet'][:16]} after failed seal attempt of block {block_id}')
                except Exception as _rb_e:
                    bootstrap.logger.warning(f'[SIGN-FAIL-ROLLBACK] trie revert failed for block {block_id}: {_rb_e}')
            block_signed = False
            bootstrap.logger.info(f'[PoSW] Sending produce_block to winning miner {winner_miner_id[:16]}')
            try:
                future = bootstrap.asyncio.get_event_loop().create_future()
                self.node._block_sign_futures[winner_miner_id] = future
                await self.node.send_to_miner(winner_miner_id, {'type': 'produce_block', 'block': unsigned_block, 'pending_txs': [tx['tx_hash'] for tx in executed_txs], 'prev_hash': prev_hash, 'height': block_id})
                signed_block = await bootstrap.asyncio.wait_for(future, timeout=60)
                self.node._block_sign_futures.pop(winner_miner_id, None)
                stripped = {k: v for k, v in signed_block.items() if k not in maze.CONSENSUS_EXCLUDED_FIELDS}
                block_hash = bootstrap.hashlib.sha256(crypto.canonical_json_bytes(stripped)).hexdigest()
            except bootstrap.asyncio.TimeoutError:
                self.node._block_sign_futures.pop(winner_miner_id, None)
                self.node._sign_timeout_total += 1
                bootstrap.logger.warning(f'[PoSW] Miner {winner_miner_id[:16]} timed out producing block — skipping block {block_id}')
                await self._slash_signing_refusal(winner_miner_id)
                await _rollback_producer_credit()
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            except Exception as e:
                self.node._block_sign_futures.pop(winner_miner_id, None)
                bootstrap.logger.error(f'[PoSW] Error receiving signed block from {winner_miner_id[:16]}: {e} — skipping block {block_id}')
                await _rollback_producer_credit()
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            try:
                async with await self.node.db.transaction():
                    staged2 = await self._stage_block_candidate(block_id, prev_hash, winner_miner_id, maze_attestation, _att_proof, _stamped_ts, computed_shrink_factor, _seal_wallet, _seal_pre_bal, tx_list=executed_txs, slashes=list(unsigned_block.get('slashes') or []), pending_snap=staged['_pending_snap'], final_rows=staged['_final_rows'], lottery_draw=_lottery_draw)
                    if staged2['state_root'] != unsigned_block.get('state_root'):
                        bootstrap.logger.warning(f'[TX-LOCK-RELEASE-1] block {block_id} re-staged state root {str(staged2['state_root'])[:16]} != signed {str(unsigned_block.get('state_root'))[:16]} — maze changed during the signing window, skipping block')
                        await self.node.db.rollback()
                        await _rollback_producer_credit()
                        self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                        return False
                    unsigned_block = staged2['unsigned_block']
                    executed_txs = staged2['executed_txs']
                    total_fees = staged2['total_fees']
                    total_reward = staged2['total_reward']
                    state_root = staged2['state_root']
                    _pending_snap = staged2['_pending_snap']
                    _final_state = staged2['_final_state']
                    _att_proof = staged2['_att_proof']
                    reward_credited = staged2['reward_credited']
                    winner_miner = staged2['winner_miner']
                    snapshot_dirty = staged2['snapshot_dirty']
                    _full_snap = staged2['_full_snap']
                    computed_merkle_root = staged2['computed_merkle_root']
                    _reward_wallet = staged2['_reward_wallet']
                    base_reward = staged2['base_reward']
                    producer_base_reward = staged2['producer_base_reward']
                    had_contract_deploy = staged2['had_contract_deploy']
                    _blk_gas = staged2['_blk_gas']
                    if self.db.db_type == 'sqlite':
                        prior = await self.db.fetchrow('SELECT block_hash FROM signed_blocks WHERE miner_id = ? AND block_id = ?', winner_miner_id, block_id)
                    else:
                        prior = await self.db.fetchrow('SELECT block_hash FROM signed_blocks WHERE miner_id = $1 AND block_id = $2', winner_miner_id, block_id)
                    if prior and prior.get('block_hash') != block_hash:
                        prior_block = await self.block_repo.get_by_id(block_id)
                        if prior_block is None:
                            if self.db.db_type == 'sqlite':
                                await self.db.execute_dml('DELETE FROM signed_blocks WHERE miner_id = ? AND block_id = ?', winner_miner_id, block_id)
                            else:
                                await self.db.execute_dml('DELETE FROM signed_blocks WHERE miner_id = $1 AND block_id = $2', winner_miner_id, block_id)
                        elif prior_block.get('phash') != unsigned_block['phash'] or prior_block.get('tx_hashes') != unsigned_block['tx_hashes']:
                            await self._slash_equivocation(winner_miner_id, block_id, prior.get('block_hash'), block_hash)
                            await self.node.db.rollback()
                            await _rollback_producer_credit()
                            return False
                    if self.db.db_type == 'sqlite':
                        await self.db.execute_dml('INSERT OR REPLACE INTO signed_blocks (miner_id, block_id, block_hash, signed_at) VALUES (?,?,?,?)', winner_miner_id, block_id, block_hash, bootstrap.time.time())
                    else:
                        await self.db.execute_dml('INSERT INTO signed_blocks (miner_id, block_id, block_hash, signed_at) VALUES ($1,$2,$3,$4) ON CONFLICT (miner_id, block_id) DO UPDATE SET block_hash=$3, signed_at=$4', winner_miner_id, block_id, block_hash, bootstrap.time.time())
                    if signed_block and signed_block.get('hash') == block_hash and crypto.verify_signature_bytes(signed_block.get('producer_pub', ''), bytes.fromhex(block_hash), signed_block.get('signature', '')):
                        _compare_fields = ('id', 'phash', 'ts', 'transactions', 'state_root', 'maze_updates', 'maze_attestation', 'reward_wallet', 'reward', 'winner', 'miners', 'slashes')
                        tampered = False
                        for _fk in _compare_fields:
                            if signed_block.get(_fk) != unsigned_block.get(_fk):
                                bootstrap.logger.warning(f"[PoSW] Miner returned altered block — rejecting (field '{_fk}' differs)")
                                tampered = True
                                break
                        if tampered:
                            self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                            await self.node.db.rollback()
                            await _rollback_producer_credit()
                            return False
                        block = signed_block
                        block['finalized'] = False
                        block_signed = True
                        bootstrap.logger.info(f'[PoSW] Received valid signed block from miner {winner_miner_id[:16]}')
                    else:
                        bootstrap.logger.warning(f'[PoSW] Signed block from {winner_miner_id[:16]} failed validation — skipping block {block_id}')
                        self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                        await self.node.db.rollback()
                        await _rollback_producer_credit()
                        return False
                    try:
                        if not await self.node.verify_block_proof(block):
                            bootstrap.logger.warning(f'[SEAL-SELF-VERIFY-1] block {block_id} failed verify_block_proof — not sealing (followers would reject)')
                            await self.node.db.rollback()
                            await _rollback_producer_credit()
                            self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                            return False
                    except Exception as _sv_e:
                        bootstrap.logger.error(f'[SEAL-SELF-VERIFY-1] block {block_id} verify raised {type(_sv_e).__name__}: {_sv_e} — not sealing')
                        await self.node.db.rollback()
                        await _rollback_producer_credit()
                        self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                        return False
                    try:
                        _svf_block_id = int(block.get('id', 0))
                        if svf.svf_active_at(_svf_block_id):
                            _ev_epoch = _svf_block_id // svf.SVF_EPOCH_BLOCKS
                            try:
                                _ev = svf.compute_block_evidence(block, _svf_block_id)
                                self.node.svf_evidence_store.setdefault(_ev_epoch, []).append(_ev)
                                _epoch_recs = self.node.svf_evidence_store.get(_ev_epoch, [])
                                _root = svf._svf_epoch_root_if_complete(_epoch_recs, _ev_epoch)
                                if _root is not None:
                                    self.node.svf_epoch_roots[_ev_epoch] = (_root, svf.SVF_EPOCH_BLOCKS)
                                    bootstrap.logger.debug(f'[SVF] block {_svf_block_id}: epoch {_ev_epoch} complete, root recorded')
                                bootstrap.logger.debug(f'[SVF] block {_svf_block_id}: evidence recorded for epoch {_ev_epoch}')
                            except svf.SVFReject as _ev_rej:
                                self.node.svf_evidence_store.setdefault(_ev_epoch, []).append(None)
                                bootstrap.logger.debug(f'[SVF] block {_svf_block_id}: no attestation evidence (genesis-like), epoch {_ev_epoch}')
                            except Exception as _ev_e:
                                raise core.AuxStateError(f'SVF evidence extraction failed for block {_svf_block_id}: {_ev_e}') from _ev_e
                            _block_certs = block.get('svf_epoch_certificates') or []
                            if _block_certs:
                                _cert = _block_certs[0]
                                _cert_epoch = int(_cert.get('evidence_epoch', -1))
                                if _cert_epoch >= 0:
                                    self.node.svf_certificates[_cert_epoch] = {'evidence_epoch': _cert_epoch, 'anchor_block_hash': _cert.get('anchor_block_hash', ''), 'evidence_root': _cert.get('evidence_root', ''), 'group_pubkey': _cert.get('group_pubkey', ''), 'threshold_signature': _cert.get('threshold_signature') or _cert.get('signature', ''), 'inclusion_block': _svf_block_id, 'usable_from': _svf_block_id + 1}
                                    bootstrap.logger.debug(f'[SVF] block {_svf_block_id}: certificate for epoch {_cert_epoch} usable from block {_svf_block_id + 1}')
                        async with await self.node.db.transaction():
                            await self.block_repo.create(block)
                            if reward_credited and winner_miner is not None:
                                await self.balance_repo.add(winner_miner['wallet'], total_reward)
                            if svf.svf_active_at(_svf_block_id):
                                _ev_epoch = _svf_block_id // svf.SVF_EPOCH_BLOCKS
                                _epoch_recs = self.node.svf_evidence_store.get(_ev_epoch, [])
                                for _ev in _epoch_recs:
                                    if _ev is None:
                                        continue
                                    try:
                                        _ev_rec = {'epoch_id': _ev_epoch, 'height': _ev.block_id, 'block_hash': _ev.block_hash, 'winner_pubkey': _ev.winner_pubkey, 'attested_size': _ev.attested_size, 'attestation_weight': str(_ev.attestation_weight), 'growth_present': 1 if _ev.growth_present else 0, 'record_hash': _ev.record_hash.hex()}
                                        if self.node.db.db_type == 'sqlite':
                                            await self.node.db.execute_dml('INSERT OR REPLACE INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES (?,?,?,?,?,?,?,?)', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                                        else:
                                            await self.node.db.execute_dml('INSERT INTO svf_evidence (epoch_id, height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (epoch_id, height) DO UPDATE SET block_hash=$3, winner_pubkey=$4, attested_size=$5, attestation_weight=$6, growth_present=$7, record_hash=$8', _ev_rec['epoch_id'], _ev_rec['height'], _ev_rec['block_hash'], _ev_rec['winner_pubkey'], _ev_rec['attested_size'], _ev_rec['attestation_weight'], _ev_rec['growth_present'], _ev_rec['record_hash'])
                                    except Exception:
                                        pass
                                _root = svf._svf_epoch_root_if_complete(_epoch_recs, _ev_epoch)
                                if _root is not None:
                                    _root_hex = _root.hex()
                                    if self.node.db.db_type == 'sqlite':
                                        await self.node.db.execute_dml('INSERT OR REPLACE INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES (?,?,?,?)', _ev_epoch, _root_hex, svf.SVF_EPOCH_BLOCKS, 1)
                                    else:
                                        await self.node.db.execute_dml('INSERT INTO svf_epoch_roots (epoch_id, root_hash, record_count, complete) VALUES ($1,$2,$3,$4) ON CONFLICT (epoch_id) DO UPDATE SET root_hash=$2, record_count=$3, complete=$4', _ev_epoch, _root_hex, svf.SVF_EPOCH_BLOCKS, 1)
                                _block_certs = block.get('svf_epoch_certificates') or []
                                if _block_certs:
                                    _cert = _block_certs[0]
                                    _cert_epoch = int(_cert.get('evidence_epoch', -1))
                                    if _cert_epoch >= 0:
                                        _cert_sig = _cert.get('threshold_signature') or _cert.get('signature', '')
                                        if self.node.db.db_type == 'sqlite':
                                            await self.node.db.execute_dml('INSERT OR REPLACE INTO svf_certificates (evidence_epoch, chain_id, committee_epoch, window_start_height, window_end_height, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from) VALUES (?,?,?,?,?,?,?,?,?,?,?)', _cert_epoch, int(config.CHAIN_ID), 0, _cert_epoch * svf.SVF_EPOCH_BLOCKS, _cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1, _cert.get('anchor_block_hash', ''), _cert.get('evidence_root', ''), _cert.get('group_pubkey', ''), _cert_sig, _svf_block_id, _svf_block_id + 1)
                                        else:
                                            await self.node.db.execute_dml('INSERT INTO svf_certificates (evidence_epoch, chain_id, committee_epoch, window_start_height, window_end_height, anchor_block_hash, evidence_root, group_public_key_id, threshold_signature, inclusion_block, usable_from) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (evidence_epoch) DO UPDATE SET chain_id=$2, committee_epoch=$3, window_start_height=$4, window_end_height=$5, anchor_block_hash=$6, evidence_root=$7, group_public_key_id=$8, threshold_signature=$9, inclusion_block=$10, usable_from=$11', _cert_epoch, int(config.CHAIN_ID), 0, _cert_epoch * svf.SVF_EPOCH_BLOCKS, _cert_epoch * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1, _cert.get('anchor_block_hash', ''), _cert.get('evidence_root', ''), _cert.get('group_pubkey', ''), _cert_sig, _svf_block_id, _svf_block_id + 1)
                    except Exception as _seal_e:
                        bootstrap.logger.error(f'[SEAL-CREDIT-ATOMIC-1] block {block_id} seal failed: {type(_seal_e).__name__}: {_seal_e} — rolling back producer credit (sibling race?)')
                        await self.node.db.rollback()
                        await _rollback_producer_credit()
                        self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                        return False
            except Exception as _stage2_e:
                bootstrap.logger.error(f'[TX-LOCK-RELEASE-1] block {block_id} Stage 2 failed: {type(_stage2_e).__name__}: {_stage2_e} — skipping block')
                await _rollback_producer_credit()
                self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
                return False
            try:
                await self.maze_attestation_repo.upsert({'maze_id': maze_attestation['maze_id'], 'last_size': int(maze_attestation['size']), 'last_block': int(block_id), 'last_block_hash': str(block['hash']), 'pubkey': str(maze_attestation.get('pubkey', ''))})
            except Exception as _e:
                bootstrap.logger.warning(f'[IDEA5-ATTEST] producer upsert failed for block {block_id}: {_e}')
            for _tx in executed_txs:
                await self.mempool.remove(_tx.get('tx_hash'))
                try:
                    _w = _tx.get('from_wallet', '')
                    if _w:
                        self.mempool.note_confirmed_nonce(_w, int(_tx.get('nonce', 0)) + 1)
                        try:
                            await self.node._account_nonce_note(_w, int(_tx.get('nonce', 0)) + 1)
                        except Exception as _ne:
                            bootstrap.logger.warning(f'[PoSW] account_nonces store skipped tx {str(_tx.get('tx_hash') or '?')[:16]}: {_ne}')
                except (TypeError, ValueError) as _le:
                    bootstrap.logger.warning(f'[PoSW] confirmed-nonce wire skipped tx {str(_tx.get('tx_hash') or '?')[:16]}: {str(_le or '?')[:16]}')
                    pass
            root_query = 'INSERT OR REPLACE INTO block_state_roots (block_id,state_root,receipt_root) VALUES (?,?,?)' if self.db.db_type == 'sqlite' else 'INSERT INTO block_state_roots (block_id,state_root,receipt_root) VALUES ($1,$2,$3) ON CONFLICT (block_id) DO UPDATE SET state_root=$2,receipt_root=$3'
            await self.db.execute_dml(root_query, block_id, state_root, '0x' + '00' * 32)
            await self.node.finality_gadget.on_block(block)
            self.node.blocks.append(block)
            self.node.height = block_id + 1
            self.node.last_hash = block['hash']
            self.node._next_block_time = bootstrap.time.time() + config.BLOCK_TIME
            self._height_last_advanced = bootstrap.time.time()
            if winner_miner_id:
                self.node.total_minted += producer_base_reward
                await self.node.network_state_repo.set('total_minted', str(self.node.total_minted))
                await self.node.db.execute_dml('UPDATE miners SET blocks = blocks + 1, rewards = rewards + ? WHERE miner_id = ?', total_reward, winner_miner_id)
                await self.node.db.execute_dml('UPDATE miners SET consecutive_misses = 0 WHERE miner_id = ?', winner_miner_id)
            height_msg = {'type': 'block_height_update', 'height': self.node.height, 'block_id': block_id}
            for mid, mws in list(self.node.miner_websockets.items()):
                try:
                    await mws.send_json(height_msg)
                except Exception as _le:
                    bootstrap.logger.warning(f'[PoSW] height broadcast failed miner {str(mid or '?')[:16]}: {str(_le or '?')[:16]}')
            del self._pending_maze_updates[:len(_pending_snap)]
            try:
                _mpr = getattr(self.node, 'maze_proof_repo', None)
                if _mpr is not None:
                    for _u in list(_pending_snap or []):
                        if isinstance(_u, dict):
                            _umid = _u.get('maze_id') or _u.get('miner_id')
                            if _umid:
                                await _mpr.upsert(_umid, _u, block_id)
                    for _pu in block.get('attestation_proof') or []:
                        if isinstance(_pu, dict):
                            _pmid = _pu.get('maze_id') or _pu.get('miner_id')
                            if _pmid:
                                await _mpr.upsert(_pmid, _pu, block_id)
            except Exception as _mp_e:
                bootstrap.logger.warning(f'[PoSW] seal maze_proof store failed block {block_id}: {_mp_e}')
            for _ev in list(self._pending_slashes):
                if await self.node._apply_slash_event(_ev, block_id):
                    await self._kick_banned_socket(_ev.get('miner_id'), f'sealed {_ev.get('reason', 'slash')}')
            self._pending_slashes.clear()
            self._pending_slashes.extend(self._deferred_slashes)
            self._deferred_slashes = []
            try:
                await self.node.db.execute_dml('DELETE FROM pending_maze_updates WHERE block_id <= ?', block_id)
            except Exception as _le:
                bootstrap.logger.warning(f'[PoSW] pending_maze_updates prune failed block {block_id}: {str(_le or '?')[:16]}')
            if winner_miner_id:
                bootstrap.logger.info(f'[PoSW] Block {block_id} won by {winner_miner_id[:16]}, reward={total_reward // config.SUBS} MCX')
            else:
                bootstrap.logger.info(f'[PoSW] Block {block_id} burned (no winner)')
            await self.node.distribute_token_mining_rewards(block_id)
            if block_id % self.epoch_length == 0:
                await self._create_finality_checkpoint(block_id, self.node.last_hash)
            if block_id % maze.SNAPSHOT_INTERVAL == 0 and block_id > 0:
                try:
                    snapshot_data = bootstrap.json.dumps(snapshot_dirty, sort_keys=True) if snapshot_dirty else '{}'
                    if self.db.db_type == 'sqlite':
                        await self.db.execute_dml('INSERT OR REPLACE INTO state_snapshots (block_id,state_root,receipt_root,snapshot_data,created_at) VALUES (?,?,?,?,?)', block_id, state_root, '0x' + '00' * 32, snapshot_data, int(bootstrap.time.time()))
                    else:
                        await self.db.execute_dml('INSERT INTO state_snapshots (block_id,state_root,receipt_root,snapshot_data,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (block_id) DO UPDATE SET state_root=$2,snapshot_data=$4', block_id, state_root, '0x' + '00' * 32, snapshot_data, int(bootstrap.time.time()))
                    bootstrap.logger.info(f'[PoSW] State snapshot saved at block {block_id}')
                except Exception as e:
                    bootstrap.logger.warning(f'[PoSW] Failed to save snapshot at block {block_id}: {e}')
            await self.node.p2p.broadcast_block(block)
            for _d in (3.0, 9.0):
                self.node.p2p._track_task(bootstrap.asyncio.create_task(self.node.p2p.rebroadcast_block_later(block, _d)))
            self.node.health_checker.record_block(block_id)
            return True

    @staticmethod
    def _select_weighted_winner(seed: bytes, eligible: list) -> bootstrap.Tuple[bootstrap.Optional[str], int, dict]:
        weights = {minerid: PoSWConsensus._maze_weight(size) for minerid, size in sorted(eligible)}
        total = sum(weights.values())
        if total <= 0:
            return (None, 0, weights)
        ticket = int.from_bytes(bootstrap.eth_keccak(b'MCXPOGTICKETV1' + seed), 'big') % total
        cursor = 0
        for minerid in sorted(weights):
            cursor += weights[minerid]
            if ticket < cursor:
                return (minerid, ticket, weights)
        raise AssertionError('Lottery selection fell through')

    async def _create_finality_checkpoint(self, block_id: int, block_hash: str):
        self.epoch += 1
        await self.finality_repo.create_checkpoint(block_id, block_hash, self.epoch)
        await self.block_repo.mark_finalized(block_id)
        bootstrap.logger.info(f'[PoSW] Finality checkpoint at block {block_id} (epoch {self.epoch})')

    async def _shrink_and_ghost_chase(self, block_id: int):
        loop = bootstrap.asyncio.get_event_loop()
        all_mazes = [mz for mz in await self.maze_repo.get_eligible(block_id) if mz.get('minerid') in self.node.miner_websockets]
        for mz in all_mazes:
            mid = mz['maze_id']
            sz = int(mz['size'])
            if sz > 5:
                gpos = self._ghost_tuple(mz)
                if gpos:
                    mx, my, mz_pos = (int(mz['posx']), int(mz['posy']), int(mz['posz']))
                    miner_pos = (mx, my, mz_pos)
                    if gpos != miner_pos:
                        ghost_moved = False
                        ghost_caught = False
                        maze_arr = await loop.run_in_executor(self._move_executor, self._generate_deterministic_maze, mz['seed'], sz, int(mz['walldensityppm']), int(mz['turbulenceppm']), self.node.height)
                        if mid in self._oscillating_mazes:
                            if mid not in self._ghost_cycle:
                                cycle_cells = []
                                for p in self._pos_history.get(mid, []):
                                    if p not in cycle_cells:
                                        cycle_cells.append(p)
                                if cycle_cells:

                                    def _manh(a, b):
                                        return abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])
                                    farthest_idx = max(range(len(cycle_cells)), key=lambda i: _manh(gpos, cycle_cells[i]))
                                    self._ghost_cycle[mid] = cycle_cells
                                    self._ghost_cycle_idx[mid] = farthest_idx
                                    self._ghost_frozen_target[mid] = cycle_cells[farthest_idx]
                            if mid in self._ghost_cycle:
                                cycle_cells = self._ghost_cycle[mid]
                                idx = self._ghost_cycle_idx[mid]
                                target = cycle_cells[idx]
                                if gpos == target:
                                    idx = (idx + 1) % len(cycle_cells)
                                    self._ghost_cycle_idx[mid] = idx
                                    target = cycle_cells[idx]
                                for _ in range(2):
                                    gdx, gdy, gdz = self._bfs_next_step(maze_arr, sz, gpos, target)
                                    if gdx is None:
                                        break
                                    gpos = (gpos[0] + gdx, gpos[1] + gdy, gpos[2] + gdz)
                                    ghost_moved = True
                                    if gpos == miner_pos:
                                        break
                                if gpos == miner_pos:
                                    restart_ev = await self._restart_position(dict(mz), mid, mz['minerid'], sz)
                                    if restart_ev:
                                        ghost_caught = True
                                        await self.maze_repo.upsert({**dict(mz), **restart_ev})
                        else:
                            gdx, gdy, gdz = self._bfs_next_step(maze_arr, sz, gpos, miner_pos)
                            if gdx is not None:
                                new_gpos = (gpos[0] + gdx, gpos[1] + gdy, gpos[2] + gdz)
                                gpos = new_gpos
                                ghost_moved = True
                                if new_gpos == miner_pos:
                                    restart_ev = await self._restart_position(dict(mz), mid, mz['minerid'], sz)
                                    if restart_ev:
                                        ghost_caught = True
                                        await self.maze_repo.upsert({**dict(mz), **restart_ev})
                        if ghost_moved and (not ghost_caught):
                            self._set_ghost(mz, gpos)
                            await self.maze_repo.upsert(dict(mz))
            await bootstrap.asyncio.sleep(0)

    async def _update_global_shrink_factor(self):
        try:
            eligible_rows = await self.maze_repo.get_eligible(self.node.height)
            if eligible_rows:
                total_size = sum((int(r['size']) for r in eligible_rows))
                self._global_avg_size = total_size / len(eligible_rows)
                maze.GLOBAL_SHRINK_FACTOR = max(1.0, self._global_avg_size / 10)
        except Exception:
            pass

    async def production_loop(self):
        last_height_broadcast = 0
        _drift_warned = False
        while not self.node._shutdown_flag:
            try:
                if not self.node._producing_enabled:
                    await bootstrap.asyncio.sleep(10)
                    continue
                try:
                    _ltip = await self.block_repo.get_latest()
                    if _ltip and _ltip.get('ts'):
                        _chain_t = util._median_ancestor_timestamp(await self._ancestor_timestamps(int(self.node.height)))
                        if _chain_t > 0 and (not _drift_warned) and (util._chain_time_drift_seconds(_chain_t, bootstrap.time.time()) > util.BLOCK_TIME_WINDOW_MAX):
                            _drift_warned = True
                            bootstrap.logger.warning('[TIME-DRIFT] local clock differs from chain time by more than %ds (chain %.0f vs local %.0f). Chain time follows block timestamps and can lead or lag real time. This warning has no consensus effect.', util.BLOCK_TIME_WINDOW_MAX, _chain_t, bootstrap.time.time())
                except Exception:
                    pass
                await self._update_global_shrink_factor()
                await self.produce_block()
                try:
                    await self._shrink_and_ghost_chase(self.node.height)
                except Exception as e:
                    bootstrap.logger.error(f'[PoSW] Shrink/ghost error: {e}')
                now = bootstrap.time.time()
                if now - last_height_broadcast >= config.BLOCK_TIME and self.node.miner_websockets:
                    last_height_broadcast = now
                    height_msg = {'type': 'block_height_update', 'height': self.node.height, 'block_id': self.node.height - 1}
                    for mid, mws in list(self.node.miner_websockets.items()):
                        try:
                            await mws.send_json(height_msg)
                        except Exception:
                            pass
                await bootstrap.asyncio.sleep(0.1)
            except Exception as e:
                bootstrap.logger.error(f'[PoSW] Production loop error: {e}', exc_info=True)
                await bootstrap.asyncio.sleep(5)

    async def _kick_banned_socket(self, miner_id: str, why: str):
        ws = self.node.miner_websockets.pop(miner_id, None)
        self.node.miners.pop(miner_id, None)
        self.node.miner_rate_limiters.pop(miner_id, None)
        if ws:
            try:
                await ws.close(code=1000, message=b'banned')
            except Exception:
                pass
        bootstrap.logger.warning(f'[BAN-KICK-1] disconnected {str(miner_id)[:16]} ({why})')

    async def _slash_signing_refusal(self, miner_id: str):
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        slash_amount = max(1, int(miner.get('rewards', 0) * 5 // 100))
        self._deferred_slashes.append({'miner_id': miner_id, 'amount': slash_amount, 'reason': 'signing_refusal', 'block_id': self.node.height})
        slash_msg = {'type': 'slash', 'miner_id': miner_id, 'amount': slash_amount, 'reason': 'signing_refusal', 'block_id': self.node.height}
        for mid, mws in list(self.node.miner_websockets.items()):
            try:
                await mws.send_json({'type': 'slash', 'data': slash_msg})
            except Exception:
                pass
        bootstrap.logger.warning(f'[Slash] Miner {miner_id[:16]} slashed for signing refusal: {slash_amount} subunits')

    async def _slash_equivocation(self, miner_id: str, block_id: int, hash_a: str, hash_b: str):
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        slash_amount = max(1, int(miner.get('rewards', 0) * 10 // 100))
        self._pending_slashes.append({'miner_id': miner_id, 'amount': slash_amount, 'reason': 'equivocation', 'block_id': block_id, 'hash_a': hash_a, 'hash_b': hash_b})
        slash_msg = {'type': 'slash', 'miner_id': miner_id, 'amount': slash_amount, 'reason': 'equivocation', 'block_id': block_id, 'hash_a': hash_a, 'hash_b': hash_b}
        for mid, mws in list(self.node.miner_websockets.items()):
            try:
                await mws.send_json({'type': 'slash', 'data': slash_msg})
            except Exception:
                pass
        bootstrap.logger.error(f'[Slash] Miner {miner_id[:16]} EQUIVOCATED at block {block_id}: {hash_a[:16]} vs {hash_b[:16]}, slashed {slash_amount}')
PoMRConsensus = PoSWConsensus
POW_BASE_DIFFICULTY = 5
