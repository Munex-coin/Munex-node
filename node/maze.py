import bootstrap
import config

def _maze_att_weight(size) -> int:
    if isinstance(size, float) and (not bootstrap.math.isfinite(size)):
        return 0
    try:
        size = int(size)
    except (TypeError, ValueError, OverflowError):
        return 0
    return 0 if size <= config.MIN_MAZE_SIZE else size ** 3 - config.MIN_MAZE_SIZE ** 3
TICKET_DOMAIN_MAX = (1 << 256) - 1

def _maze_threshold(size) -> int:
    try:
        size = int(size)
    except (TypeError, ValueError, OverflowError):
        return 0
    if size <= config.MIN_MAZE_SIZE:
        return 0
    denom = size ** 3
    return TICKET_DOMAIN_MAX - config.MIN_MAZE_SIZE ** 3 * TICKET_DOMAIN_MAX // denom

def _maze_ticket(prev_hash: str, height: int, maze_id: str, ts=0) -> int:
    height_i = int(height)
    try:
        ts_i = int(ts)
    except (TypeError, ValueError, OverflowError):
        ts_i = int(float(ts))
    if height_i < 0 or ts_i < 0 or ts_i >= 1 << 64:
        raise ValueError('height/ts out of ticket domain')
    return int.from_bytes(bootstrap.eth_keccak(bytes.fromhex(prev_hash) + height_i.to_bytes(8, 'big') + ts_i.to_bytes(8, 'big') + str(maze_id).encode()), 'big')

def _block_att_weight(block: dict) -> int:
    att = block.get('maze_attestation')
    if not isinstance(att, dict):
        return 0
    _validators = config._effective_validators()
    if _validators and config._normalize_validator_key(att.get('pubkey', '')) not in _validators:
        return 0
    return _maze_att_weight(att.get('size', 0))

def _fork_tiebreak_winner(our_tip: str, their_tip: str) -> bool:
    return str(their_tip or '') > str(our_tip or '')
BLOCK_CACHE_MAX = 10000
OFFLINE_DECAY_RATE = 0.25
GROWTH_DIFFICULTY_EXP = 0.1
MIN_WALL_DENSITY_PPM = 350000
DENSITY_INCREMENT_PPM = 35000
TURBULENCE_INCREMENT_PPM = 150000
ACTIVE_MINER_WINDOW_SEC = 60
STORAGE_PER_CELL_KB = 10
GLOBAL_SHRINK_FACTOR = 1.0
BASE_DENSITY_PPM = 500000
BASE_TURBULENCE_PPM = 100000
SNAPSHOT_INTERVAL = 10000
CONSENSUS_EXCLUDED_FIELDS = {'hash', 'signature', 'pqc_signature', 'finalized'}
_BLOCK_PROOF_KEYS = {'winner', 'producer_pub', 'signature', 'state_root', 'transactions', 'maze_attestation', 'reward_wallet', 'maze_updates', 'attestation_proof', 'global_shrink_factor', 'slashes', 'maze_state', 'svf_epoch_certificates', 'lottery_draw'}
MAZE_ROW_COLS = frozenset({'maze_id', 'minerid', 'size', 'walldensityppm', 'seed', 'posx', 'posy', 'posz', 'goalx', 'goaly', 'goalz', 'movenonce', 'consecutivewallhits', 'turbulenceppm', 'growthcount', 'knowledge', 'lastgoalheight', 'lastactiveheight', 'mazeroot', 'invitedguest', 'guestlock', 'lastknowledgeheight', 'createdat', 'updatedat', 'ghostx', 'ghosty', 'ghostz'})
MIN_MAZE_SIZE_3D = config.MIN_MAZE_SIZE

def _valid_maze_size(v):
    try:
        if isinstance(v, bool):
            return None
        n = int(v)
        if isinstance(v, float) and float(n) != float(v):
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    if n < config.MIN_MAZE_SIZE:
        return None
    return n

def _last_updates_by_maze(updates) -> dict:
    out: dict = {}
    if not isinstance(updates, (list, tuple)):
        return out
    for _u in updates:
        if not isinstance(_u, dict):
            continue
        _mid = str(_u.get('maze_id') or _u.get('miner_id') or '')
        if not _mid:
            continue
        out[_mid] = _u
    return out

def _proven_sizes_from_updates(updates) -> dict:
    out: dict = {}
    for _mid, _u in _last_updates_by_maze(updates).items():
        _sz = _valid_maze_size(_u.get('new_size'))
        if _sz is not None:
            out[_mid] = _sz
    return out
_MOVE_ROW_SAFE_COLS = frozenset({'posx', 'posy', 'posz', 'goalx', 'goaly', 'goalz', 'movenonce', 'consecutivewallhits', 'lastactiveheight', 'ghostx', 'ghosty', 'ghostz'})
STATE_TREE_EMPTY_HASH = '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'

def mutate_maze_walls(dense_maze, movenonce: int, size: int, protect=None):
    protect = set(protect) if protect else set()
    protect.add((0, 0, 0))
    protect.add((size - 1, size - 1, size - 1))
    bounded_nonce = movenonce & 18446744073709551615
    mn_bytes = bounded_nonce.to_bytes(8, 'big')
    toggled = []
    for z in range(size):
        for y in range(size):
            for x in range(size):
                if (x, y, z) in protect:
                    continue
                h = bootstrap.eth_keccak(b'MCXPOGMUTATEV1' + mn_bytes + x.to_bytes(2, 'big') + y.to_bytes(2, 'big') + z.to_bytes(2, 'big'))
                if h[0] < 64:
                    dense_maze[z][y][x] = not dense_maze[z][y][x]
                    toggled.append((x, y, z))
    if toggled:
        start = (0, 0, 0)
        goal = (size - 1, size - 1, size - 1)
        q = bootstrap.deque([start])
        visited = {start}
        while q:
            cx, cy, cz = q.popleft()
            if (cx, cy, cz) == goal:
                break
            for ddx, ddy, ddz in ((1, 0, 0), (-1, 0, 0), (0, 1, 0), (0, -1, 0), (0, 0, 1), (0, 0, -1)):
                nx, ny, nz = (cx + ddx, cy + ddy, cz + ddz)
                if 0 <= nx < size and 0 <= ny < size and (0 <= nz < size) and ((nx, ny, nz) not in visited) and (not dense_maze[nz][ny][nx]):
                    visited.add((nx, ny, nz))
                    q.append((nx, ny, nz))
        else:
            for tx, ty, tz in toggled:
                dense_maze[tz][ty][tx] = not dense_maze[tz][ty][tx]
    return dense_maze
_MAZE_STATE_COLUMNS = ('maze_id', 'minerid', 'walldensityppm', 'seed', 'goalx', 'goaly', 'goalz')

def _maze_state_entry_from_row(row: dict) -> dict:
    return {'maze_id': str(row.get('maze_id') or ''), 'minerid': str(row.get('minerid') or ''), 'walldensityppm': int(row.get('walldensityppm') or 0), 'seed': str(row.get('seed') or ''), 'goalx': int(row.get('goalx') or 0), 'goaly': int(row.get('goaly') or 0), 'goalz': int(row.get('goalz') or 0)}

def _build_maze_state(maze_rows: list, maze_attestation) -> list:
    if not isinstance(maze_attestation, dict) or not maze_attestation:
        return []
    att_mid = str(maze_attestation.get('maze_id', '') or '').lower()
    out, seen = ([], set())
    for _row in maze_rows or []:
        if not isinstance(_row, dict):
            continue
        _mid = str(_row.get('maze_id') or '')
        if not _mid or _mid.lower() in seen:
            continue
        seen.add(_mid.lower())
        out.append(_maze_state_entry_from_row(_row))
    if att_mid and att_mid not in seen:
        out.append(_maze_state_entry_from_row({'maze_id': maze_attestation.get('maze_id', ''), 'minerid': str(maze_attestation.get('minerid', '') or '')}))
    return out

class _SparseZRow:
    __slots__ = ('_walls', '_size', '_z')

    def __init__(self, walls, size, z):
        self._walls = walls
        self._size = size
        self._z = z

    def __getitem__(self, y):
        return _SparseXYRow(self._walls, self._size, self._z, y)

    def __len__(self):
        return self._size

class _SparseXYRow:
    __slots__ = ('_walls', '_size', '_z', '_y')

    def __init__(self, walls, size, z, y):
        self._walls = walls
        self._size = size
        self._z = z
        self._y = y

    def __getitem__(self, x):
        return (x, self._y, self._z) in self._walls

    def __len__(self):
        return self._size

class SparseMaze:
    __slots__ = ('walls', 'size')

    def __init__(self, walls: set, size: int):
        self.walls = walls
        self.size = size

    def __getitem__(self, z):
        return _SparseZRow(self.walls, self.size, z)

    def __len__(self):
        return self.size

def dense_to_sparse(maze) -> SparseMaze:
    size = len(maze)
    walls = set()
    for z in range(size):
        for y in range(size):
            for x in range(size):
                if maze[z][y][x]:
                    walls.add((x, y, z))
    return SparseMaze(walls, size)

def sparse_to_dense(sparse: SparseMaze) -> list:
    size = sparse.size
    maze = [[[False] * size for _ in range(size)] for _ in range(size)]
    for x, y, z in sparse.walls:
        maze[z][y][x] = True
    return maze

class Maze3DGenerator:

    @staticmethod
    def generate(seed: str, size: int, density: float=config.WALL_DENSITY_3D) -> bootstrap.List[bootstrap.List[bootstrap.List[bool]]]:
        attempts = 0
        while attempts < 20:
            rng = bootstrap.random.Random(seed + str(attempts))
            maze = [[[True] * size for _ in range(size)] for _ in range(size)]

            def carve(x0, y0, z0, x1, y1, z1):
                width, depth, height = (x1 - x0, y1 - y0, z1 - z0)
                if min(width, depth, height) <= 2:
                    for z in range(z0, z1):
                        for y in range(y0, y1):
                            for x in range(x0, x1):
                                maze[z][y][x] = False
                    return
                axis = max(range(3), key=lambda idx: (x1, y1, z1)[idx] - (x0, y0, z0)[idx])
                bounds = [(x0, x1), (y0, y1), (z0, z1)]
                low, high = bounds[axis]
                split = rng.randrange(low + 1, high - 1)
                bounds_a = [list(b) for b in bounds]
                bounds_b = [list(b) for b in bounds]
                bounds_a[axis][1] = split
                bounds_b[axis][0] = split + 1
                carve(*[v for pair in bounds_a for v in pair])
                carve(*[v for pair in bounds_b for v in pair])
                passage = [rng.randrange(start, end) for start, end in bounds]
                passage[axis] = split
                maze[passage[2]][passage[1]][passage[0]] = False
                adj = passage.copy()
                adj[axis] += 1
                maze[adj[2]][adj[1]][adj[0]] = False
            carve(0, 0, 0, size, size, size)
            maze[0][0][0] = False
            maze[size - 1][size - 1][size - 1] = False
            if Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                extra = int(size * size * size * 0.03)
                for _ in range(extra):
                    x = rng.randrange(0, size)
                    y = rng.randrange(0, size)
                    z = rng.randrange(0, size)
                    if (x, y, z) in [(0, 0, 0), (size - 1, size - 1, size - 1)]:
                        continue
                    if not maze[z][y][x]:
                        maze[z][y][x] = True
                        if not Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                            maze[z][y][x] = False
                return maze
            attempts += 1
        return [[[False] * size for _ in range(size)] for _ in range(size)]

    @staticmethod
    def is_connected(maze, start: bootstrap.Tuple[int, int, int], goal: bootstrap.Tuple[int, int, int]) -> bool:
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            is_wall = lambda x, y, z: (x, y, z) in walls
        else:
            size = len(maze)
            is_wall = lambda x, y, z: maze[z][y][x]
        visited = {start}
        queue = bootstrap.deque([start])
        while queue:
            x, y, z = queue.popleft()
            for dx, dy, dz in DIRS_3D.values():
                nx, ny, nz = (x + dx, y + dy, z + dz)
                if 0 <= nx < size and 0 <= ny < size and (0 <= nz < size) and ((nx, ny, nz) not in visited) and (not is_wall(nx, ny, nz)):
                    visited.add((nx, ny, nz))
                    queue.append((nx, ny, nz))
        total_open = size * size * size - len(walls) if isinstance(maze, SparseMaze) else sum((1 for zz in range(size) for yy in range(size) for xx in range(size) if not maze[zz][yy][xx]))
        return len(visited) == total_open

    @staticmethod
    def open_cells(maze) -> bootstrap.List[bootstrap.Tuple[int, int, int]]:
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            return [(x, y, z) for z in range(size) for y in range(size) for x in range(size) if (x, y, z) not in walls]
        else:
            size = len(maze)
            return [(x, y, z) for z in range(size) for y in range(size) for x in range(size) if not maze[z][y][x]]

    @staticmethod
    def bfs_distance(maze, start: bootstrap.Tuple[int, int, int], goal: bootstrap.Tuple[int, int, int]) -> bootstrap.Optional[int]:
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            is_wall = lambda x, y, z: (x, y, z) in walls
        else:
            size = len(maze)
            is_wall = lambda x, y, z: maze[z][y][x]
        if not (0 <= start[0] < size and 0 <= start[1] < size and (0 <= start[2] < size)):
            return None
        if not (0 <= goal[0] < size and 0 <= goal[1] < size and (0 <= goal[2] < size)):
            return None
        if is_wall(start[0], start[1], start[2]) or is_wall(goal[0], goal[1], goal[2]):
            return None
        visited = {start}
        queue = bootstrap.deque([(start, 0)])
        while queue:
            (x, y, z), dist = queue.popleft()
            if (x, y, z) == goal:
                return dist
            for dx, dy, dz in DIRS_3D.values():
                nx, ny, nz = (x + dx, y + dy, z + dz)
                if 0 <= nx < size and 0 <= ny < size and (0 <= nz < size) and ((nx, ny, nz) not in visited) and (not is_wall(nx, ny, nz)):
                    visited.add((nx, ny, nz))
                    queue.append(((nx, ny, nz), dist + 1))
        return None
DIRS_3D = {'east': (1, 0, 0), 'west': (-1, 0, 0), 'north': (0, 1, 0), 'south': (0, -1, 0), 'up': (0, 0, 1), 'down': (0, 0, -1)}
_SEAL_TS_LOG_AT = {}
_SEAL_TS_LOG_INTERVAL = 60.0

def _seal_ts_log_due(key: str) -> bool:
    try:
        now = bootstrap.time.monotonic()
    except Exception:
        return True
    try:
        last = _SEAL_TS_LOG_AT.get(key, 0.0)
        if now - last < _SEAL_TS_LOG_INTERVAL:
            return False
        _SEAL_TS_LOG_AT[key] = now
        return True
    except Exception:
        return True
