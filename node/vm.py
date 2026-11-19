import bootstrap
import config
import crypto
import util
import svf_keys
import svf

class Opcode(bootstrap.IntEnum):
    STOP = 0
    ADD = 1
    SUB = 2
    MUL = 3
    DIV = 4
    SDIV = 5
    MOD = 6
    SMOD = 7
    EXP = 8
    NEG = 9
    LT = 16
    GT = 17
    SLT = 18
    SGT = 19
    EQ = 20
    ISZERO = 21
    AND = 22
    OR = 23
    XOR = 24
    NOT = 25
    BYTE = 26
    SHL = 27
    SHR = 28
    SAR = 29
    SHA3 = 32
    POP = 80
    MLOAD = 81
    MSTORE = 82
    MSTORE8 = 83
    SLOAD = 84
    SSTORE = 85
    JUMP = 86
    JUMPI = 87
    PC = 88
    MSIZE = 89
    GAS = 90
    JUMPDEST = 91
    PUSH1 = 96
    PUSH2 = 97
    PUSH3 = 98
    PUSH4 = 99
    PUSH5 = 100
    PUSH6 = 101
    PUSH7 = 102
    PUSH8 = 103
    PUSH9 = 104
    PUSH10 = 105
    PUSH11 = 106
    PUSH12 = 107
    PUSH13 = 108
    PUSH14 = 109
    PUSH15 = 110
    PUSH16 = 111
    PUSH17 = 112
    PUSH18 = 113
    PUSH19 = 114
    PUSH20 = 115
    PUSH21 = 116
    PUSH22 = 117
    PUSH23 = 118
    PUSH24 = 119
    PUSH25 = 120
    PUSH26 = 121
    PUSH27 = 122
    PUSH28 = 123
    PUSH29 = 124
    PUSH30 = 125
    PUSH31 = 126
    PUSH32 = 127
    DUP1 = 128
    DUP2 = 129
    DUP3 = 130
    DUP4 = 131
    DUP5 = 132
    DUP6 = 133
    DUP7 = 134
    DUP8 = 135
    DUP9 = 136
    DUP10 = 137
    DUP11 = 138
    DUP12 = 139
    DUP13 = 140
    DUP14 = 141
    DUP15 = 142
    DUP16 = 143
    SWAP1 = 144
    SWAP2 = 145
    SWAP3 = 146
    SWAP4 = 147
    SWAP5 = 148
    SWAP6 = 149
    SWAP7 = 150
    SWAP8 = 151
    SWAP9 = 152
    SWAP10 = 153
    SWAP11 = 154
    SWAP12 = 155
    SWAP13 = 156
    SWAP14 = 157
    SWAP15 = 158
    SWAP16 = 159
    LOG0 = 160
    LOG1 = 161
    LOG2 = 162
    LOG3 = 163
    LOG4 = 164
    CREATE = 240
    CALL = 241
    CALLCODE = 242
    RETURN = 243
    DELEGATECALL = 244
    CREATE2 = 245
    STATICCALL = 250
    REVERT = 253
    INVALID = 254
    SELFDESTRUCT = 255
    CHAINID = 70
    EXTCODEHASH = 63
    SELFBALANCE = 71
    BASEFEE = 72
    SIGNEXTEND = 11
    ORIGIN = 50
    CALLER = 51
    GASPRICE = 58
    RETURNDATASIZE = 61
    RETURNDATACOPY = 62
    BLOCKHASH = 64
    TIMESTAMP = 66
    NUMBER = 67
    ADDRESS = 48
    BALANCE = 49
    CALLVALUE = 52
    CALLDATALOAD = 53
    CALLDATASIZE = 54
    CALLDATACOPY = 55
    CODESIZE = 56
    CODECOPY = 57
    EXTCODESIZE = 59
    EXTCODECOPY = 60

class GasCost:
    ZERO = 0
    BASE = 2
    VERYLOW = 3
    LOW = 5
    MID = 8
    HIGH = 10
    EXTCODE = 700
    BALANCE = 700
    SLOAD = 800
    SSTORE = 20000
    SSTORE_COLD = 20000
    CALL = 700
    NEWACCOUNT = 25000
    MEMORY = 3
    LOG = 375
    LOGDATA = 8
    LOGTOPIC = 375
    SHA3 = 30
    SHA3_WORD = 6
    CREATE = 32000
    CREATE2 = 32000
    EXP_BYTE = 50
    EXTCODEHASH_COST = 700
    SELFBALANCE_COST = 5
    BASEFEE_COST = 2
    CHAINID_COST = 2
    COPY = 3
    RETURN_COST = 0
    REVERT_COST = 0
    SELFDESTRUCT_COST = 5000
    CALLVALUE_COST = 2
    CALLDATA = 3
PRECOMPILED = {'0x0000000000000000000000000000000000000001': 'ecrecover', '0x0000000000000000000000000000000000000002': 'sha256', '0x0000000000000000000000000000000000000003': 'keccak256', '0x0000000000000000000000000000000000000004': 'token', '0x0000000000000000000000000000000000000005': 'mcx', '0x0000000000000000000000000000000000000006': 'htlc', '0x0000000000000000000000000000000000000007': 'ripemd160', '0x0000000000000000000000000000000000000008': 'identity', '0x000000000000000000000000000000000000000a': 'blake2', '0x000000000000000000000000000000000000000b': 'modexp', '0x000000000000000000000000000000000000000c': 'ecAdd', '0x000000000000000000000000000000000000000d': 'ecMul', '0x000000000000000000000000000000000000000e': 'ecPairing', '0x0000000000000000000000000000000000000800': 'svf_guard'}
PRECOMPILED_VERSIONS = {'0x0000000000000000000000000000000000000001': 0, '0x0000000000000000000000000000000000000002': 0, '0x0000000000000000000000000000000000000003': 0, '0x0000000000000000000000000000000000000004': 0, '0x0000000000000000000000000000000000000005': 0, '0x0000000000000000000000000000000000000006': 0, '0x0000000000000000000000000000000000000007': 0, '0x0000000000000000000000000000000000000008': 0, '0x000000000000000000000000000000000000000a': 0, '0x000000000000000000000000000000000000000b': 0, '0x000000000000000000000000000000000000000c': 0, '0x000000000000000000000000000000000000000d': 0, '0x000000000000000000000000000000000000000e': 0, '0x0000000000000000000000000000000000000800': 0}
try:
    from py_ecc.secp256k1 import SECP256K1_N, G, add, mul, inv
    from py_ecc.secp256k1 import curve
except ImportError:
    from py_ecc.secp256k1.secp256k1 import N as SECP256K1_N, G, add, multiply as mul, inv, P as _SECP256K1_FIELD_PRIME
    from types import SimpleNamespace
    curve = SimpleNamespace(field_prime=_SECP256K1_FIELD_PRIME)

def _parse_bn256_point(data: bytes):
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:64], 'big')
    if x == 0 and y == 0:
        return ()
    try:
        try:
            from py_ecc.bn128 import curve
            p = curve.field_prime
        except ImportError:
            from py_ecc.bn128 import field_modulus as p
        if x >= p or y >= p:
            return None
        if (x ** 3 + 3) % p == y ** 2 % p:
            from py_ecc.bn128 import FQ
            return (FQ(x), FQ(y))
    except Exception:
        pass
    return None

def _bn256_field_prime():
    try:
        from py_ecc.bn128 import curve
        return curve.field_prime
    except ImportError:
        from py_ecc.bn128 import field_modulus as p
        return p

def _bn256_g2_canonical(x0: int, x1: int, y0: int, y1: int) -> bool:
    try:
        p = _bn256_field_prime()
    except Exception:
        return False
    try:
        return 0 <= int(x0) < p and 0 <= int(x1) < p and (0 <= int(y0) < p) and (0 <= int(y1) < p)
    except (TypeError, ValueError):
        return False

def _encode_bn256_point(point) -> bytes:
    if point is None or point == (0, 0, 0):
        return b'\x00' * 64
    x, y = (point[0], point[1])
    return int(x).to_bytes(32, 'big') + int(y).to_bytes(32, 'big')

def _normalize_call_address(to):
    if isinstance(to, str):
        return to
    try:
        return '0x' + (int(to) & (1 << 160) - 1).to_bytes(20, 'big').hex()
    except Exception:
        return to

class VMExecutionEngine:

    def __init__(self, repo_provider: bootstrap.Callable):
        self.repo_provider = repo_provider
        self._pending_svf_profile = None
        self._pending_svf_db_exec = []
        self.stack = []
        self.memory = bytearray()
        self.pc = 0
        self.gas = 0
        self.stopped = False
        self.return_data = b''
        self.last_return_data = b''
        self.reverted = False
        self.current_contract = None
        self.storage_address = None
        self.caller = None
        self.origin = None
        self.value = 0
        self.depth = 0
        self.storage_cache = {}
        self.sub_storage: bootstrap.Dict[str, bootstrap.Dict[str, int]] = {}
        self.storage_dirty: bootstrap.Set[str] = set()
        self.logs = []
        self.code = b''
        self.static_call = False
        self.reentrancy_lock = set()
        self.code_cache = {}
        self.balance_cache = {}
        self.token_balance_cache = {}
        self.htlc_repo = None
        self.selfdestruct_beneficiary = None
        self.created_contracts = []
        self.access_list = {}
        self.gas_refund = 0
        self.original_storage = {}
        self.block_height = 0
        self.block_ts = None

    def _charge_memory_expansion(self, new_size):
        if new_size <= len(self.memory):
            return
        if new_size > config.MAX_VM_MEMORY:
            self.reverted = True
            return
        old_words = (len(self.memory) + 31) // 32
        new_words = (new_size + 31) // 32
        old_cost = old_words * 3 + old_words * old_words // 512
        new_cost = new_words * 3 + new_words * new_words // 512
        expansion_cost = new_cost - old_cost
        if self.gas < expansion_cost:
            self.reverted = True
            return
        self.gas -= expansion_cost
        self.memory.extend(b'\x00' * (new_size - len(self.memory)))

    def execute(self, bytecode: bytes, caller: str, origin: str, value: int, gas_limit: int, contract_address: str, input_data: bytes, static: bool=False, storage_address: str=None, initial_storage: dict=None, shared_context: bool=False, call_depth: int=0) -> bootstrap.Tuple[bool, bytes, int, bootstrap.List[bootstrap.Dict]]:
        self.gas = gas_limit
        self.caller = caller
        self.origin = origin
        self.value = value
        self.current_contract = contract_address
        self.storage_address = storage_address if storage_address is not None else contract_address
        self.stack = []
        self.memory = bytearray()
        self.pc = 0
        self.stopped = False
        self.reverted = False
        self.logs = []
        self.return_data = b''
        self._pending_svf_profile = None
        self._pending_svf_db_exec = []
        self.last_return_data = b''
        self.storage_cache = dict(initial_storage) if initial_storage is not None else {}
        self.sub_storage = {}
        self.storage_dirty = set()
        self.code = bytecode
        self.input_data = input_data or b''
        self.static_call = static
        self.depth = call_depth
        self.selfdestruct_beneficiary = None
        self.created_contracts = []
        self.access_list = {}
        self.gas_refund = 0
        if self.current_contract in self.reentrancy_lock and (not shared_context):
            self.reverted = True
            return (False, b'', 0, [])
        _lock_owned = self.current_contract not in self.reentrancy_lock
        self.reentrancy_lock.add(self.current_contract)
        try:
            code_len = len(self.code)
            while not self.stopped and self.gas > 0 and (self.pc < code_len):
                op = self.code[self.pc]
                self.pc += 1
                if 96 <= op <= 127:
                    size = op - 95
                    if self.pc + size > code_len:
                        self.pc = code_len
                        break
                    data = self.code[self.pc:self.pc + size]
                    self.pc += size
                    val = int.from_bytes(data, 'big')
                    self.stack.append(val)
                    self.gas -= GasCost.VERYLOW
                    continue
                if 128 <= op <= 143:
                    n = op - 127
                    if len(self.stack) >= n:
                        self.stack.append(self.stack[-n])
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                    continue
                if 144 <= op <= 159:
                    n = op - 143
                    if len(self.stack) >= n + 1:
                        idx = -n - 1
                        self.stack[idx], self.stack[-1] = (self.stack[-1], self.stack[idx])
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                    continue
                if op == Opcode.STOP:
                    self.stopped = True
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.ADD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a + b & (1 << 256) - 1)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SUB:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a - b & (1 << 256) - 1)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MUL:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a * b & (1 << 256) - 1)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.DIV:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a // b if b != 0 else 0)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SDIV:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        if b == 0:
                            self.stack.append(0)
                        else:
                            sa, sb = (crypto._s256(a), crypto._s256(b))
                            q = abs(sa) // abs(sb)
                            if (sa < 0) != (sb < 0):
                                q = -q
                            self.stack.append(q & (1 << 256) - 1)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MOD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a % b if b != 0 else 0)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SMOD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        if b == 0:
                            self.stack.append(0)
                        else:
                            sa, sb = (crypto._s256(a), crypto._s256(b))
                            r = abs(sa) % abs(sb)
                            if sa < 0:
                                r = -r
                            self.stack.append(r & (1 << 256) - 1)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.EXP:
                    if len(self.stack) >= 2:
                        base = self.stack.pop()
                        exponent = self.stack.pop()
                        self.stack.append(pow(base, exponent, 1 << 256))
                        exp_bytes = (exponent.bit_length() + 7) // 8
                        self.gas -= GasCost.EXP_BYTE * exp_bytes
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.NEG:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append(-a & (1 << 256) - 1)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(1 if a < b else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.GT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(1 if a > b else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SLT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(1 if crypto._s256(a) < crypto._s256(b) else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SGT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(1 if crypto._s256(a) > crypto._s256(b) else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.EQ:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(1 if b == a else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.ISZERO:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append(1 if a == 0 else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.AND:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a & b)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.OR:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a | b)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.XOR:
                    if len(self.stack) >= 2:
                        a = self.stack.pop()
                        b = self.stack.pop()
                        self.stack.append(a ^ b)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.NOT:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append(~a & (1 << 256) - 1)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.BYTE:
                    if len(self.stack) >= 2:
                        idx = self.stack.pop()
                        val = self.stack.pop()
                        self.stack.append(val >> 8 * (31 - idx) & 255 if idx < 32 else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SHL:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop()
                        val = self.stack.pop()
                        self.stack.append(val << shift & (1 << 256) - 1 if shift < 256 else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SHR:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop()
                        val = self.stack.pop()
                        self.stack.append(val >> shift if shift < 256 else 0)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SAR:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop()
                        val = self.stack.pop()
                        signed = crypto._s256(val)
                        if shift >= 256:
                            self.stack.append(0 if signed >= 0 else (1 << 256) - 1)
                        else:
                            self.stack.append(signed >> shift & (1 << 256) - 1)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SIGNEXTEND:
                    if len(self.stack) >= 2:
                        b = self.stack.pop()
                        x = self.stack.pop()
                        if b < 32:
                            bit = 8 * b + 7
                            if x & 1 << bit:
                                x = x | (1 << 256) - 1 ^ (1 << bit + 1) - 1
                            else:
                                x = x & (1 << bit + 1) - 1
                        self.stack.append(x & (1 << 256) - 1)
                        self.gas -= GasCost.LOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SHA3:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        hash_val = crypto.keccak_256(data)
                        self.stack.append(int.from_bytes(hash_val, 'big'))
                        self.gas -= GasCost.SHA3 + GasCost.SHA3_WORD * ((size + 31) // 32)
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.POP:
                    if self.stack:
                        self.stack.pop()
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MLOAD:
                    if len(self.stack) >= 1:
                        offset = self.stack.pop()
                        self._charge_memory_expansion(offset + 32)
                        if self.reverted:
                            break
                        val = int.from_bytes(self.memory[offset:offset + 32], 'big')
                        self.stack.append(val)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MSTORE:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        val = self.stack.pop()
                        self._charge_memory_expansion(offset + 32)
                        if self.reverted:
                            break
                        self.memory[offset:offset + 32] = val.to_bytes(32, 'big')
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MSTORE8:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        val = self.stack.pop() & 255
                        self._charge_memory_expansion(offset + 1)
                        if self.reverted:
                            break
                        self.memory[offset] = val
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.MSIZE:
                    self.stack.append(len(self.memory))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.SLOAD:
                    if len(self.stack) >= 1:
                        key = self.stack.pop()
                        slot_key = (self.storage_address, key)
                        warm = slot_key in self.access_list
                        if not warm:
                            self.gas -= 2100
                            self.access_list[slot_key] = True
                        else:
                            self.gas -= 100
                        val = self.storage_cache.get(str(key), 0)
                        self.stack.append(val)
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SSTORE:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 2:
                        key = self.stack.pop()
                        val = self.stack.pop() & (1 << 256) - 1
                        slot_key = (self.storage_address, key)
                        warm = slot_key in self.access_list
                        if not warm:
                            self.gas -= 2100
                            self.access_list[slot_key] = True
                        else:
                            self.gas -= 100
                        current = self.storage_cache.get(str(key), 0)
                        original_key = (self.storage_address, key)
                        original = self.original_storage.get(original_key, current)
                        self.original_storage[original_key] = original
                        if val != current:
                            if original == current:
                                if original == 0:
                                    self.gas -= config.SSTORE_SET
                                else:
                                    self.gas -= config.SSTORE_RESET
                                    if val == 0:
                                        self.gas_refund += config.SSTORE_REFUND
                            else:
                                self.gas -= 100
                                if original != 0:
                                    if current == 0:
                                        self.gas_refund = max(0, self.gas_refund - config.SSTORE_REFUND)
                                    if val == 0:
                                        self.gas_refund += config.SSTORE_REFUND
                                if val == original:
                                    if original == 0:
                                        self.gas_refund += config.SSTORE_SET - 2100
                                    else:
                                        self.gas_refund += config.SSTORE_RESET - 2100
                        self.storage_cache[str(key)] = val
                        self.storage_dirty.add(str(key))
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.JUMP:
                    if len(self.stack) >= 1:
                        dest = self.stack.pop()
                        if dest < 0 or dest >= code_len or self.code[dest] != 91:
                            self.reverted = True
                            break
                        self.pc = dest
                        self.gas -= GasCost.MID
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.JUMPI:
                    if len(self.stack) >= 2:
                        dest = self.stack.pop()
                        cond = self.stack.pop()
                        if cond != 0:
                            if dest < 0 or dest >= code_len or self.code[dest] != 91:
                                self.reverted = True
                                break
                            self.pc = dest
                        self.gas -= GasCost.HIGH
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.JUMPDEST:
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.PC:
                    self.stack.append(self.pc)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.GAS:
                    self.stack.append(self.gas)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.GASPRICE:
                    self.stack.append(config.GAS_PRICE)
                    self.gas -= GasCost.BASE
                elif op == Opcode.CHAINID:
                    self.stack.append(config.CHAIN_ID)
                    self.gas -= GasCost.CHAINID_COST
                elif op == Opcode.ADDRESS:
                    self.stack.append(int(self.current_contract[2:], 16) if isinstance(self.current_contract, str) and self.current_contract.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.ORIGIN:
                    self.stack.append(int(self.origin[2:], 16) if isinstance(self.origin, str) and self.origin.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.CALLER:
                    self.stack.append(int(self.caller[2:], 16) if isinstance(self.caller, str) and self.caller.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.BALANCE:
                    if len(self.stack) < 1:
                        self.reverted = True
                        break
                    address = _normalize_call_address(self.stack.pop())
                    bal = self.balance_cache.get(address)
                    if bal is None:
                        loaded = self._load_balance_for(address)
                        bal = loaded if loaded is not None else 0
                        self.balance_cache[address] = bal
                    self.stack.append(bal)
                    self.gas -= GasCost.BALANCE
                elif op == Opcode.CALLVALUE:
                    self.stack.append(self.value)
                    self.gas -= GasCost.CALLVALUE_COST
                elif op == Opcode.CALLDATASIZE:
                    self.stack.append(len(self.input_data))
                    self.gas -= GasCost.CALLDATA
                elif op == Opcode.CALLDATALOAD:
                    if len(self.stack) < 1:
                        self.reverted = True
                        break
                    offset = self.stack.pop()
                    data = self.input_data[offset:offset + 32].ljust(32, b'\x00')
                    self.stack.append(int.from_bytes(data, 'big'))
                    self.gas -= GasCost.CALLDATA
                elif op in (Opcode.CALLDATACOPY, Opcode.CODECOPY, Opcode.EXTCODECOPY):
                    needed = 3 if op != Opcode.EXTCODECOPY else 4
                    if len(self.stack) < needed:
                        self.reverted = True
                        break
                    if op == Opcode.EXTCODECOPY:
                        address_value = self.stack.pop()
                        memory_offset = self.stack.pop()
                        code_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        source = self._load_code_for(_normalize_call_address(address_value)) or b''
                    else:
                        memory_offset = self.stack.pop()
                        code_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        source = self.input_data if op == Opcode.CALLDATACOPY else self.code
                    if memory_offset + copy_size > len(self.memory):
                        self._charge_memory_expansion(memory_offset + copy_size)
                        if self.reverted:
                            break
                    self.memory[memory_offset:memory_offset + copy_size] = source[code_offset:code_offset + copy_size].ljust(copy_size, b'\x00')
                    self.gas -= GasCost.COPY * ((copy_size + 31) // 32)
                elif op == Opcode.RETURNDATASIZE:
                    self.stack.append(len(self.last_return_data))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.RETURNDATACOPY:
                    if len(self.stack) >= 3:
                        memory_offset = self.stack.pop()
                        data_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        if data_offset + copy_size > len(self.last_return_data):
                            self.reverted = True
                            break
                        if memory_offset + copy_size > len(self.memory):
                            self._charge_memory_expansion(memory_offset + copy_size)
                            if self.reverted:
                                break
                        self.memory[memory_offset:memory_offset + copy_size] = self.last_return_data[data_offset:data_offset + copy_size]
                        self.gas -= GasCost.VERYLOW + GasCost.COPY * ((copy_size + 31) // 32)
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.CODESIZE:
                    self.stack.append(len(self.code))
                    self.gas -= GasCost.BASE
                elif op == Opcode.EXTCODESIZE:
                    if len(self.stack) < 1:
                        self.reverted = True
                        break
                    address = _normalize_call_address(self.stack.pop())
                    code = self._load_code_for(address)
                    self.stack.append(len(code) if code is not None else 0)
                    self.gas -= GasCost.EXTCODE
                elif op == Opcode.SELFBALANCE:
                    bal = self.balance_cache.get(self.current_contract)
                    if bal is None:
                        loaded = self._load_balance_for(self.current_contract)
                        bal = loaded if loaded is not None else 0
                        self.balance_cache[self.current_contract] = bal
                    self.stack.append(bal)
                    self.gas -= GasCost.SELFBALANCE_COST
                elif op == Opcode.BASEFEE:
                    self.stack.append(config.GAS_PRICE)
                    self.gas -= GasCost.BASEFEE_COST
                elif op == Opcode.TIMESTAMP:
                    self.stack.append(int(self.block_ts) if self.block_ts is not None else 0)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.NUMBER:
                    self.stack.append(int(self.block_height or 0))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.BLOCKHASH:
                    if len(self.stack) >= 1:
                        _bn = self.stack.pop()
                        _bh = 0
                        try:
                            _bn_i = int(_bn)
                        except (TypeError, ValueError):
                            _bn_i = -1
                        if 0 <= _bn_i <= int(self.block_height or 0) - 1 and _bn_i >= int(self.block_height or 0) - 256:
                            _bh = self._load_block_hash_for(_bn_i)
                        self.stack.append(_bh)
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.EXTCODEHASH:
                    if len(self.stack) >= 1:
                        addr = _normalize_call_address(self.stack.pop())
                        code = self._load_code_for(addr) or b''
                        self.stack.append(int.from_bytes(bootstrap.eth_keccak(code), 'big'))
                        self.gas -= GasCost.EXTCODEHASH_COST
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LOG0:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        self.logs.append({'address': self.current_contract, 'topics': [], 'data': data.hex()})
                        self.gas -= GasCost.LOG + GasCost.LOGDATA * size
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LOG1:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 3:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        topic = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        self.logs.append({'address': self.current_contract, 'topics': [topic], 'data': data.hex()})
                        self.gas -= GasCost.LOG + GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LOG2:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 4:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        t1 = self.stack.pop()
                        t2 = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        self.logs.append({'address': self.current_contract, 'topics': [t1, t2], 'data': data.hex()})
                        self.gas -= GasCost.LOG + 2 * GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LOG3:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 5:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        t1 = self.stack.pop()
                        t2 = self.stack.pop()
                        t3 = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        self.logs.append({'address': self.current_contract, 'topics': [t1, t2, t3], 'data': data.hex()})
                        self.gas -= GasCost.LOG + 3 * GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.LOG4:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 6:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        t1 = self.stack.pop()
                        t2 = self.stack.pop()
                        t3 = self.stack.pop()
                        t4 = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        data = self.memory[offset:offset + size]
                        self.logs.append({'address': self.current_contract, 'topics': [t1, t2, t3, t4], 'data': data.hex()})
                        self.gas -= GasCost.LOG + 4 * GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.CALL:
                    if len(self.stack) >= 7:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        val = self.stack.pop()
                        in_off = self.stack.pop()
                        in_sz = self.stack.pop()
                        out_off = self.stack.pop()
                        out_sz = self.stack.pop()
                        if self.static_call and val != 0:
                            self.reverted = True
                            break
                        if val != 0:
                            self.gas -= 9000
                            _to_norm = _normalize_call_address(to)
                            if not self._has_deployed_code(_to_norm, _to_norm.lower()) and (not self._has_balance_for(_to_norm)):
                                self.gas -= GasCost.NEWACCOUNT
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted:
                            break
                        input_data = self.memory[in_off:in_off + in_sz]
                        if to in self.reentrancy_lock:
                            self.stack.append(0)
                            self.gas -= GasCost.CALL
                            continue
                        success, ret = self._call_contract(to, val, input_data, gas, self.current_contract)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted:
                                    break
                                self.memory[out_off:out_off + out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.CALLCODE:
                    if len(self.stack) >= 7:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        val = self.stack.pop()
                        in_off = self.stack.pop()
                        in_sz = self.stack.pop()
                        out_off = self.stack.pop()
                        out_sz = self.stack.pop()
                        if self.static_call and val != 0:
                            self.reverted = True
                            break
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted:
                            break
                        input_data = self.memory[in_off:in_off + in_sz]
                        success, ret = self._callcode_contract(to, val, input_data, gas, self.caller)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted:
                                    break
                                self.memory[out_off:out_off + out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.DELEGATECALL:
                    if len(self.stack) >= 6:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        in_off = self.stack.pop()
                        in_sz = self.stack.pop()
                        out_off = self.stack.pop()
                        out_sz = self.stack.pop()
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted:
                            break
                        input_data = self.memory[in_off:in_off + in_sz]
                        success, ret = self._delegate_call(to, input_data, gas)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted:
                                    break
                                self.memory[out_off:out_off + out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.STATICCALL:
                    if len(self.stack) >= 6:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        in_off = self.stack.pop()
                        in_sz = self.stack.pop()
                        out_off = self.stack.pop()
                        out_sz = self.stack.pop()
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted:
                            break
                        input_data = self.memory[in_off:in_off + in_sz]
                        success, ret = self._static_call(to, input_data, gas)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted:
                                    break
                                self.memory[out_off:out_off + out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.CREATE:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 3:
                        value = self.stack.pop()
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        init_code = self.memory[offset:offset + size]
                        nonce = self.storage_cache.get(f'nonce_{self.current_contract}', 0)
                        new_addr = self._compute_create_address(self.current_contract, nonce)
                        self._increment_nonce(self.current_contract)
                        success, addr, ret = self._create_contract(new_addr, init_code, value)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            self.stack.append(int(addr, 16))
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CREATE
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.CREATE2:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 4:
                        value = self.stack.pop()
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        salt = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        init_code = self.memory[offset:offset + size]
                        new_addr = self._compute_create2_address(self.current_contract, salt, init_code)
                        self._increment_nonce(self.current_contract)
                        success, addr, ret = self._create_contract(new_addr, init_code, value)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            self.stack.append(int(addr, 16))
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CREATE2
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.RETURN:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        self.return_data = self.memory[offset:offset + size]
                        self.stopped = True
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.REVERT:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop()
                        size = self.stack.pop()
                        self._charge_memory_expansion(offset + size)
                        if self.reverted:
                            break
                        self.return_data = self.memory[offset:offset + size]
                        self.reverted = True
                        self.stopped = True
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                elif op == Opcode.SELFDESTRUCT:
                    if self.static_call:
                        self.reverted = True
                        break
                    if len(self.stack) >= 1:
                        beneficiary = _normalize_call_address(self.stack.pop())
                        balance = self.balance_cache.get(self.current_contract, 0)
                        if beneficiary != self.current_contract:
                            self.balance_cache[beneficiary] = self.balance_cache.get(beneficiary, 0) + balance
                            self.balance_cache[self.current_contract] = 0
                        self.selfdestruct_beneficiary = beneficiary
                        self.stopped = True
                        self.gas -= GasCost.SELFDESTRUCT_COST
                    else:
                        self.reverted = True
                        break
                else:
                    self.reverted = True
                    break
            if self.gas < 0 or (self.reverted and (not self.stopped)):
                self.reverted = True
                return (False, self.return_data, gas_limit, self.logs)
            if self.reverted:
                return (False, self.return_data, gas_limit - self.gas, self.logs)
            if not self.stopped and self.pc < code_len:
                self.reverted = True
                return (False, self.return_data, gas_limit, self.logs)
            gas_used = gas_limit - self.gas
            refund = min(self.gas_refund, gas_used // 5)
            gas_used -= refund
            return (True, self.return_data, gas_used, self.logs)
        except Exception as e:
            bootstrap.logger.error(f'[VM] Execution error: {e}', exc_info=True)
            return (False, b'', gas_limit, [])
        finally:
            if _lock_owned:
                self.reentrancy_lock.discard(self.current_contract)

    def _load_storage_for(self, address: str) -> dict:
        if not address:
            return {}
        try:
            db = self.repo_provider() if self.repo_provider else None
            if db is None:
                return {}
            ph = '?' if str(getattr(db, 'db_url', 'sqlite://')).startswith('sqlite') else '%s'
            cur = db.execute(f'SELECT key, value FROM contract_storage_v2 WHERE contract_address = {ph}', address)
            rows = cur.fetchall()
            out = {}
            for row in rows or []:
                if isinstance(row, dict):
                    k, v = (row.get('key'), row.get('value'))
                else:
                    k, v = (row[0], row[1])
                try:
                    out[str(k)] = int(v)
                except (TypeError, ValueError) as _le:
                    bootstrap.logger.warning(f'[VM] storage int parse skipped addr {str(address or '?')[:16]} key {str(k or '?')[:16]}: {str(_le or '?')[:16]}')
                    continue
            return out
        except Exception:
            return {}

    def _load_balance_for(self, address: str):
        if not address:
            return None
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return None
            cur = sync_db.execute('SELECT bal FROM balances WHERE wallet = ?', address)
            row = cur.fetchone()
            if row is None:
                return 0
            try:
                return row['bal']
            except (TypeError, KeyError, IndexError):
                return row[0]
        except Exception:
            return None

    def _load_code_for(self, address: str):
        if not address:
            return None
        if address in self.code_cache:
            return self.code_cache[address]
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return None
            cur = sync_db.execute('SELECT bytecode FROM contract_v2 WHERE address = ?', address)
            row = cur.fetchone()
            if row:
                bytecode = bytes.fromhex(row[0])
                self.code_cache[address] = bytecode
                return bytecode
            return None
        except Exception:
            return None

    def _load_block_hash_for(self, block_id: int) -> int:
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return 0
            cur = sync_db.execute('SELECT hash FROM blocks WHERE id = ?', int(block_id))
            row = cur.fetchone()
            if not row:
                return 0
            try:
                _h = row['hash']
            except (TypeError, KeyError, IndexError):
                _h = row[0]
            return int(str(_h).removeprefix('0x'), 16)
        except Exception:
            return 0

    def _absorb_child_storage(self, child) -> None:
        if child.storage_address == self.storage_address:
            self.storage_cache.update(child.storage_cache)
            self.storage_dirty |= child.storage_dirty
        else:
            bucket = self.sub_storage.setdefault(child.storage_address, {})
            for k in child.storage_dirty:
                bucket[k] = child.storage_cache.get(k, 0)
        for addr, slots in getattr(child, 'sub_storage', {}).items():
            if addr == self.storage_address:
                self.storage_cache.update(slots)
                self.storage_dirty |= set(slots)
            else:
                self.sub_storage.setdefault(addr, {}).update(slots)

    def _storage_load(self, key: int) -> int:
        return self.storage_cache.get(str(key), 0)

    def _storage_store(self, key: int, value: int):
        self.storage_cache[str(key)] = value & (1 << 256) - 1
        self.storage_dirty.add(str(key))

    def set_block_height(self, h: int) -> None:
        self.block_height = int(h)

    def set_block_timestamp(self, ts) -> None:
        try:
            self.block_ts = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            self.block_ts = None

    def _get_nonce(self, address: str) -> int:
        return self.storage_cache.get(f'nonce_{address}', 0)

    def _increment_nonce(self, address: str) -> int:
        nonce = self._get_nonce(address) + 1
        self.storage_cache[f'nonce_{address}'] = nonce
        self.storage_dirty.add(f'nonce_{address}')
        return nonce

    def _compute_create_address(self, sender: str, nonce: int) -> str:
        return util.compute_contract_address(sender, nonce)

    def _compute_create2_address(self, sender: str, salt: int, init_code: bytes) -> str:
        prefix = b'\xff'
        sender_bytes = bytes.fromhex(sender[2:])
        salt_bytes = salt.to_bytes(32, 'big')
        init_hash = bootstrap.eth_keccak(init_code)
        data = prefix + sender_bytes + salt_bytes + init_hash
        return '0x' + bootstrap.eth_keccak(data)[-20:].hex()

    def _create_contract(self, address: str, init_code: bytes, value: int) -> bootstrap.Tuple[bool, str, bytes]:
        if self.depth + 1 >= 1024:
            return (False, address, b'')
        if address in self.code_cache:
            return (False, address, b'')
        saved_creator = self.balance_cache.get(self.current_contract, 0)
        saved_new = self.balance_cache.get(address, 0)
        if value > 0:
            if saved_creator < value:
                return (False, address, b'')
            self.balance_cache[self.current_contract] = saved_creator - value
            self.balance_cache[address] = saved_new + value
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.block_height = self.block_height
        child.block_ts = self.block_ts
        child.original_storage = self.original_storage
        success, ret, gas_used, logs = child.execute(init_code, caller=self.current_contract, origin=self.origin, value=value, gas_limit=self.gas, contract_address=address, input_data=b'', static=False, storage_address=address, call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and (not child.reverted):
            deployed_code = ret if ret else init_code
            if len(deployed_code) > config.MAX_BYTECODE:
                if value > 0:
                    self.balance_cache[self.current_contract] = saved_creator
                    self.balance_cache[address] = saved_new
                bootstrap.logger.debug(f'[VM] CREATE rejected: runtime size {len(deployed_code)} > MAX_BYTECODE {config.MAX_BYTECODE}')
                return (False, address, b'')
            self.balance_cache.update(child.balance_cache)
            self.logs.extend(child.logs)
            self._absorb_child_storage(child)
            self.code_cache[address] = deployed_code
            self.created_contracts.append((address, deployed_code))
            return (True, address, ret)
        else:
            if value > 0:
                self.balance_cache[address] = saved_new
                self.balance_cache[self.current_contract] = saved_creator
            return (False, address, ret)

    def _has_balance_for(self, to: str) -> bool:
        try:
            if isinstance(to, str) and self.balance_cache.get(to, 0) > 0:
                return True
            sync_db = self.repo_provider()
            if sync_db is None:
                return False
            cur = sync_db.execute('SELECT bal FROM balances WHERE wallet = ?', to)
            row = cur.fetchone()
            if row is None:
                return False
            try:
                return int(row['bal']) > 0
            except (TypeError, KeyError, IndexError):
                return int(row[0]) > 0
        except Exception:
            return False

    def _has_deployed_code(self, to: str, to_lower: str) -> bool:
        if to in self.code_cache or to_lower in self.code_cache:
            return True
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return False
            for _addr in (to, to_lower):
                try:
                    cur = sync_db.execute('SELECT 1 FROM contract_v2 WHERE address = ?', _addr)
                    if cur.fetchone() is not None:
                        return True
                except Exception as _le:
                    bootstrap.logger.warning(f'[VM] deployed-code probe failed addr {str(_addr or '?')[:16]}: {str(_le or '?')[:16]}')
                    continue
        except Exception as _le:
            bootstrap.logger.warning(f'[VM] deployed-code probe error addr {str(to or '?')[:16]}: {str(_le or '?')[:16]}')
        return False

    def _call_contract(self, to: str, value: int, input_data: bytes, gas: int, caller: str) -> bootstrap.Tuple[bool, bytes]:
        if self.depth + 1 >= 1024:
            return (False, b'')
        gas = min(gas, max(0, self.gas - self.gas // 64))
        to = _normalize_call_address(to)
        to_lower = to.lower()
        if to_lower in PRECOMPILED and (not self._has_deployed_code(to, to_lower)):
            cell: bootstrap.List[int] = []
            ok, ret = self._execute_precompiled(to, input_data, value, gas, caller, cell)
            if ok and cell:
                self.gas -= cell[0]
            else:
                self.gas -= gas
            return (ok, ret)
        if to in self.reentrancy_lock:
            return (False, b'')
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return (False, b'')
            try:
                cur = sync_db.execute('SELECT bytecode FROM contract_v2 WHERE address = ?', to)
                row = cur.fetchone()
                if row:
                    bytecode = row[0]
                    self.code_cache[to] = bytes.fromhex(bytecode)
                else:
                    return (False, b'')
            except Exception:
                return (False, b'')
        saved_caller = self.balance_cache.get(caller, 0)
        saved_to = self.balance_cache.get(to, 0)
        if value > 0:
            if saved_caller < value:
                return (False, b'')
            self.balance_cache[caller] = saved_caller - value
            self.balance_cache[to] = saved_to + value
        if self.storage_address is not None and to.lower() == str(self.storage_address).lower():
            initial_storage = dict(self.storage_cache)
        else:
            initial_storage = self._load_storage_for(to)
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child.block_height = self.block_height
        child.block_ts = self.block_ts
        child.original_storage = self.original_storage
        success, ret, gas_used, logs = child.execute(bytecode, caller=caller, origin=self.origin, value=value, gas_limit=gas, contract_address=to, input_data=input_data, static=self.static_call, initial_storage=initial_storage, call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and (not child.reverted):
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return (True, ret)
        if value > 0:
            self.balance_cache[caller] = saved_caller
            self.balance_cache[to] = saved_to
        return (False, ret)

    def _callcode_contract(self, to: str, value: int, input_data: bytes, gas: int, caller: str) -> bootstrap.Tuple[bool, bytes]:
        to = _normalize_call_address(to)
        if self.depth + 1 >= 1024:
            return (False, b'')
        gas = min(gas, max(0, self.gas - self.gas // 64))
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return (False, b'')
            try:
                cur = sync_db.execute('SELECT bytecode FROM contract_v2 WHERE address = ?', to)
                row = cur.fetchone()
                if row:
                    bytecode = bytes.fromhex(row[0])
                    self.code_cache[to] = bytecode
                else:
                    return (False, b'')
            except Exception:
                return (False, b'')
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child.block_height = self.block_height
        child.block_ts = self.block_ts
        child.original_storage = self.original_storage
        success, ret, gas_used, logs = child.execute(bytecode, caller=self.caller, origin=self.origin, value=value, gas_limit=gas, contract_address=self.current_contract, input_data=input_data, static=self.static_call, storage_address=self.storage_address, initial_storage=dict(self.storage_cache), shared_context=True, call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and (not child.reverted):
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return (True, ret)
        return (False, ret)

    def _delegate_call(self, to: str, input_data: bytes, gas: int) -> bootstrap.Tuple[bool, bytes]:
        to = _normalize_call_address(to)
        if self.depth + 1 >= 1024:
            return (False, b'')
        gas = min(gas, max(0, self.gas - self.gas // 64))
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return (False, b'')
            try:
                cur = sync_db.execute('SELECT bytecode FROM contract_v2 WHERE address = ?', to)
                row = cur.fetchone()
                if row:
                    bytecode = bytes.fromhex(row[0])
                    self.code_cache[to] = bytecode
                else:
                    return (False, b'')
            except Exception:
                return (False, b'')
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child.block_height = self.block_height
        child.block_ts = self.block_ts
        child.original_storage = self.original_storage
        success, ret, gas_used, logs = child.execute(bytecode, caller=self.caller, origin=self.origin, value=self.value, gas_limit=gas, contract_address=self.current_contract, input_data=input_data, static=self.static_call, storage_address=self.storage_address, initial_storage=dict(self.storage_cache), shared_context=True, call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and (not child.reverted):
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return (True, ret)
        return (False, ret)

    def _static_call(self, to: str, input_data: bytes, gas: int) -> bootstrap.Tuple[bool, bytes]:
        if self.depth + 1 >= 1024:
            return (False, b'')
        gas = min(gas, max(0, self.gas - self.gas // 64))
        prev = self.static_call
        self.static_call = True
        try:
            return self._call_contract(to, 0, input_data, gas, self.caller)
        finally:
            self.static_call = prev

    def _execute_precompiled(self, address: str, input_data: bytes, value: int, gas: int, caller: str, gas_cost_out=None) -> bootstrap.Tuple[bool, bytes]:
        addr_lower = address.lower()
        activation = PRECOMPILED_VERSIONS.get(addr_lower)
        if activation is None:
            return (False, b'')
        if activation > self.block_height:
            return (False, b'')
        name = PRECOMPILED.get(addr_lower)
        if name is None:
            return (False, b'')

        def _charge(cost):
            if gas_cost_out is not None:
                gas_cost_out.append(cost)
            return cost <= gas
        if name == 'ecrecover':
            if not _charge(3000):
                return (False, b'\x00' * 32)
            if len(input_data) < 128:
                return (False, b'\x00' * 32)
            try:
                from eth_keys import keys
                hash_val = input_data[0:32]
                v = int.from_bytes(input_data[32:64], 'big')
                r = int.from_bytes(input_data[64:96], 'big')
                s = int.from_bytes(input_data[96:128], 'big')
                if r == 0 or s == 0:
                    return (False, b'\x00' * 32)
                if v in (27, 28):
                    recid = v - 27
                else:
                    recid = v
                sig = keys.Signature(vrs=(recid, r, s))
                pub = sig.recover_public_key_from_msg_hash(hash_val)
                addr = pub.to_checksum_address()
                return (True, b'\x00' * 12 + bytes.fromhex(addr[2:]))
            except Exception:
                return (False, b'\x00' * 32)
        elif name == 'sha256':
            if not _charge(60 + 12 * ((len(input_data) + 31) // 32)):
                return (False, b'')
            return (True, bootstrap.hashlib.sha256(input_data).digest())
        elif name == 'keccak256':
            if not _charge(30 + 6 * ((len(input_data) + 31) // 32)):
                return (False, b'')
            return (True, crypto.keccak_256(input_data))
        elif name == 'ripemd160':
            if not _charge(600 + 120 * ((len(input_data) + 31) // 32)):
                return (False, b'')
            if len(input_data) == 0:
                return (True, b'\x00' * 20)
            h = bootstrap.hashlib.new('ripemd160', input_data).digest()
            return (True, h + b'\x00' * 12)
        elif name == 'identity':
            if not _charge(15 + 3 * ((len(input_data) + 31) // 32)):
                return (False, b'')
            return (True, input_data)
        elif name == 'token':
            if not _charge(1000):
                return (False, b'')
            if len(input_data) < 4:
                return (False, b'')
            selector = input_data[:4]
            if selector == b'p\xa0\x821':
                if len(input_data) < 36:
                    return (False, b'')
                addr = input_data[4:36].hex()
                token_addr = self.current_contract
                bal = self.token_balance_cache.get((token_addr, addr), 0)
                return (True, bal.to_bytes(32, 'big'))
            else:
                return (False, b'')
        elif name == 'mcx':
            if not _charge(1000):
                return (False, b'')
            if len(input_data) < 4:
                return (False, b'')
            selector = input_data[:4]
            if selector == b'p\xa0\x821':
                if len(input_data) < 36:
                    return (False, b'')
                addr = input_data[4:36].hex()
                bal = self.balance_cache.get(addr, 0)
                return (True, bal.to_bytes(32, 'big'))
            elif selector == b'\xa9\x05\x9c\xbb':
                if len(input_data) < 68:
                    return (False, b'')
                if self.static_call:
                    return (False, b'')
                to = input_data[4:36].hex()
                amount = int.from_bytes(input_data[36:68], 'big')
                caller_bal = self.balance_cache.get(caller, 0)
                if caller_bal < amount:
                    return (False, b'\x00')
                self.balance_cache[caller] = caller_bal - amount
                self.balance_cache[to] = self.balance_cache.get(to, 0) + amount
                return (True, b'\x01')
            else:
                return (False, b'')
        elif name == 'htlc':
            if not config.HTLC_V1_ENABLED:
                return (False, b'')
            if not _charge(1000):
                return (False, b'')
            return self._execute_htlc(input_data, caller)
        elif name == 'blake2':
            return (False, b'')
        elif name == 'modexp':
            if len(input_data) < 96:
                return (False, b'')
            base_len = int.from_bytes(input_data[0:32], 'big')
            exp_len = int.from_bytes(input_data[32:64], 'big')
            mod_len = int.from_bytes(input_data[64:96], 'big')
            max_len = base_len if base_len >= mod_len else mod_len
            words = (max_len + 7) // 8
            mult = words * words
            _exp_off = 96 + base_len
            _exp_head_raw = input_data[_exp_off:_exp_off + 32]
            _exp_head_raw = _exp_head_raw + b'\x00' * (32 - len(_exp_head_raw))
            if exp_len <= 32:
                _exp_full_raw = input_data[_exp_off:_exp_off + exp_len]
                _exp_full_raw = _exp_full_raw + b'\x00' * (exp_len - len(_exp_full_raw))
                _exp_full = int.from_bytes(_exp_full_raw, 'big')
                adj = 0 if _exp_full == 0 else _exp_full.bit_length() - 1
            else:
                _head = int.from_bytes(_exp_head_raw, 'big')
                adj = 8 * (exp_len - 32) + (_head.bit_length() - 1)
            if adj < 1:
                adj = 1
            mx_cost = mult * adj // 3
            if mx_cost < 200:
                mx_cost = 200
            if not _charge(mx_cost):
                return (False, b'')
            _need = 96 + base_len + exp_len + mod_len
            if _need - len(input_data) > 16 * 1024 * 1024:
                return (False, b'')
            _padded = input_data + b'\x00' * (_need - len(input_data)) if _need > len(input_data) else input_data
            offset = 96
            base = int.from_bytes(_padded[offset:offset + base_len], 'big')
            offset += base_len
            exp = int.from_bytes(_padded[offset:offset + exp_len], 'big')
            offset += exp_len
            mod = int.from_bytes(_padded[offset:offset + mod_len], 'big')
            result = pow(base, exp, mod) if mod != 0 else 0
            return (True, result.to_bytes(mod_len, 'big') if mod_len > 0 else b'')
        elif name in ('ecAdd', 'ecMul', 'ecPairing'):
            try:
                try:
                    from py_ecc.bn128 import add, mul, pairing, G1, Z1, neg
                except ImportError:
                    from py_ecc.bn128 import add, pairing, G1, Z1, neg
                    from py_ecc.bn128 import multiply as mul
                if name == 'ecAdd':
                    if len(input_data) != 128:
                        return (False, b'')
                    if not _charge(150):
                        return (False, b'')
                    p1_bytes = input_data[:64]
                    p2_bytes = input_data[64:128]
                    p1 = _parse_bn256_point(p1_bytes)
                    p2 = _parse_bn256_point(p2_bytes)
                    if p1 is None or p2 is None:
                        return (False, b'')
                    result = add(p1 or None, p2 or None)
                    return (True, _encode_bn256_point(result))
                elif name == 'ecMul':
                    if len(input_data) != 96:
                        return (False, b'')
                    if not _charge(6000):
                        return (False, b'')
                    p_bytes = input_data[:64]
                    scalar_bytes = input_data[64:96]
                    p = _parse_bn256_point(p_bytes)
                    if p is None:
                        return (False, b'')
                    scalar = int.from_bytes(scalar_bytes, 'big')
                    result = mul(p or None, scalar)
                    return (True, _encode_bn256_point(result))
                elif name == 'ecPairing':
                    if len(input_data) % 192 != 0:
                        return (False, b'')
                    n_pairs = len(input_data) // 192
                    if not _charge(45000 + 34000 * n_pairs):
                        return (False, b'')
                    if n_pairs == 0:
                        return (True, b'\x01' + b'\x00' * 31)
                    try:
                        from py_ecc.bn128 import FQ2, FQ12, is_on_curve, b2
                    except ImportError:
                        return (False, b'')
                    try:
                        acc = FQ12.one()
                        for i in range(n_pairs):
                            g1_bytes = input_data[i * 192:i * 192 + 64]
                            p1 = _parse_bn256_point(g1_bytes)
                            if p1 is None:
                                return (False, b'')
                            x0 = int.from_bytes(input_data[i * 192 + 64:i * 192 + 96], 'big')
                            x1 = int.from_bytes(input_data[i * 192 + 96:i * 192 + 128], 'big')
                            y0 = int.from_bytes(input_data[i * 192 + 128:i * 192 + 160], 'big')
                            y1 = int.from_bytes(input_data[i * 192 + 160:i * 192 + 192], 'big')
                            if not _bn256_g2_canonical(x0, x1, y0, y1):
                                return (False, b'')
                            if x0 == 0 and x1 == 0 and (y0 == 0) and (y1 == 0):
                                g2 = None
                            else:
                                g2 = (FQ2([x0, x1]), FQ2([y0, y1]))
                                if not is_on_curve(g2, b2):
                                    return (False, b'')
                            if p1 == ():
                                continue
                            if g2 is None:
                                continue
                            acc = acc * pairing(g2, p1)
                        ok = acc == FQ12.one()
                    except Exception:
                        return (False, b'')
                    return (True, b'\x01' + b'\x00' * 31 if ok else b'\x00' * 32)
            except Exception:
                return (False, b'')
        elif name == 'svf_guard':
            return self._execute_svf_guard(input_data)
        return (False, b'')

    def _execute_svf_guard(self, input_data: bytes) -> bootstrap.Tuple[bool, bytes]:
        if len(input_data) < 4:
            return (False, b'')
        selector = input_data[:4]
        token_addr = self.current_contract or ''
        if token_addr.startswith('0x'):
            token_addr = token_addr[2:]
        token_addr = token_addr.lower()

        def _db_query(query, params=()):
            try:
                db = self.repo_provider() if self.repo_provider else None
            except Exception:
                return svf._DB_FAILED
            if db is None:
                return svf._DB_FAILED
            try:
                cur = db.execute(query, params)
                return cur.fetchall()
            except Exception:
                return svf._DB_FAILED

        def _db_exec(query, params=()):
            if not isinstance(params, tuple):
                return False
            try:
                db = self.repo_provider() if self.repo_provider else None
            except Exception:
                return False
            if db is None:
                return False
            self._pending_svf_db_exec.append((query, params))
            return True
        if selector == svf._svf_selector('requirePass()'):
            rows = _db_query('SELECT canonical_profile_bytes, effective_epoch FROM svf_profiles WHERE token_address = ?', (token_addr,))
            if rows is svf._DB_FAILED:
                return (False, b'')
            if not rows:
                return (True, b'\x01')
            profile_hex = rows[0][0]
            effective_epoch = int(rows[0][1]) if rows[0][1] is not None else 0
            try:
                profile_bytes = bytes.fromhex(profile_hex)
            except ValueError:
                return (False, b'')
            try:
                profile = svf.svf_parse_profile(profile_bytes)
            except svf.SVFReject:
                return (False, b'')
            block_h = int(self.block_height or 0)
            if block_h <= 0:
                return (False, b'')
            _mature = (block_h - svf.SVF_EPOCH_BLOCKS - 100) // svf.SVF_EPOCH_BLOCKS
            if _mature < 0:
                return (False, b'')
            target_epoch = _mature
            if target_epoch < effective_epoch:
                return (False, b'')
            rows = _db_query('SELECT height, block_hash, winner_pubkey, attested_size, attestation_weight, growth_present, record_hash FROM svf_evidence WHERE epoch_id = ? ORDER BY height', (target_epoch,))
            if rows is svf._DB_FAILED:
                return (False, b'')
            recs = []
            for r in rows or []:
                recs.append({'block_id': int(r[0]), 'block_hash': r[1], 'winner_pubkey': r[2], 'attested_size': int(r[3]), 'attestation_weight': int(r[4]), 'growth_present': bool(int(r[5])), 'record_hash': bytes.fromhex(r[6]) if r[6] else b'\x00' * 32})
            if len(recs) != svf.SVF_EPOCH_BLOCKS:
                return (False, b'')
            rows = _db_query('SELECT evidence_root, threshold_signature, committee_epoch, anchor_block_hash FROM svf_certificates WHERE evidence_epoch = ?', (target_epoch,))
            if rows is svf._DB_FAILED:
                return (False, b'')
            cert = None
            epoch_root = None
            _cert_committee_epoch = None
            _cert_anchor = None
            if rows:
                cert = {'threshold_signature': rows[0][1]}
                try:
                    epoch_root = bytes.fromhex(rows[0][0])
                except (ValueError, TypeError):
                    epoch_root = None
                try:
                    _cert_committee_epoch = int(rows[0][2])
                except (ValueError, TypeError):
                    _cert_committee_epoch = None
                _cert_anchor = rows[0][3] if isinstance(rows[0][3], str) else None
            if cert is not None:
                if svf_keys.SVF_GROUP_PUBLIC_KEY is None or epoch_root is None or _cert_committee_epoch is None or (not _cert_anchor):
                    return (False, b'')
                try:
                    import struct as _svf_struct
                    _cert_msg = b'MCX-SVF-EPOCH-BEACON-V1'
                    _cert_msg += _svf_struct.pack('>H', 1)
                    _cert_msg += _svf_struct.pack('>Q', int(config.CHAIN_ID))
                    _cert_msg += _svf_struct.pack('>Q', int(_cert_committee_epoch))
                    _cert_msg += _svf_struct.pack('>Q', int(target_epoch))
                    _cert_msg += _svf_struct.pack('>Q', int(target_epoch) * svf.SVF_EPOCH_BLOCKS)
                    _cert_msg += _svf_struct.pack('>Q', int(target_epoch) * svf.SVF_EPOCH_BLOCKS + svf.SVF_EPOCH_BLOCKS - 1)
                    _cert_msg += bytes.fromhex(_cert_anchor)
                    _cert_msg += epoch_root
                    _cert_sig = cert.get('threshold_signature') or ''
                    _cert_sig_bytes = bytes.fromhex(_cert_sig) if isinstance(_cert_sig, str) else bytes(_cert_sig)
                    if not svf_keys._svf_bls_verify(svf_keys.SVF_GROUP_PUBLIC_KEY, _cert_msg, _cert_sig_bytes):
                        return (False, b'')
                except (ValueError, TypeError):
                    return (False, b'')
            try:
                prof_hash = svf.svf_profile_hash(int(config.CHAIN_ID), token_addr, profile_bytes)
            except svf.SVFReject:
                return (False, b'')
            try:
                verdict = svf.evaluate_profile(profile, recs, block_h, challenge_seed=None, epoch_root=epoch_root, certificate=cert, chain_id=int(config.CHAIN_ID), token_address=token_addr, profile_hash=prof_hash.hex(), prune_blocks=100)
            except svf.SVFReject:
                return (False, b'')
            if verdict == 'PASS':
                return (True, b'\x01')
            return (False, b'')
        elif selector == svf._svf_selector('registerProfile(bytes)'):
            if len(input_data) < 4 + 32:
                return (False, b'')
            if len(input_data) < 4 + 32 + 32:
                return (False, b'')
            _off = int.from_bytes(input_data[4:36], 'big')
            if _off < 32 or 4 + _off + 32 > len(input_data):
                return (False, b'')
            _plen = int.from_bytes(input_data[4 + _off:4 + _off + 32], 'big')
            if _plen != svf.SVF_PROFILE_SIZE:
                return (False, b'')
            _pstart = 4 + _off + 32
            if _pstart + _plen > len(input_data):
                return (False, b'')
            profile_bytes = input_data[_pstart:_pstart + _plen]
            if len(profile_bytes) != svf.SVF_PROFILE_SIZE:
                return (False, b'')
            try:
                profile = svf.svf_parse_profile(profile_bytes)
            except svf.SVFReject:
                return (False, b'')
            try:
                prof_hash = svf.svf_profile_hash(int(config.CHAIN_ID), token_addr, profile_bytes)
            except svf.SVFReject:
                return (False, b'')
            rows = _db_query('SELECT profile_hash FROM svf_profiles WHERE token_address = ?', (token_addr,))
            if rows is svf._DB_FAILED:
                return (False, b'')
            if rows:
                _existing_hash = ''
                try:
                    _existing_hash = str(rows[0][0] or '').lower()
                except Exception:
                    _existing_hash = ''
                if _existing_hash and _existing_hash == prof_hash.hex().lower():
                    return (True, b'\x01')
                return (False, b'')
            block_h = int(self.block_height or 0)
            effective_epoch = block_h // svf.SVF_EPOCH_BLOCKS + 1
            runtime_code_hash = ''
            template_id = ''
            db = self.repo_provider() if self.repo_provider else None
            if db is not None:
                try:
                    candidates = [token_addr, '0x' + token_addr, token_addr.lower(), ('0x' + token_addr).lower()]
                    row = None
                    for cand in candidates:
                        try:
                            cur = db.execute('SELECT bytecode FROM contract_v2 WHERE address = ?', (cand,))
                            row = cur.fetchone()
                            if row:
                                break
                        except Exception:
                            continue
                    if row is None:
                        return (False, b'')
                    bytecode_hex = row[0]
                    if isinstance(bytecode_hex, str):
                        bytecode_bytes = bytes.fromhex(bytecode_hex)
                    else:
                        bytecode_bytes = bytes(bytecode_hex)
                    runtime_code_hash = bootstrap.hashlib.sha256(bytecode_bytes).hexdigest()
                    template_id = None
                    for tmpl_id, tmpl_hash in svf_keys.SVF_APPROVED_TEMPLATES.items():
                        if runtime_code_hash == tmpl_hash:
                            template_id = tmpl_id
                            break
                    if template_id is None:
                        return (False, b'')
                except Exception:
                    return (False, b'')
            if not runtime_code_hash:
                return (False, b'')
            ok = _db_exec('INSERT INTO svf_profiles (token_address, chain_id, runtime_code_hash, template_id, profile_schema_version, canonical_profile_bytes, profile_hash, registrant, registration_tx_hash, registration_block_height, effective_epoch, status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', (token_addr, int(config.CHAIN_ID), runtime_code_hash, template_id, 1, profile_bytes.hex(), prof_hash.hex(), token_addr, '', block_h, effective_epoch, 'ACTIVE'))
            if ok:
                self._pending_svf_profile = {'token_address': token_addr, 'chain_id': int(config.CHAIN_ID), 'runtime_code_hash': runtime_code_hash, 'template_id': template_id, 'canonical_profile_bytes': profile_bytes.hex(), 'profile_hash': prof_hash.hex(), 'registration_block_height': block_h, 'effective_epoch': effective_epoch, 'profile': profile}
            if not ok:
                return (False, b'')
            return (True, b'\x01')
        elif selector == svf._svf_selector('profileOf(address)'):
            rows = _db_query('SELECT profile_hash FROM svf_profiles WHERE token_address = ?', (token_addr,))
            if rows is svf._DB_FAILED:
                return (False, b'')
            if rows:
                return (True, bytes.fromhex(rows[0][0]))
            return (True, b'\x00' * 32)
        elif selector == svf._svf_selector('epochStatus(address,uint64)'):
            return (True, b'\x00')
        elif selector == svf._svf_selector('protocolInfo()'):
            info = bootstrap.struct.pack('>H', 1)
            info += bootstrap.struct.pack('>Q', svf.SVF_ACTIVATION_HEIGHT if svf.SVF_ACTIVATION_HEIGHT is not None else 0)
            info += bootstrap.struct.pack('>Q', svf.SVF_EPOCH_BLOCKS)
            return (True, info)
        return (False, b'')

    def _execute_htlc(self, input_data: bytes, caller: str) -> bootstrap.Tuple[bool, bytes]:
        SELECTOR_NEW_CONTRACT = crypto.keccak_256(b'newContract(address,bytes32,uint256)')[:4]
        SELECTOR_WITHDRAW = crypto.keccak_256(b'withdraw(bytes32,bytes32)')[:4]
        SELECTOR_REFUND = crypto.keccak_256(b'refund(bytes32)')[:4]
        SELECTOR_GET_CONTRACT = crypto.keccak_256(b'getContract(bytes32)')[:4]
        if len(input_data) < 4:
            return (False, b'')
        selector = input_data[:4]
        if selector == SELECTOR_NEW_CONTRACT:
            if len(input_data) < 4 + 20 + 32 + 32:
                return (False, b'')
            if self.static_call:
                return (False, b'')
            offset = 4
            receiver = input_data[offset:offset + 20].hex()
            offset += 20
            hashlock = input_data[offset:offset + 32].hex()
            offset += 32
            timelock = int.from_bytes(input_data[offset:offset + 32], 'big')
            amount = self.value
            token = b'\x00' * 20
            htlc_id = bootstrap.secrets.token_hex(32)
            if token == b'\x00' * 20:
                if self.balance_cache.get(caller, 0) < amount:
                    return (False, b'')
                self.balance_cache[caller] = self.balance_cache.get(caller, 0) - amount
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) + amount
            else:
                key = (token.hex(), caller)
                if self.token_balance_cache.get(key, 0) < amount:
                    return (False, b'')
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[token.hex(), htlc_id] = self.token_balance_cache.get((token.hex(), htlc_id), 0) + amount
            htlc_data = {'id': htlc_id, 'sender': caller, 'receiver': receiver, 'hashlock': hashlock, 'timelock': timelock, 'amount': amount, 'token_address': '0x' + token.hex() if token != b'\x00' * 20 else '', 'status': 'open'}
            self.htlc_repo.create(htlc_data)
            return (True, bytes.fromhex(htlc_id))
        elif selector == SELECTOR_WITHDRAW:
            if len(input_data) < 4 + 32 + 32:
                return (False, b'')
            if self.static_call:
                return (False, b'')
            htlc_id = input_data[4:36].hex()
            preimage = input_data[36:68].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc or htlc['status'] != 'open':
                return (False, b'')
            if crypto.keccak_256(bytes.fromhex(preimage)).hex() != htlc['hashlock']:
                return (False, b'')
            if bootstrap.time.time() > htlc['timelock']:
                return (False, b'')
            token = htlc['token_address']
            amount = htlc['amount']
            receiver = htlc['receiver']
            if token == '' or token == '0x' + '00' * 20:
                if self.balance_cache.get(htlc_id, 0) < amount:
                    return (False, b'')
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) - amount
                self.balance_cache[receiver] = self.balance_cache.get(receiver, 0) + amount
            else:
                key = (token, htlc_id)
                if self.token_balance_cache.get(key, 0) < amount:
                    return (False, b'')
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[token, receiver] = self.token_balance_cache.get((token, receiver), 0) + amount
            self.htlc_repo.update_status(htlc_id, 'claimed', bootstrap.time.time(), None)
            return (True, b'\x01')
        elif selector == SELECTOR_REFUND:
            if len(input_data) < 4 + 32:
                return (False, b'')
            if self.static_call:
                return (False, b'')
            htlc_id = input_data[4:36].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc or htlc['status'] != 'open':
                return (False, b'')
            if bootstrap.time.time() <= htlc['timelock']:
                return (False, b'')
            sender = htlc['sender']
            token = htlc['token_address']
            amount = htlc['amount']
            if token == '' or token == '0x' + '00' * 20:
                if self.balance_cache.get(htlc_id, 0) < amount:
                    return (False, b'')
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) - amount
                self.balance_cache[sender] = self.balance_cache.get(sender, 0) + amount
            else:
                key = (token, htlc_id)
                if self.token_balance_cache.get(key, 0) < amount:
                    return (False, b'')
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[token, sender] = self.token_balance_cache.get((token, sender), 0) + amount
            self.htlc_repo.update_status(htlc_id, 'refunded', None, bootstrap.time.time())
            return (True, b'\x01')
        elif selector == SELECTOR_GET_CONTRACT:
            if len(input_data) < 4 + 32:
                return (False, b'')
            htlc_id = input_data[4:36].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc:
                return (False, b'')
            sender = bytes.fromhex(htlc['sender'][2:])
            receiver = bytes.fromhex(htlc['receiver'][2:])
            amount = htlc['amount'].to_bytes(32, 'big')
            hashlock = bytes.fromhex(htlc['hashlock'])
            timelock = htlc['timelock'].to_bytes(32, 'big')
            status = (1 if htlc['status'] == 'open' else 0).to_bytes(1, 'big')
            preimage = b'\x00' * 32
            return (True, sender + receiver + amount + hashlock + timelock + status + preimage)
        else:
            return (False, b'')
