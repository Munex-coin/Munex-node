#!/usr/bin/env python3
_DEPS = [('yaml', 'PyYAML', True), ('requests', 'requests', True), ('rlp', 'rlp', True), ('eth_utils', 'eth-utils', True), ('eth_account', 'eth-account', True), ('eth_keys', 'eth-keys', True), ('cryptography', 'cryptography', True), ('argon2', 'argon2-cffi', True), ('bcrypt', 'bcrypt', True), ('aiohttp', 'aiohttp', True), ('websockets', 'websockets', True), ('pythonjsonlogger', 'python-json-logger', True), ('py_ecc', 'py_ecc', True), ('psycopg2', 'psycopg2-binary', False), ('asyncpg', 'asyncpg', False), ('bip32utils', 'bip32utils', False), ('uvloop', 'uvloop', False), ('kademlia', 'kademlia', False), ('Crypto', 'pycryptodome', False)]

def _auto_install_enabled(config=None) -> bool:
    import os
    raw = os.environ.get('MCX_ALLOW_AUTO_INSTALL', '').strip().lower()
    if raw in ('0', 'false', 'no', 'off'):
        return False
    if raw in ('1', 'true', 'yes', 'on'):
        return True
    return True

def _ensure_dependencies() -> None:
    import os, sys
    if os.environ.get('MCX_SKIP_AUTO_INSTALL', '').strip().lower() in ('1', 'true', 'yes', 'on'):
        print('[MCX] Dependency auto-install skipped (environment override).', file=sys.stderr)
        return
    try:
        import importlib.util as _ilu
    except Exception:
        return

    def _absent():
        out = []
        for imp, pip_name, required in _DEPS:
            if imp == 'uvloop' and sys.platform == 'win32':
                continue
            try:
                found = _ilu.find_spec(imp) is not None
            except Exception:
                found = False
            if not found:
                out.append((pip_name, required))
        return out
    missing = _absent()
    if not missing:
        return
    required_missing = [p for p, req in missing if req]
    optional_missing = [p for p, req in missing if not req]
    if required_missing:
        print('[MCX] Missing required Python packages: ' + ', '.join(required_missing), file=sys.stderr)
    if optional_missing:
        print('[MCX] Missing optional Python packages: ' + ', '.join(optional_missing), file=sys.stderr)
    if not missing:
        return
    try:
        ans = input('[MCX] Install missing Python packages now? (y/n): ').strip().lower()
    except EOFError:
        if False:
            ans = 'y'
        else:
            print('[MCX] Auto-install declined (non-interactive, no MCX_ALLOW_AUTO_INSTALL=1).', file=sys.stderr)
            required_missing = [p for p, req in missing if req]
            if required_missing:
                print('[MCX] FATAL: required packages missing: ' + ', '.join(required_missing), file=sys.stderr)
                sys.exit(1)
            return
    if ans not in ('y', 'yes'):
        required_missing = [p for p, req in missing if req]
        if required_missing:
            print('[MCX] FATAL: required packages missing: ' + ', '.join(required_missing), file=sys.stderr)
            sys.exit(1)
        print('[MCX] Optional packages unavailable (some features stay disabled).', file=sys.stderr)
        return
    import subprocess, tempfile

    def _norm(name):
        return name.strip().lower().replace('_', '-')
    _pg = {'psycopg2-binary', 'asyncpg'}
    _pg_opt_in = os.environ.get('MCX_INSTALL_PG_DRIVERS', '').strip().lower() in ('1', 'true', 'yes', 'on')
    _termux = sys.platform == 'android' or 'com.termux' in os.environ.get('PREFIX', '')
    required_names = [p for p, req in missing if req]
    optional_names = [p for p, req in missing if not req and (_pg_opt_in or _norm(p) not in {_norm(x) for x in _pg}) and (not (_termux and _norm(p) == 'uvloop'))]
    print('[MCX] Installing missing Python packages: ' + ', '.join(required_names + optional_names), file=sys.stderr)

    def _pip(args):
        try:
            r = subprocess.run([sys.executable, '-m', 'pip', 'install', '--prefer-binary', *args], timeout=900)
            return r.returncode == 0
        except Exception as e:
            print(f'[MCX] pip error: {e}', file=sys.stderr)
            return False
    if required_names:
        done = False
        _manifest = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements-mcx78.txt')
        if os.path.exists(_manifest):
            _req_set = {_norm(pip) for _imp, pip, req in _DEPS if req}
            _keep = []
            with open(_manifest, encoding='utf-8') as _mf:
                for _line in _mf:
                    _raw = _line.strip()
                    if not _raw or _raw.startswith('#'):
                        continue
                    _nm = _raw
                    for _sep in ('==', '>=', '<=', '~=', '!=', '>', '<', '[', ';', ' '):
                        _nm = _nm.split(_sep)[0]
                    if _norm(_nm) in _req_set:
                        _keep.append(_raw)
            if _keep:
                _tf = tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False, encoding='utf-8')
                _tf.write('\n'.join(_keep) + '\n')
                _tf.close()
                try:
                    done = _pip(['-r', _tf.name])
                finally:
                    try:
                        os.unlink(_tf.name)
                    except OSError:
                        pass
        if not done:
            for _name in required_names:
                if not _pip([_name]):
                    print(f'[MCX] could not install required package: {_name}', file=sys.stderr)
                    if _termux:
                        print("[MCX] On Termux, packages that need Rust (for example pydantic-core, pulled in by eth-utils 6.x) must be built with Termux's own toolchain. Run: pkg install rust clang  then rerun node.py. Auto-install cannot fix this by picking another version.", file=sys.stderr)
    for _name in optional_names:
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', '--prefer-binary', _name], timeout=600)
        except Exception as e:
            print(f'[MCX] optional package {_name} not installed: {e}', file=sys.stderr)
    still_missing = _absent()
    required_missing = [p for p, req in still_missing if req]
    if required_missing:
        print('[MCX] FATAL: required packages still missing after install attempt: ' + ', '.join(required_missing), file=sys.stderr)
        print('[MCX] Fix pip/network access and rerun, or set MCX_SKIP_AUTO_INSTALL=1 if you manage dependencies yourself.', file=sys.stderr)
        sys.exit(1)
    if still_missing:
        print('[MCX] Optional packages unavailable (some features stay disabled): ' + ', '.join((p for p, _ in still_missing)), file=sys.stderr)
_ensure_dependencies()
import sys, io, os, time, json, hashlib, hmac, secrets, random, struct, socket, subprocess, re, argparse, traceback, logging, base64, binascii, ipaddress, math, asyncio, aiohttp, websockets, signal, importlib, warnings, sqlite3, copy, threading
from datetime import datetime
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
import multiprocessing as mp
import heapq
import tempfile
warnings.filterwarnings('default')
if sys.platform == 'win32':
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8')
        except Exception:
            pass
import requests
try:
    import rlp
except ImportError:
    rlp = None
try:
    from eth_utils import keccak as eth_keccak
except ImportError:
    import Crypto.Hash.keccak

    def eth_keccak(data: bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')
        k = Crypto.Hash.keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
try:
    from eth_account import Account
except ImportError:
    Account = None
from cryptography.hazmat.primitives.asymmetric import ec
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
    MLKEM_AVAILABLE = True
except (ImportError, AttributeError):
    mlkem = None
    MLKEM_AVAILABLE = False
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
try:
    from argon2 import PasswordHasher
except ImportError:
    PasswordHasher = None
try:
    import bcrypt
except ImportError:
    bcrypt = None
from logging.handlers import RotatingFileHandler
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None
try:
    import asyncpg
except ImportError:
    asyncpg = None
from urllib.parse import urlparse
import urllib.request
try:
    import bip32utils
except ImportError:
    bip32utils = None
try:
    from pythonjsonlogger import jsonlogger

    class JsonFormatter(jsonlogger.JsonFormatter):

        def add_fields(self, log_record, record, message_dict):
            super().add_fields(log_record, record, message_dict)
            log_record['level'] = record.levelname
            log_record['timestamp'] = time.time()
except ImportError:

    class JsonFormatter(logging.Formatter):

        def format(self, record):
            return json.dumps({'timestamp': time.time(), 'level': record.levelname, 'name': record.name, 'message': record.getMessage()})
log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(trace_id)s] %(name)s: %(message)s'))
logger = logging.getLogger('mcx')
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)
trace_id_var: ContextVar[str] = ContextVar('mcx_trace_id', default='-')

def new_trace_id() -> str:
    return secrets.token_hex(8)

def set_trace_id(tid: Optional[str]=None) -> str:
    tid = tid or new_trace_id()
    trace_id_var.set(tid)
    return tid

class _TraceIdFilter(logging.Filter):

    def filter(self, record):
        try:
            record.trace_id = trace_id_var.get()
        except Exception:
            record.trace_id = '-'
        return True
_trace_filter = _TraceIdFilter()
for _h in list(logger.handlers):
    _h.addFilter(_trace_filter)
ph = PasswordHasher(time_cost=4, memory_cost=262144, parallelism=8, hash_len=32, salt_len=16) if PasswordHasher is not None else None
if sys.platform != 'win32':
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass
HAVE_RESOURCE = sys.platform != 'win32'
if HAVE_RESOURCE:
    import resource
try:
    import yaml
except ImportError:
    print('[MCX] FATAL: PyYAML is required but not installed.', file=sys.stderr)
    print('[MCX] Run: pip install PyYAML  (or leave startup auto-install enabled instead of skipping it).', file=sys.stderr)
    sys.exit(1)
try:
    from logging.handlers import TimedRotatingFileHandler

    class SafeTimedRotatingFileHandler(TimedRotatingFileHandler):

        def doRollover(self):
            try:
                super().doRollover()
            except PermissionError:
                self.rolloverAt = self.computeRollover(time.time())
    file_handler = SafeTimedRotatingFileHandler('mcx.log', when='midnight', interval=1, backupCount=5)
    file_handler.setFormatter(JsonFormatter('%(timestamp)s %(level)s [%(trace_id)s] %(name)s %(message)s'))
    file_handler.addFilter(_trace_filter)
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f'File logging disabled: {e}')
RESET, GREEN, CYAN, YELLOW, RED, BOLD = ('\x1b[0m', '\x1b[92m', '\x1b[96m', '\x1b[93m', '\x1b[91m', '\x1b[1m')
