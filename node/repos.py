import bootstrap
import config
import crypto
import util
import maze

class BlockRepo:

    def __init__(self, db):
        self.db = db

    def _unpack_block(self, row):
        if not row:
            return row
        if self.db.db_type == 'sqlite':
            row['miners'] = row['miners'].split(',') if row['miners'] else []
            row['tx_hashes'] = bootstrap.json.loads(row['tx_hashes']) if row['tx_hashes'] else []
        proof = row.get('proof')
        if proof:
            if isinstance(proof, str):
                try:
                    proof = bootstrap.json.loads(proof)
                except Exception:
                    proof = {}
            for k, v in proof.items():
                if k in maze._BLOCK_PROOF_KEYS:
                    row[k] = v
            del row['proof']
        return row

    async def create(self, block):
        proof_fields = {k: block[k] for k in ('winner', 'producer_pub', 'signature', 'state_root', 'transactions', 'maze_attestation', 'reward_wallet', 'maze_updates', 'attestation_proof', 'global_shrink_factor', 'slashes', 'maze_state', 'svf_epoch_certificates', 'lottery_draw') if k in block}
        proof_json = bootstrap.json.dumps(proof_fields)
        if self.db.db_type == 'sqlite':
            query = 'INSERT INTO blocks (id,ts,phash,miners,hash,reward,tx_count,merkle_root,nonce,difficulty,version,challenge,coverage,total_tx_value,total_fees,tx_hashes,finalized,proof) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
            params = (block['id'], block['ts'], block['phash'], ','.join((str(m) for m in block.get('miners', []))), block['hash'], block['reward'], block['tx_count'], block['merkle_root'], 0, block['difficulty'], block['version'], block['challenge'], block['coverage'], block['total_tx_value'], block['total_fees'], bootstrap.json.dumps(block['tx_hashes']), block.get('finalized', False), proof_json)
        else:
            query = 'INSERT INTO blocks (id,ts,phash,miners,hash,reward,tx_count,merkle_root,nonce,difficulty,version,challenge,coverage,total_tx_value,total_fees,tx_hashes,finalized,proof) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)'
            params = (block['id'], block['ts'], block['phash'], block['miners'], block['hash'], block['reward'], block['tx_count'], block['merkle_root'], 0, block['difficulty'], block['version'], block['challenge'], block['coverage'], block['total_tx_value'], block['total_fees'], block['tx_hashes'], block.get('finalized', False), proof_json)
        await self.db.execute_dml(query, *params)
        if block.get('id', 0) > 0:
            _rb = await self.get_by_id(block['id'])
            if _rb is not None:
                _rehash = crypto.calculate_block_hash({k: v for k, v in _rb.items() if k not in maze.CONSENSUS_EXCLUDED_FIELDS})
                if _rb.get('hash') != _rehash:
                    raise RuntimeError(f'R16 block {block['id']} hash did not survive storage (stored={block.get('hash')} reloaded={_rehash})')

    async def get_by_id(self, block_id):
        query = 'SELECT * FROM blocks WHERE id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM blocks WHERE id = $1'
        return self._unpack_block(await self.db.fetchrow(query, block_id))

    async def get_latest(self):
        query = 'SELECT * FROM blocks ORDER BY id DESC LIMIT 1'
        return self._unpack_block(await self.db.fetchrow(query))

    async def get_range(self, start, end, limit=100):
        query = 'SELECT * FROM blocks WHERE id >= ? AND id <= ? ORDER BY id LIMIT ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM blocks WHERE id >= $1 AND id <= $2 ORDER BY id LIMIT $3'
        return [self._unpack_block(r) for r in await self.db.fetch(query, start, end, limit)]

    async def mark_finalized(self, block_id):
        query = 'UPDATE blocks SET finalized = 1 WHERE id = ?' if self.db.db_type == 'sqlite' else 'UPDATE blocks SET finalized = TRUE WHERE id = $1'
        await self.db.execute_dml(query, block_id)

class TransactionRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, tx):
        _data = tx.get('data', {})
        try:
            _burn = int(tx.get('_burn_tax', 0) or 0)
        except (TypeError, ValueError):
            _burn = 0
        if _burn > 0:
            _data = dict(_data) if isinstance(_data, dict) else {}
            _data['_burn_tax'] = _burn
        try:
            _vmv = int(tx.get('_value_moved', 0) or 0)
        except (TypeError, ValueError):
            _vmv = 0
        if _vmv:
            if isinstance(_data, dict):
                _data = dict(_data)
            elif isinstance(_data, (bytes, bytearray)):
                _data = {'raw': bytes(_data).hex()}
            else:
                _data = {'raw': _data}
            _data['_value_moved'] = _vmv
        if self.db.db_type == 'sqlite':
            query = 'INSERT OR REPLACE INTO transactions (tx_hash,from_wallet,to_wallet,amount,fee,timestamp,block_id,status,tx_type,signature,nonce,confirmations,data,confirmed,token_address,contract_address,function,params) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
            params = (tx['tx_hash'], tx['from_wallet'], tx['to_wallet'], tx['amount'], tx['fee'], tx['timestamp'], tx.get('block_id', -1), tx['status'], tx['tx_type'], tx.get('signature', ''), tx.get('nonce', 0), tx.get('confirmations', 0), bootstrap.json.dumps(_data), tx.get('confirmed', False), tx.get('token_address', ''), tx.get('contract_address', ''), tx.get('function', ''), bootstrap.json.dumps(tx.get('params', [])))
        else:
            query = 'INSERT INTO transactions (tx_hash,from_wallet,to_wallet,amount,fee,timestamp,block_id,status,tx_type,signature,nonce,confirmations,data,confirmed,token_address,contract_address,function,params) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT (tx_hash) DO UPDATE SET block_id=$7, status=$8, confirmed=$14'
            params = (tx['tx_hash'], tx['from_wallet'], tx['to_wallet'], tx['amount'], tx['fee'], tx['timestamp'], tx.get('block_id', -1), tx['status'], tx['tx_type'], tx.get('signature', ''), tx.get('nonce', 0), tx.get('confirmations', 0), bootstrap.json.dumps(_data), tx.get('confirmed', False), tx.get('token_address', ''), tx.get('contract_address', ''), tx.get('function', ''), bootstrap.json.dumps(tx.get('params', [])))
        await self.db.execute_dml(query, *params)

    async def update_status(self, tx_hash, status, block_id):
        query = 'UPDATE transactions SET status = ?, block_id = ?, confirmed = 1 WHERE tx_hash = ?' if self.db.db_type == 'sqlite' else 'UPDATE transactions SET status = $1, block_id = $2, confirmed = TRUE WHERE tx_hash = $3'
        await self.db.execute_dml(query, status, block_id, tx_hash)

    async def get_pending(self, limit=1000):
        query = "SELECT * FROM transactions WHERE status = 'pending' ORDER BY fee DESC, timestamp ASC LIMIT ?" if self.db.db_type == 'sqlite' else "SELECT * FROM transactions WHERE status = 'pending' ORDER BY fee DESC, timestamp ASC LIMIT $1"
        return await self.db.fetch(query, limit)

    async def get_by_hash(self, tx_hash):
        query = 'SELECT * FROM transactions WHERE tx_hash = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM transactions WHERE tx_hash = $1'
        return await self.db.fetchrow(query, tx_hash)

    async def get_for_wallet(self, wallet, limit=100):
        query = 'SELECT * FROM transactions WHERE from_wallet = ? OR to_wallet = ? ORDER BY timestamp DESC LIMIT ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM transactions WHERE from_wallet = $1 OR to_wallet = $2 ORDER BY timestamp DESC LIMIT $3'
        return await self.db.fetch(query, wallet, wallet, limit)

class BalanceRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, wallet):
        query = 'SELECT bal FROM balances WHERE wallet = ?' if self.db.db_type == 'sqlite' else 'SELECT bal FROM balances WHERE wallet = $1'
        row = await self.db.fetchrow(query, wallet.lower() if isinstance(wallet, str) else wallet)
        return row['bal'] if row else 0

    async def set(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO balances (wallet, bal) VALUES (?,?)', w, amount)
        else:
            await self.db.execute_dml('INSERT INTO balances (wallet, bal, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (wallet) DO UPDATE SET bal = $2, updated_at = NOW()', w, amount)

    async def add(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        if self.db.db_type == 'sqlite':
            await self.set(w, await self.get(w) + amount)
        else:
            await self.db.execute_dml('INSERT INTO balances (wallet, bal) VALUES ($1,$2) ON CONFLICT (wallet) DO UPDATE SET bal = balances.bal + $2, updated_at = NOW()', w, amount)

    async def subtract(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        current = await self.get(w)
        if current < amount:
            return False
        await self.set(w, current - amount)
        return True

class MinerRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, miner):
        priv_enc = miner.get('private_key_encrypted')
        if isinstance(priv_enc, dict):
            priv_enc = bootstrap.json.dumps(priv_enc)
        elif priv_enc is None:
            priv_enc = ''
        if self.db.db_type == 'sqlite':
            query = 'INSERT INTO miners (miner_id,wallet,pub,rewards,blocks,slashes,uptime,today_uptime,type,liquidity,fees,last_ping,banned_until,created_at,last_block,consecutive_misses,total_uptime,ip_address,node_id,version,active,confirmed_balance,password_hash,private_key_encrypted,gas_collected,maze_wins,block_signing_pub) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner.get('rewards', 0), miner.get('blocks', 0), miner.get('slashes', 0), miner.get('uptime', 0), miner.get('today_uptime', 0), miner.get('type', 'web'), miner.get('liquidity', 0), miner.get('fees', 0), miner.get('last_ping', bootstrap.time.time()), miner.get('banned_until', 0), miner.get('created_at', bootstrap.time.time()), miner.get('last_block', 0), miner.get('consecutive_misses', 0), miner.get('total_uptime', 0), miner.get('ip_address', ''), miner.get('node_id', ''), miner.get('version', config.VERSION), 1 if miner.get('active', True) else 0, miner.get('confirmed_balance', 0), miner.get('password_hash', ''), priv_enc, miner.get('gas_collected', 0), miner.get('maze_wins', 0), miner.get('block_signing_pub', ''))
        else:
            query = 'INSERT INTO miners (miner_id,wallet,pub,rewards,blocks,slashes,uptime,today_uptime,type,liquidity,fees,last_ping,banned_until,created_at,last_block,consecutive_misses,total_uptime,ip_address,node_id,version,active,confirmed_balance,password_hash,private_key_encrypted,gas_collected,maze_wins,block_signing_pub) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)'
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner.get('rewards', 0), miner.get('blocks', 0), miner.get('slashes', 0), miner.get('uptime', 0), miner.get('today_uptime', 0), miner.get('type', 'web'), miner.get('liquidity', 0), miner.get('fees', 0), miner.get('last_ping', bootstrap.time.time()), miner.get('banned_until', 0), miner.get('last_block', 0), miner.get('consecutive_misses', 0), miner.get('total_uptime', 0), miner.get('ip_address', ''), miner.get('node_id', ''), miner.get('version', config.VERSION), miner.get('active', True), miner.get('confirmed_balance', 0), miner.get('password_hash', ''), priv_enc, miner.get('gas_collected', 0), miner.get('maze_wins', 0), miner.get('block_signing_pub', ''))
        await self.db.execute_dml(query, *params)

    async def update(self, miner):
        priv_enc = miner.get('private_key_encrypted')
        if isinstance(priv_enc, dict):
            priv_enc = bootstrap.json.dumps(priv_enc)
        elif priv_enc is None:
            priv_enc = ''
        if self.db.db_type == 'sqlite':
            query = 'UPDATE miners SET wallet=?,pub=?,rewards=?,blocks=?,slashes=?,uptime=?,today_uptime=?,type=?,liquidity=?,fees=?,last_ping=?,banned_until=?,last_block=?,consecutive_misses=?,total_uptime=?,ip_address=?,node_id=?,version=?,active=?,confirmed_balance=?,password_hash=?,private_key_encrypted=?,gas_collected=?,maze_wins=?,block_signing_pub=? WHERE miner_id=?'
            params = (miner['wallet'], miner['pub'], miner['rewards'], miner['blocks'], miner['slashes'], miner['uptime'], miner['today_uptime'], miner['type'], miner['liquidity'], miner['fees'], miner['last_ping'], miner['banned_until'], miner['last_block'], miner['consecutive_misses'], miner['total_uptime'], miner['ip_address'], miner['node_id'], miner['version'], 1 if miner['active'] else 0, miner['confirmed_balance'], miner['password_hash'], priv_enc, miner['gas_collected'], miner['maze_wins'], miner.get('block_signing_pub', ''), miner['miner_id'])
        else:
            query = 'UPDATE miners SET wallet=$2,pub=$3,rewards=$4,blocks=$5,slashes=$6,uptime=$7,today_uptime=$8,type=$9,liquidity=$10,fees=$11,last_ping=$12,banned_until=$13,last_block=$14,consecutive_misses=$15,total_uptime=$16,ip_address=$17,node_id=$18,version=$19,active=$20,confirmed_balance=$21,password_hash=$22,private_key_encrypted=$23,gas_collected=$24,maze_wins=$25,block_signing_pub=$26 WHERE miner_id=$1'
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner['rewards'], miner['blocks'], miner['slashes'], miner['uptime'], miner['today_uptime'], miner['type'], miner['liquidity'], miner['fees'], miner['last_ping'], miner['banned_until'], miner['last_block'], miner['consecutive_misses'], miner['total_uptime'], miner['ip_address'], miner['node_id'], miner['version'], miner['active'], miner['confirmed_balance'], miner['password_hash'], priv_enc, miner['gas_collected'], miner['maze_wins'], miner.get('block_signing_pub', ''))
        await self.db.execute_dml(query, *params)

    async def get(self, miner_id):
        query = 'SELECT * FROM miners WHERE miner_id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM miners WHERE miner_id = $1'
        row = await self.db.fetchrow(query, miner_id)
        if row and row.get('private_key_encrypted'):
            try:
                val = bootstrap.json.loads(row['private_key_encrypted'])
                if isinstance(val, dict):
                    row['private_key_encrypted'] = val
            except Exception:
                pass
        return row

    async def get_active(self):
        if self.db.db_type == 'sqlite':
            rows = await self.db.fetch('SELECT * FROM miners WHERE active = 1 AND banned_until < ?', bootstrap.time.time())
        else:
            rows = await self.db.fetch('SELECT * FROM miners WHERE active = TRUE AND banned_until < EXTRACT(EPOCH FROM NOW())')
        for row in rows:
            if row.get('private_key_encrypted'):
                try:
                    val = bootstrap.json.loads(row['private_key_encrypted'])
                    if isinstance(val, dict):
                        row['private_key_encrypted'] = val
                except Exception:
                    pass
        return rows

    async def get_by_wallet(self, wallet):
        query = 'SELECT * FROM miners WHERE wallet = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM miners WHERE wallet = $1'
        rows = await self.db.fetch(query, wallet)
        for row in rows:
            if row.get('private_key_encrypted'):
                try:
                    val = bootstrap.json.loads(row['private_key_encrypted'])
                    if isinstance(val, dict):
                        row['private_key_encrypted'] = val
                except Exception:
                    pass
        return rows

    async def update_last_ping(self, miner_id):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE miners SET last_ping = ? WHERE miner_id = ?', bootstrap.time.time(), miner_id)
        else:
            await self.db.execute_dml('UPDATE miners SET last_ping = EXTRACT(EPOCH FROM NOW()) WHERE miner_id = $1', miner_id)

    async def increment_blocks(self, miner_id, reward):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE miners SET blocks = blocks + 1, rewards = rewards + ? WHERE miner_id = ?', reward, miner_id)
        else:
            await self.db.execute_dml('UPDATE miners SET blocks = blocks + 1, rewards = rewards + $1 WHERE miner_id = $2', reward, miner_id)

class NodeRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, node):
        if self.db.db_type == 'sqlite':
            query = 'INSERT INTO nodes (node_id,wallet,ip,port,last_seen,height,active,rewards_earned,version,mining_enabled,staking_enabled,last_sync,is_multisig_signer,public_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], 1 if node['active'] else 0, node['rewards_earned'], node['version'], 1 if node['mining_enabled'] else 0, 1 if node['staking_enabled'] else 0, node['last_sync'], 1 if node['is_multisig_signer'] else 0, node['public_key'])
        else:
            query = 'INSERT INTO nodes (node_id,wallet,ip,port,last_seen,height,active,rewards_earned,version,mining_enabled,staking_enabled,last_sync,is_multisig_signer,public_key) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)'
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], node['active'], node['rewards_earned'], node['version'], node['mining_enabled'], node['staking_enabled'], node['last_sync'], node['is_multisig_signer'], node['public_key'])
        await self.db.execute_dml(query, *params)

    async def update(self, node):
        if self.db.db_type == 'sqlite':
            query = 'UPDATE nodes SET wallet=?,ip=?,port=?,last_seen=?,height=?,active=?,rewards_earned=?,version=?,mining_enabled=?,staking_enabled=?,last_sync=?,is_multisig_signer=?,public_key=? WHERE node_id=?'
            params = (node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], 1 if node['active'] else 0, node['rewards_earned'], node['version'], 1 if node['mining_enabled'] else 0, 1 if node['staking_enabled'] else 0, node['last_sync'], 1 if node['is_multisig_signer'] else 0, node['public_key'], node['node_id'])
        else:
            query = 'UPDATE nodes SET wallet=$2,ip=$3,port=$4,last_seen=$5,height=$6,active=$7,rewards_earned=$8,version=$9,mining_enabled=$10,staking_enabled=$11,last_sync=$12,is_multisig_signer=$13,public_key=$14 WHERE node_id=$1'
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], node['active'], node['rewards_earned'], node['version'], node['mining_enabled'], node['staking_enabled'], node['last_sync'], node['is_multisig_signer'], node['public_key'])
        await self.db.execute_dml(query, *params)

    async def get(self, node_id):
        query = 'SELECT * FROM nodes WHERE node_id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM nodes WHERE node_id = $1'
        return await self.db.fetchrow(query, node_id)

    async def get_active(self):
        query = 'SELECT * FROM nodes WHERE active = 1' if self.db.db_type == 'sqlite' else 'SELECT * FROM nodes WHERE active = TRUE'
        return await self.db.fetch(query)

    async def update_height(self, node_id, height):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE nodes SET height = ?, last_seen = ? WHERE node_id = ?', height, bootstrap.time.time(), node_id)
        else:
            await self.db.execute_dml('UPDATE nodes SET height = $1, last_seen = NOW() WHERE node_id = $2', height, node_id)

class TokenRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, token):
        if self.db.db_type == 'sqlite':
            query = 'INSERT INTO tokens (address,name,symbol,owner,total_supply,decimals,created_at,fee_paid,mintable,burnable,mining_type,mining_reward,mining_interval,mining_difficulty,stake_threshold,last_mined_block,total_mined,max_mineable_supply) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
            params = (token['address'], token['name'], token['symbol'], token['owner'], token['total_supply'], token['decimals'], token['created_at'], token['fee_paid'], 1 if token['mintable'] else 0, 1 if token['burnable'] else 0, token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        else:
            query = 'INSERT INTO tokens (address,name,symbol,owner,total_supply,decimals,created_at,fee_paid,mintable,burnable,mining_type,mining_reward,mining_interval,mining_difficulty,stake_threshold,last_mined_block,total_mined,max_mineable_supply) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)'
            params = (token['address'], token['name'], token['symbol'], token['owner'], token['total_supply'], token['decimals'], token['created_at'], token['fee_paid'], token['mintable'], token['burnable'], token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        await self.db.execute_dml(query, *params)

    async def get(self, address):
        query = 'SELECT * FROM tokens WHERE address = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM tokens WHERE address = $1'
        return await self.db.fetchrow(query, address)

    async def get_by_owner(self, owner):
        query = 'SELECT * FROM tokens WHERE owner = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM tokens WHERE owner = $1'
        return await self.db.fetch(query, owner)

    async def update(self, token):
        if self.db.db_type == 'sqlite':
            query = 'UPDATE tokens SET name=?,symbol=?,total_supply=?,decimals=?,mintable=?,burnable=?,mining_type=?,mining_reward=?,mining_interval=?,mining_difficulty=?,stake_threshold=?,last_mined_block=?,total_mined=?,max_mineable_supply=? WHERE address=?'
            params = (token['name'], token['symbol'], token['total_supply'], token['decimals'], 1 if token['mintable'] else 0, 1 if token['burnable'] else 0, token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'], token['address'])
        else:
            query = 'UPDATE tokens SET name=$2,symbol=$3,total_supply=$4,decimals=$5,mintable=$6,burnable=$7,mining_type=$8,mining_reward=$9,mining_interval=$10,mining_difficulty=$11,stake_threshold=$12,last_mined_block=$13,total_mined=$14,max_mineable_supply=$15 WHERE address=$1'
            params = (token['address'], token['name'], token['symbol'], token['total_supply'], token['decimals'], token['mintable'], token['burnable'], token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        await self.db.execute_dml(query, *params)

    async def upsert(self, token):
        existing = await self.get(token['address'])
        if existing:
            await self.update(token)
        else:
            await self.create(token)

class TokenBalanceRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, token, wallet):
        query = 'SELECT balance FROM token_balances WHERE token_address = ? AND wallet = ?' if self.db.db_type == 'sqlite' else 'SELECT balance FROM token_balances WHERE token_address = $1 AND wallet = $2'
        row = await self.db.fetchrow(query, token, wallet)
        return row['balance'] if row else 0

    async def set(self, token, wallet, balance):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO token_balances (token_address,wallet,balance) VALUES (?,?,?)', token, wallet, balance)
        else:
            await self.db.execute_dml('INSERT INTO token_balances (token_address,wallet,balance) VALUES ($1,$2,$3) ON CONFLICT (token_address,wallet) DO UPDATE SET balance=$3', token, wallet, balance)

class ContractStateRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, contract, key):
        query = 'SELECT value FROM contract_state WHERE contract_address = ? AND key = ?' if self.db.db_type == 'sqlite' else 'SELECT value FROM contract_state WHERE contract_address = $1 AND key = $2'
        row = await self.db.fetchrow(query, contract, key)
        return row['value'] if row else None

    async def set(self, contract, key, value):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO contract_state (contract_address,key,value) VALUES (?,?,?)', contract, key, value)
        else:
            await self.db.execute_dml('INSERT INTO contract_state (contract_address,key,value) VALUES ($1,$2,$3) ON CONFLICT (contract_address,key) DO UPDATE SET value=$3', contract, key, value)

    async def get_all(self, contract):
        query = 'SELECT key,value FROM contract_state WHERE contract_address = ?' if self.db.db_type == 'sqlite' else 'SELECT key,value FROM contract_state WHERE contract_address = $1'
        rows = await self.db.fetch(query, contract)
        return {r['key']: r['value'] for r in rows}

class ContractEventRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, event):
        data_json = bootstrap.json.dumps(event['data']) if isinstance(event['data'], (dict, list)) else event['data']
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO contract_events (contract_address,event_name,data,block_id,tx_hash,timestamp) VALUES (?,?,?,?,?,?)', event['contract_address'], event['event_name'], data_json, event['block_id'], event['tx_hash'], bootstrap.time.time())
        else:
            await self.db.execute_dml('INSERT INTO contract_events (contract_address,event_name,data,block_id,tx_hash,timestamp) VALUES ($1,$2,$3::jsonb,$4,$5,NOW())', event['contract_address'], event['event_name'], data_json, event['block_id'], event['tx_hash'])

    async def get_by_contract(self, contract, limit=100):
        query = 'SELECT * FROM contract_events WHERE contract_address = ? ORDER BY id DESC LIMIT ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM contract_events WHERE contract_address = $1 ORDER BY id DESC LIMIT $2'
        return await self.db.fetch(query, contract, limit)

class MultisigRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, address, public_keys, threshold):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO multisig_wallets (address,public_keys,threshold,created_at) VALUES (?,?,?,?)', address, bootstrap.json.dumps(public_keys), threshold, bootstrap.time.time())
        else:
            await self.db.execute_dml('INSERT INTO multisig_wallets (address,public_keys,threshold,created_at) VALUES ($1,$2::jsonb,$3,NOW())', address, bootstrap.json.dumps(public_keys), threshold)

    async def get(self, address):
        query = 'SELECT * FROM multisig_wallets WHERE address = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM multisig_wallets WHERE address = $1'
        return await self.db.fetchrow(query, address)

class ChallengeRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, wallet, nonce, expires):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO signing_challenges (wallet,nonce,expires) VALUES (?,?,?)', wallet, nonce, expires)
        else:
            await self.db.execute_dml('INSERT INTO signing_challenges (wallet,nonce,expires) VALUES ($1,$2,to_timestamp($3)) ON CONFLICT (wallet) DO UPDATE SET nonce=$2, expires=to_timestamp($3)', wallet, nonce, expires)

    async def get(self, wallet):
        query = 'SELECT nonce, expires FROM signing_challenges WHERE wallet = ?' if self.db.db_type == 'sqlite' else 'SELECT nonce, EXTRACT(EPOCH FROM expires) AS expires FROM signing_challenges WHERE wallet = $1'
        return await self.db.fetchrow(query, wallet)

    async def delete(self, wallet):
        query = 'DELETE FROM signing_challenges WHERE wallet = ?' if self.db.db_type == 'sqlite' else 'DELETE FROM signing_challenges WHERE wallet = $1'
        await self.db.execute_dml(query, wallet)

class ReceiptRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, receipt):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO transaction_receipts (tx_hash,block_id,status,gas_used,logs,contract_address,result) VALUES (?,?,?,?,?,?,?)', receipt['tx_hash'], receipt['block_id'], receipt['status'], receipt['gas_used'], bootstrap.json.dumps(receipt['logs']), receipt['contract_address'], receipt['result'])
        else:
            await self.db.execute_dml('INSERT INTO transaction_receipts (tx_hash,block_id,status,gas_used,logs,contract_address,result) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)', receipt['tx_hash'], receipt['block_id'], receipt['status'], receipt['gas_used'], bootstrap.json.dumps(receipt['logs']), receipt['contract_address'], receipt['result'])

    async def get(self, tx_hash):
        query = 'SELECT * FROM transaction_receipts WHERE tx_hash = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM transaction_receipts WHERE tx_hash = $1'
        return await self.db.fetchrow(query, tx_hash)

class FinalityRepo:

    def __init__(self, db):
        self.db = db

    async def create_checkpoint(self, block_id, block_hash, epoch):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO finality_checkpoints (block_id,hash,finalized_at,epoch) VALUES (?,?,?,?)', block_id, block_hash, bootstrap.time.time(), epoch)
        else:
            await self.db.execute_dml('INSERT INTO finality_checkpoints (block_id,hash,finalized_at,epoch) VALUES ($1,$2,NOW(),$3) ON CONFLICT (block_id) DO UPDATE SET hash=$2, finalized_at=NOW(), epoch=$3', block_id, block_hash, epoch)

    async def get_latest(self):
        query = 'SELECT * FROM finality_checkpoints ORDER BY block_id DESC LIMIT 1'
        return await self.db.fetchrow(query)

    async def get_by_epoch(self, epoch: int):
        query = 'SELECT * FROM finality_checkpoints WHERE epoch = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM finality_checkpoints WHERE epoch = $1'
        return await self.db.fetch(query, epoch)

class FinalityGadget:
    EPOCH_SIZE = 100

    def __init__(self, node):
        self.node = node
        self._last_finalized_block = 0

    async def on_block(self, block):
        block_id = block.get('id', 0)
        if block_id > 0 and block_id % self.EPOCH_SIZE == 0:
            await self.create_checkpoint(block_id, block.get('hash', ''), block_id // self.EPOCH_SIZE)

    async def create_checkpoint(self, block_id, block_hash, epoch):
        try:
            await self.node.finality_repo.create_checkpoint(block_id, block_hash, epoch)
            block_repo = BlockRepo(self.node.db)
            if self.node.db.db_type == 'sqlite':
                _page_q = 'SELECT id FROM blocks WHERE id <= ? AND finalized = 0 LIMIT 1000'
            else:
                _page_q = 'SELECT id FROM blocks WHERE id <= $1 AND finalized = FALSE LIMIT 1000'
            _total = 0
            while True:
                rows = await self.node.db.fetch(_page_q, block_id)
                if not rows:
                    break
                for row in rows:
                    await block_repo.mark_finalized(row['id'])
                    _total += 1
            self._last_finalized_block = max(self._last_finalized_block, block_id)
            bootstrap.logger.info(f'[Finality] Epoch {epoch} finalized at block {block_id} ({_total} blocks)')
        except Exception as e:
            bootstrap.logger.error(f'[Finality] Failed to create checkpoint at block {block_id}: {e}')

    def get_last_finalized_block(self):
        return self._last_finalized_block

    async def ensure_loaded(self):
        if self._last_finalized_block == 0:
            latest = await self.node.finality_repo.get_latest()
            if latest:
                self._last_finalized_block = latest['block_id']

    def is_finalized(self, block_id):
        return block_id <= self._last_finalized_block

class NetworkStateRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, key):
        query = 'SELECT value FROM network_state WHERE key = ?' if self.db.db_type == 'sqlite' else 'SELECT value FROM network_state WHERE key = $1'
        row = await self.db.fetchrow(query, key)
        return row['value'] if row else None

    async def set(self, key, value):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO network_state (key,value) VALUES (?,?)', key, value)
        else:
            await self.db.execute_dml('INSERT INTO network_state (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2', key, value)

class ContractV2Repo:

    def __init__(self, db):
        self.db = db

    async def create(self, contract):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO contract_v2 (address,owner,bytecode,abi,created_at,tx_hash,storage_root,code_hash) VALUES (?,?,?,?,?,?,?,?)', contract['address'], contract['owner'], contract['bytecode'], contract['abi'], contract['created_at'], contract['tx_hash'], contract['storage_root'], contract['code_hash'])
        else:
            await self.db.execute_dml('INSERT INTO contract_v2 (address,owner,bytecode,abi,created_at,tx_hash,storage_root,code_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)', contract['address'], contract['owner'], contract['bytecode'], contract['abi'], contract['created_at'], contract['tx_hash'], contract['storage_root'], contract['code_hash'])

    async def get(self, address):
        query = 'SELECT * FROM contract_v2 WHERE address = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM contract_v2 WHERE address = $1'
        return await self.db.fetchrow(query, address)

    async def get_all(self):
        query = 'SELECT * FROM contract_v2'
        return await self.db.fetch(query)

    async def update(self, contract):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE contract_v2 SET bytecode=?,abi=?,storage_root=?,code_hash=? WHERE address=?', contract['bytecode'], contract['abi'], contract['storage_root'], contract['code_hash'], contract['address'])
        else:
            await self.db.execute_dml('UPDATE contract_v2 SET bytecode=$1,abi=$2,storage_root=$3,code_hash=$4 WHERE address=$5', contract['bytecode'], contract['abi'], contract['storage_root'], contract['code_hash'], contract['address'])

class ContractStorageV2Repo:

    def __init__(self, db):
        self.db = db

    async def set(self, contract, key, value):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO contract_storage_v2 (contract_address,key,value) VALUES (?,?,?)', contract, key, value)
        else:
            await self.db.execute_dml('INSERT INTO contract_storage_v2 (contract_address,key,value) VALUES ($1,$2,$3) ON CONFLICT (contract_address,key) DO UPDATE SET value=$3', contract, key, value)

    async def get(self, contract, key):
        query = 'SELECT value FROM contract_storage_v2 WHERE contract_address = ? AND key = ?' if self.db.db_type == 'sqlite' else 'SELECT value FROM contract_storage_v2 WHERE contract_address = $1 AND key = $2'
        row = await self.db.fetchrow(query, contract, key)
        return row['value'] if row else None

    async def get_all(self, contract):
        query = 'SELECT key,value FROM contract_storage_v2 WHERE contract_address = ?' if self.db.db_type == 'sqlite' else 'SELECT key,value FROM contract_storage_v2 WHERE contract_address = $1'
        rows = await self.db.fetch(query, contract)
        return {r['key']: r['value'] for r in rows}

def verify_automation_delete_auth(auto_id, owner, pub_key, signature, ts) -> bootstrap.Tuple[bool, str]:
    if not pub_key or not signature:
        return (False, 'Missing signature')
    if ts is None:
        return (False, 'Missing timestamp')
    try:
        ts_f = float(ts)
    except (TypeError, ValueError):
        return (False, 'Bad timestamp')
    if abs(bootstrap.time.time() - ts_f) > 300:
        return (False, 'Stale timestamp')
    try:
        if util.pubkey_to_address(pub_key).lower() != str(owner).lower():
            return (False, 'pub_key does not match owner')
    except Exception:
        return (False, 'Invalid pub_key')
    message = f'{config.CHAIN_ID}:delete_automation:{auto_id}:{owner}:{int(ts_f)}'
    if not crypto.verify_signature(pub_key, message, signature):
        return (False, 'Invalid signature')
    return (True, str(owner))

def _automation_replay_key(message) -> str:
    if isinstance(message, str):
        message = message.encode('utf-8')
    return bootstrap.hashlib.sha256(bytes(message)).hexdigest()

def _automation_sig_replay(seen: dict, sig: str, now: float, window: float=300.0) -> bool:
    try:
        _now = float(now)
    except (TypeError, ValueError, OverflowError):
        return False
    try:
        _win = float(window)
    except (TypeError, ValueError, OverflowError):
        _win = 300.0
    for _k, _ts in list(seen.items()):
        try:
            if _now - float(_ts) > _win:
                seen.pop(_k, None)
        except (TypeError, ValueError, OverflowError):
            seen.pop(_k, None)
    if sig in seen:
        return True
    seen[sig] = _now
    return False

class AutomationRepo:

    def __init__(self, db):
        self.db = db

    @staticmethod
    def _redact(d: dict) -> dict:
        ac = d.get('action_config')
        if not isinstance(ac, dict):
            return d
        txs = ac.get('txs')
        if not isinstance(txs, list):
            return d
        red = [{'tx_hash': t.get('tx_hash'), 'tx_type': t.get('tx_type')} for t in txs if isinstance(t, dict)]
        out = dict(d)
        out_ac = dict(ac)
        out_ac['txs'] = red
        out['action_config'] = out_ac
        return out

    async def create(self, data: dict):
        t_conf = bootstrap.json.dumps(data.get('trigger_config', {}))
        a_conf = bootstrap.json.dumps(data.get('action_config', {}))
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO automations (id,name,owner,trigger_type,trigger_config,action_type,action_config,enabled,created_at,last_run_at,run_count,last_result) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)', data['id'], data['name'], data['owner'], data['trigger_type'], t_conf, data['action_type'], a_conf, 1 if data.get('enabled', True) else 0, data.get('created_at', bootstrap.time.time()), data.get('last_run_at'), data.get('run_count', 0), data.get('last_result', ''))
        else:
            await self.db.execute_dml('INSERT INTO automations (id,name,owner,trigger_type,trigger_config,action_type,action_config,enabled,created_at,last_run_at,run_count,last_result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO UPDATE SET name=$2, trigger_type=$4, trigger_config=$5, action_type=$6, action_config=$7, enabled=$8, last_run_at=$10, run_count=$11, last_result=$12', data['id'], data['name'], data['owner'], data['trigger_type'], t_conf, data['action_type'], a_conf, bool(data.get('enabled', True)), data.get('created_at', bootstrap.time.time()), data.get('last_run_at'), data.get('run_count', 0), data.get('last_result', ''))

    async def get(self, auto_id: str):
        q = 'SELECT * FROM automations WHERE id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM automations WHERE id = $1'
        row = await self.db.fetchrow(q, auto_id)
        if not row:
            return None
        d = dict(row)
        if isinstance(d.get('trigger_config'), str):
            try:
                d['trigger_config'] = bootstrap.json.loads(d['trigger_config'])
            except Exception:
                pass
        if isinstance(d.get('action_config'), str):
            try:
                d['action_config'] = bootstrap.json.loads(d['action_config'])
            except Exception:
                pass
        return AutomationRepo._redact(d)

    async def list_active(self):
        q = 'SELECT * FROM automations WHERE enabled = 1' if self.db.db_type == 'sqlite' else 'SELECT * FROM automations WHERE enabled = TRUE'
        rows = await self.db.fetch(q)
        res = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get('trigger_config'), str):
                try:
                    d['trigger_config'] = bootstrap.json.loads(d['trigger_config'])
                except Exception:
                    pass
            if isinstance(d.get('action_config'), str):
                try:
                    d['action_config'] = bootstrap.json.loads(d['action_config'])
                except Exception:
                    pass
            res.append(AutomationRepo._redact(d))
        return res

    async def list_by_owner(self, owner: str):
        q = 'SELECT * FROM automations WHERE owner = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM automations WHERE owner = $1'
        rows = await self.db.fetch(q, owner)
        res = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get('trigger_config'), str):
                try:
                    d['trigger_config'] = bootstrap.json.loads(d['trigger_config'])
                except Exception:
                    pass
            if isinstance(d.get('action_config'), str):
                try:
                    d['action_config'] = bootstrap.json.loads(d['action_config'])
                except Exception:
                    pass
            res.append(AutomationRepo._redact(d))
        return res

    async def update_run(self, auto_id: str, last_run_at: float, run_count: int, last_result: str, last_block_run: int=0):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE automations SET last_run_at = ?, run_count = ?, last_result = ?, last_block_run = ? WHERE id = ?', last_run_at, run_count, str(last_result), int(last_block_run or 0), auto_id)
        else:
            await self.db.execute_dml('UPDATE automations SET last_run_at = $1, run_count = $2, last_result = $3, last_block_run = $4 WHERE id = $5', last_run_at, run_count, str(last_result), int(last_block_run or 0), auto_id)

    async def set_enabled(self, auto_id: str, enabled: bool):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE automations SET enabled = ? WHERE id = ?', 1 if enabled else 0, auto_id)
        else:
            await self.db.execute_dml('UPDATE automations SET enabled = $1 WHERE id = $2', bool(enabled), auto_id)

    async def delete(self, auto_id: str):
        q = 'DELETE FROM automations WHERE id = ?' if self.db.db_type == 'sqlite' else 'DELETE FROM automations WHERE id = $1'
        await self.db.execute_dml(q, auto_id)

    async def note_replay_seen(self, key: str, now: float, window: float=300.0) -> bool:
        try:
            _now = float(now)
            _win = float(window)
        except (TypeError, ValueError, OverflowError):
            return False
        _cut = _now - _win
        try:
            if self.db.db_type == 'sqlite':
                await self.db.execute_dml('DELETE FROM automation_replay_seen WHERE seen_at < ?', _cut)
                row = await self.db.fetchrow('SELECT seen_at FROM automation_replay_seen WHERE sig_hash = ?', str(key))
                if row is not None:
                    return True
                await self.db.execute_dml('INSERT OR REPLACE INTO automation_replay_seen (sig_hash, seen_at) VALUES (?, ?)', str(key), _now)
            else:
                await self.db.execute_dml('DELETE FROM automation_replay_seen WHERE seen_at < $1', _cut)
                row = await self.db.fetchrow('SELECT seen_at FROM automation_replay_seen WHERE sig_hash = $1', str(key))
                if row is not None:
                    return True
                await self.db.execute_dml('INSERT INTO automation_replay_seen (sig_hash, seen_at) VALUES ($1, $2) ON CONFLICT (sig_hash) DO UPDATE SET seen_at = EXCLUDED.seen_at', str(key), _now)
        except Exception:
            return False
        return False

class HTLCRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, htlc):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)', htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address', ''), htlc.get('status', 'open'), bootstrap.time.time())
        else:
            await self.db.execute_dml('INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())', htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address', ''), htlc.get('status', 'open'))

    async def get(self, htlc_id):
        query = 'SELECT * FROM htlc_contracts WHERE id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM htlc_contracts WHERE id = $1'
        return await self.db.fetchrow(query, htlc_id)

    async def update_status(self, htlc_id, status, claimed_at=None, refunded_at=None):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE htlc_contracts SET status=?, claimed_at=?, refunded_at=? WHERE id=?', status, claimed_at, refunded_at, htlc_id)
        else:
            await self.db.execute_dml('UPDATE htlc_contracts SET status=$1, claimed_at=$2, refunded_at=$3 WHERE id=$4', status, claimed_at, refunded_at, htlc_id)

    async def get_open_by_receiver(self, receiver):
        query = "SELECT * FROM htlc_contracts WHERE receiver = ? AND status = 'open'" if self.db.db_type == 'sqlite' else "SELECT * FROM htlc_contracts WHERE receiver = $1 AND status = 'open'"
        return await self.db.fetch(query, receiver)

class MinerMazeRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, miner_id: str):
        query = 'SELECT * FROM minermazes WHERE minerid = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM minermazes WHERE minerid = $1'
        return await self.db.fetch(query, miner_id)

    async def get_by_maze_id(self, maze_id: str):
        if not maze_id:
            return None
        query = 'SELECT * FROM minermazes WHERE maze_id = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM minermazes WHERE maze_id = $1'
        return await self.db.fetchrow(query, maze_id)

    async def create_for_maze(self, maze_id: str, miner_id: str, row: dict):
        row = dict(row)
        row['maze_id'] = maze_id
        row['minerid'] = miner_id
        await self.upsert(row)
        return row

    async def bind_miner(self, maze_id: str, miner_id: str):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE minermazes SET minerid=?, updatedat=? WHERE maze_id=?', miner_id, int(bootstrap.time.time()), maze_id)
        else:
            await self.db.execute_dml('UPDATE minermazes SET minerid=$1, updatedat=$2 WHERE maze_id=$3', miner_id, int(bootstrap.time.time()), maze_id)

    async def get_by_miner_id(self, miner_id: str):
        query = 'SELECT * FROM minermazes WHERE minerid = ?' if self.db.db_type == 'sqlite' else 'SELECT * FROM minermazes WHERE minerid = $1'
        return await self.db.fetch(query, miner_id)

    async def get_for_miner(self, miner_id: str, maze_id: str):
        rows = await self.get_by_miner_id(miner_id)
        if rows:
            return dict(rows[0])
        row = await self.get_by_maze_id(maze_id)
        return dict(row) if row else None

    async def upsert(self, m: dict):
        now = int(bootstrap.time.time())
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO minermazes (maze_id,minerid,size,walldensityppm,seed,posx,posy,posz,goalx,goaly,goalz,movenonce,consecutivewallhits,turbulenceppm,growthcount,knowledge,lastgoalheight,lastactiveheight,mazeroot,invitedguest,guestlock,lastknowledgeheight,createdat,updatedat,ghostx,ghosty,ghostz) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', m.get('maze_id', m['minerid']), m['minerid'], m['size'], m['walldensityppm'], m['seed'], m['posx'], m['posy'], m['posz'], m['goalx'], m['goaly'], m['goalz'], m.get('movenonce', 0), m.get('consecutivewallhits', 0), m.get('turbulenceppm', 0), m.get('growthcount', 0), m.get('knowledge', 0), m.get('lastgoalheight', 0), m.get('lastactiveheight', 0), m['mazeroot'], m.get('invitedguest', None), 1 if m.get('guestlock', False) else 0, m.get('lastknowledgeheight', 0), m.get('createdat', now), now, m.get('ghostx'), m.get('ghosty'), m.get('ghostz'))
        else:
            await self.db.execute_dml('INSERT INTO minermazes (maze_id,minerid,size,walldensityppm,seed,posx,posy,posz,goalx,goaly,goalz,movenonce,consecutivewallhits,turbulenceppm,growthcount,knowledge,lastgoalheight,lastactiveheight,mazeroot,invitedguest,guestlock,lastknowledgeheight,createdat,updatedat,ghostx,ghosty,ghostz)\n                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)\n                   ON CONFLICT (maze_id) DO UPDATE SET minerid=$2,size=$3,walldensityppm=$4,seed=$5,posx=$6,posy=$7,posz=$8,goalx=$9,goaly=$10,goalz=$11,movenonce=$12,consecutivewallhits=$13,turbulenceppm=$14,growthcount=$15,knowledge=$16,lastgoalheight=$17,lastactiveheight=$18,mazeroot=$19,invitedguest=$20,guestlock=$21,lastknowledgeheight=$22,updatedat=$24,ghostx=$25,ghosty=$26,ghostz=$27', m.get('maze_id', m['minerid']), m['minerid'], m['size'], m['walldensityppm'], m['seed'], m['posx'], m['posy'], m['posz'], m['goalx'], m['goaly'], m['goalz'], m.get('movenonce', 0), m.get('consecutivewallhits', 0), m.get('turbulenceppm', 0), m.get('growthcount', 0), m.get('knowledge', 0), m.get('lastgoalheight', 0), m.get('lastactiveheight', 0), m['mazeroot'], m.get('invitedguest', None), m.get('guestlock', False), m.get('lastknowledgeheight', 0), m.get('createdat', now), now, m.get('ghostx'), m.get('ghosty'), m.get('ghostz'))

    async def get_eligible(self, block_id: int) -> list:
        cutoff_height = max(0, block_id - config.ACTIVE_MINER_WINDOW_BLOCKS)
        _min_elig = int(config.MIN_MAZE_SIZE)
        if self.db.db_type == 'sqlite':
            rows = await self.db.fetch(f'SELECT * FROM minermazes WHERE lastactiveheight >= ? AND size > {_min_elig}', cutoff_height)
        else:
            rows = await self.db.fetch(f'SELECT * FROM minermazes WHERE lastactiveheight >= $1 AND size > {_min_elig}', cutoff_height)
        return rows

    async def update_miner_inactive(self, miner_id: str):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('UPDATE minermazes SET lastactiveheight = -1000000 WHERE minerid = ?', miner_id)
        else:
            await self.db.execute_dml('UPDATE minermazes SET lastactiveheight = -1000000 WHERE minerid = $1', miner_id)

    async def get_all(self) -> list:
        if self.db.db_type == 'sqlite':
            return await self.db.fetch('SELECT * FROM minermazes')
        else:
            return await self.db.fetch('SELECT * FROM minermazes')

class MazeAttestationRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, maze_id: str):
        if self.db.db_type == 'sqlite':
            return await self.db.fetchrow('SELECT * FROM maze_attestations WHERE maze_id = ?', maze_id)
        else:
            return await self.db.fetchrow('SELECT * FROM maze_attestations WHERE maze_id = $1', maze_id)

    async def get_all(self):
        return await self.db.fetch('SELECT * FROM maze_attestations')

    async def upsert(self, att: dict):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO maze_attestations (maze_id,last_size,last_block,last_block_hash,pubkey) VALUES (?,?,?,?,?)', str(att['maze_id']), int(att['last_size']), int(att['last_block']), str(att.get('last_block_hash', '')), str(att.get('pubkey', '')))
        else:
            await self.db.execute_dml('INSERT INTO maze_attestations (maze_id,last_size,last_block,last_block_hash,pubkey) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (maze_id) DO UPDATE SET last_size=$2,last_block=$3,last_block_hash=$4,pubkey=$5', str(att['maze_id']), int(att['last_size']), int(att['last_block']), str(att.get('last_block_hash', '')), str(att.get('pubkey', '')))

    async def rollback_after(self, common_height: int):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('DELETE FROM maze_attestations WHERE last_block > ?', common_height)
        else:
            await self.db.execute_dml('DELETE FROM maze_attestations WHERE last_block > $1', common_height)

class MazeProofRepo:

    def __init__(self, db):
        self.db = db

    async def get(self, maze_id: str):
        if self.db.db_type == 'sqlite':
            return await self.db.fetchrow('SELECT * FROM maze_proofs WHERE maze_id = ? ORDER BY new_size DESC LIMIT 1', maze_id)
        else:
            return await self.db.fetchrow('SELECT * FROM maze_proofs WHERE maze_id = $1 ORDER BY new_size DESC LIMIT 1', maze_id)

    async def get_for_size(self, maze_id: str, size: int):
        if self.db.db_type == 'sqlite':
            return await self.db.fetchrow('SELECT * FROM maze_proofs WHERE maze_id = ? AND new_size = ?', maze_id, int(size))
        else:
            return await self.db.fetchrow('SELECT * FROM maze_proofs WHERE maze_id = $1 AND new_size = $2', maze_id, int(size))

    async def upsert(self, maze_id: str, proof: dict, block_id: int):
        if not isinstance(proof, dict):
            return
        if proof.get('caught_at_nonce') is None:
            return
        _sz = maze._valid_maze_size(proof.get('new_size'))
        if _sz is None:
            return
        _pj = bootstrap.json.dumps(proof)
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO maze_proofs (maze_id, new_size, proof_json, updated_block) VALUES (?,?,?,?)', str(maze_id), int(_sz), _pj, int(block_id))
        else:
            await self.db.execute_dml('INSERT INTO maze_proofs (maze_id, new_size, proof_json, updated_block) VALUES ($1,$2,$3,$4) ON CONFLICT (maze_id, new_size) DO UPDATE SET proof_json=$3, updated_block=$4', str(maze_id), int(_sz), _pj, int(block_id))

    async def rollback_after(self, common_height: int):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('DELETE FROM maze_proofs WHERE updated_block > ?', common_height)
        else:
            await self.db.execute_dml('DELETE FROM maze_proofs WHERE updated_block > $1', common_height)

class LotteryRepo:

    def __init__(self, db):
        self.db = db

    async def put_commit(self, height: int, miner_id: str, commit: str):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO lottery_commits (height, miner_id, "commit") VALUES (?,?,?)', height, miner_id, commit)
        else:
            await self.db.execute_dml('INSERT INTO lottery_commits (height, miner_id, "commit") VALUES ($1,$2,$3) ON CONFLICT (height, miner_id) DO UPDATE SET "commit"=EXCLUDED."commit"', height, miner_id, commit)

    async def get_commit(self, height: int, miner_id: str):
        if self.db.db_type == 'sqlite':
            return await self.db.fetchrow('SELECT * FROM lottery_commits WHERE height = ? AND miner_id = ?', height, miner_id)
        else:
            return await self.db.fetchrow('SELECT * FROM lottery_commits WHERE height = $1 AND miner_id = $2', height, miner_id)

    async def put_reveal(self, height: int, miner_id: str, secret: str):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO lottery_reveals (height, miner_id, secret) VALUES (?,?,?)', height, miner_id, secret)
        else:
            await self.db.execute_dml('INSERT INTO lottery_reveals (height, miner_id, secret) VALUES ($1,$2,$3) ON CONFLICT (height, miner_id) DO UPDATE SET secret=EXCLUDED.secret', height, miner_id, secret)

    async def get_reveals_for_height(self, height: int):
        if self.db.db_type == 'sqlite':
            return await self.db.fetch('SELECT * FROM lottery_reveals WHERE height = ?', height)
        else:
            return await self.db.fetch('SELECT * FROM lottery_reveals WHERE height = $1', height)

    async def clear_height(self, height: int):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('DELETE FROM lottery_commits WHERE height = ?', height)
            await self.db.execute_dml('DELETE FROM lottery_reveals WHERE height = ?', height)
        else:
            await self.db.execute_dml('DELETE FROM lottery_commits WHERE height = $1', height)
            await self.db.execute_dml('DELETE FROM lottery_reveals WHERE height = $1', height)

class SlashRepo:

    def __init__(self, db):
        self.db = db

    async def create(self, miner_id: str, amount: int, reason: str, block_id: int):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT INTO slashing_events (miner_id, amount, reason, timestamp, block_id) VALUES (?,?,?,?,?)', miner_id, amount, reason, bootstrap.time.time(), block_id)
        else:
            await self.db.execute_dml('INSERT INTO slashing_events (miner_id, amount, reason, timestamp, block_id) VALUES ($1,$2,$3,$4,$5)', miner_id, amount, reason, bootstrap.time.time(), block_id)

    async def get_by_miner(self, miner_id: str):
        if self.db.db_type == 'sqlite':
            return await self.db.fetch('SELECT * FROM slashing_events WHERE miner_id = ?', miner_id)
        else:
            return await self.db.fetch('SELECT * FROM slashing_events WHERE miner_id = $1', miner_id)

class PeerBanRepo:

    def __init__(self, db):
        self.db = db

    async def upsert(self, address: str, node_id: bootstrap.Optional[str], reason: str, expires_at: float):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('INSERT OR REPLACE INTO peer_bans (address,node_id,reason,banned_at,expires_at) VALUES (?,?,?,?,?)', address, node_id or '', reason, bootstrap.time.time(), expires_at)
        else:
            await self.db.execute_dml('INSERT INTO peer_bans (address,node_id,reason,banned_at,expires_at) VALUES ($1,$2,$3,NOW(),$4) ON CONFLICT (address) DO UPDATE SET node_id=$2, reason=$3, banned_at=NOW(), expires_at=$4', address, node_id or '', reason, expires_at)

    async def get_active(self):
        if self.db.db_type == 'sqlite':
            return await self.db.fetch('SELECT * FROM peer_bans WHERE expires_at > ?', bootstrap.time.time())
        else:
            return await self.db.fetch('SELECT * FROM peer_bans WHERE expires_at > $1', bootstrap.time.time())

    async def delete_expired(self):
        if self.db.db_type == 'sqlite':
            await self.db.execute_dml('DELETE FROM peer_bans WHERE expires_at <= ?', bootstrap.time.time())
        else:
            await self.db.execute_dml('DELETE FROM peer_bans WHERE expires_at <= $1', bootstrap.time.time())
