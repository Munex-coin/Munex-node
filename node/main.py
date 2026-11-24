#!/usr/bin/env python3
import bootstrap
import config as _config
import svf_keys
import genesis
import core
import tunnel

async def main():
    parser = bootstrap.argparse.ArgumentParser(description=f'{_config.NAME} Node v{_config.VERSION}')
    parser.add_argument('--config', type=str, default=_config.CONFIG_PATH, help='Path to config file')
    parser.add_argument('--wallet', type=str, help='Wallet address')
    parser.add_argument('--password', type=str, help='Password for encrypted private key')
    parser.add_argument('--external-ip', type=str, help='Public IP or hostname for P2P (overrides config)')
    parser.add_argument('--db-url', type=str, help='Database URL (overrides config)')
    parser.add_argument('--public-ip', type=str, help='Public IP for P2P (overrides auto-detect)')
    parser.add_argument('--no-dht', action='store_true', help='Disable DHT')
    parser.add_argument('--allow-new-genesis', action='store_true', help='DELIBERATE new-chain init (seed node only): create a genesis when none can be synced. NEVER use on joining nodes - they must copy genesis.json from the network instead.')
    parser.add_argument('--genesis-file', type=str, default=None, help='Path to the intended genesis file (overrides MCX_GENESIS_FILE env, node.genesis_file config, and the genesis.json default)')
    args = parser.parse_args()
    config = _config.load_config()
    if args.config:
        _config.CONFIG_PATH = args.config
        config = _config.load_config()
    if args.external_ip:
        config['node']['external_ip'] = args.external_ip
    if args.db_url:
        config['database'] = {'url': args.db_url}
    if args.public_ip:
        bootstrap.os.environ['MCX_PUBLIC_IP'] = args.public_ip
    if args.wallet:
        config['wallet'] = args.wallet
    if args.password:
        config['password'] = args.password
        bootstrap.logger.warning('[Node] R4-password-cli: --password exposes the secret via the process list; prefer the MCX_PASSWORD environment variable')
    if args.no_dht:
        config['p2p']['dht_enabled'] = False
    _config.DHT_ENABLED = config['p2p'].get('dht_enabled', True)
    _node_section = config.setdefault('node', {})
    if 'mainnet' in _node_section and _node_section.get('mainnet') is not None:
        if not isinstance(_node_section.get('mainnet'), bool):
            bootstrap.logger.warning('[CONFIG] node.mainnet is legacy and ignored; non-boolean value discarded')
            _node_section.pop('mainnet', None)
        else:
            bootstrap.logger.info('[CONFIG] node.mainnet is legacy and ignored (no testnet/mainnet mode split)')
    try:
        _config.EXPECTED_GENESIS_PIN = _config._expected_genesis_pin(config)
    except ValueError as _pe:
        bootstrap.logger.error(f'[CONFIG] {_pe}; refusing to start')
        bootstrap.sys.exit(1)
    if _config.EXPECTED_GENESIS_PIN is None:
        bootstrap.logger.warning('[CONFIG] p2p.expected_genesis_hash is not set: this node will learn genesis from any existing peer that answers. Pin it for any real network.')
    _gen_src = 'default genesis.json'
    if args.genesis_file:
        _gen_src = '--genesis-file CLI'
    elif (bootstrap.os.environ.get('MCX_GENESIS_FILE', '') or '').strip():
        _gen_src = 'MCX_GENESIS_FILE env'
    elif isinstance((config.get('node', {}) or {}).get('genesis_file', ''), str) and ((config.get('node', {}) or {}).get('genesis_file', '') or '').strip():
        _gen_src = 'node.genesis_file config'
    _config.GENESIS_FILE = genesis.resolve_genesis_file(config, args.genesis_file)
    bootstrap.logger.info(f'[GENESIS] Using genesis file {bootstrap.os.path.abspath(_config.GENESIS_FILE)} (source: {_gen_src})')
    try:
        _config.validate_validators_config(_config.VALIDATORS)
        _config.validate_validators_config((config.get('consensus') or {}).get('validators'))
    except ValueError as _ve:
        bootstrap.logger.error(f'[CONFIG] {_ve}; refusing to start')
        bootstrap.sys.exit(1)
    try:
        _config.apply_consensus_config(config)
    except ValueError as _ve:
        bootstrap.logger.error(f'[CONFIG] {_ve}; refusing to start')
        bootstrap.sys.exit(1)
    svf_keys._svf_ensure_key_loaded(config)
    node = core.MicroCoreNode(config)
    node._allow_new_genesis = args.allow_new_genesis
    print(f'\n{'=' * 60}')
    print(f'{bootstrap.GREEN}{_config.NAME} ({_config.SYMBOL}) COMPLETE NODE v{_config.VERSION}{bootstrap.RESET}')
    print(f'{'=' * 60}')
    print(f'Node ID: {node.node_id[:16]}...')
    print(f'Wallet: {node.wallet}')
    print(f'Height: {node.height}')
    print(f'Peers: {(node.p2p.get_peer_count() if node.p2p else 0)}')
    print(f'Miners: {len(node.miners)}')
    print(f'{'=' * 60}\n')
    try:
        await node.start()
    except bootstrap.asyncio.CancelledError:
        bootstrap.logger.info('[Node] Cancelled')
    except Exception as _run_e:
        bootstrap.logger.error(f'[Node] Fatal during start: {_run_e}')
        bootstrap.logger.error(bootstrap.traceback.format_exc())
        raise
    finally:
        await node.shutdown()
if __name__ == '__main__':
    if any((a.startswith('--tunnel') for a in bootstrap.sys.argv[1:])):
        bootstrap.sys.exit(tunnel.tunnel_main(bootstrap.sys.argv[1:]))
    try:
        if bootstrap.sys.platform == 'win32':
            import ctypes

            def _win_ctrl_handler(dw):
                if dw in (0, 1):
                    ctypes.pythonapi.PyErr_SetInterrupt()
                    return True
                return False
            _win_ctrl_cb = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int)(_win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_ctrl_cb, True)
        bootstrap.asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[SHUTDOWN] Interrupted by user')
        bootstrap.sys.exit(0)
    except Exception as e:
        print(f'\n{bootstrap.RED}[ERROR] {e}{bootstrap.RESET}')
        bootstrap.traceback.print_exc()
        bootstrap.sys.exit(1)
