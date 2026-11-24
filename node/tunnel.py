import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import types
import urllib.request
import urllib.error
TUNNEL_WS_PORT = 8080
TUNNEL_API_PORT = 8085
TUNNEL_P2P_PORT = 8081
TUNNEL_UDP_PORT = 8083
TUNNEL_DEFAULT_REGISTRY = 'https://munex-registry.animax-plorer22.workers.dev'
TUNNEL_DEFAULT_INTERVAL = 30
TUNNEL_DEFAULT_FAILURES = 3
TUNNEL_PROBE_TIMEOUT = 5
TUNNEL_REGISTER_TIMEOUT = 8
TUNNEL_QUICK_URL_RE = re.compile('https://[A-Za-z0-9\\-]+\\.trycloudflare\\.com')
TUNNEL_DOWNLOAD_URLS = {('Windows', 'AMD64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe', ('Windows', 'ARM64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-arm64.exe', ('Linux', 'x86_64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64', ('Linux', 'aarch64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64', ('Linux', 'arm64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64', ('Darwin', 'x86_64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64.tgz', ('Darwin', 'arm64'): 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-arm64.tgz'}

def tunnel_say(text):
    print(text, flush=True)

def tunnel_ask(text, default=None):
    if default:
        shown = text + ' [' + default + ']: '
    else:
        shown = text + ': '
    try:
        answer = input(shown).strip()
    except (EOFError, KeyboardInterrupt):
        tunnel_say('')
        raise SystemExit(0)
    if not answer and default:
        return default
    return answer

def tunnel_ask_choice(text, options):
    tunnel_say(text)
    for key, label in options:
        tunnel_say('  ' + key + ' = ' + label)
    while True:
        answer = tunnel_ask('Your choice').strip()
        for key, label in options:
            if answer == key:
                return key
        tunnel_say('Please type one of: ' + ', '.join((k for k, _ in options)))

def tunnel_probe_url(url):
    request = urllib.request.Request(url, method='GET', headers={'User-Agent': 'munex-tunnel/1.0'})
    try:
        with urllib.request.urlopen(request, timeout=TUNNEL_PROBE_TIMEOUT) as response:
            body = response.read(4000).decode('utf-8', 'replace')
            return (True, response.status, body)
    except urllib.error.HTTPError as err:
        try:
            body = err.read(4000).decode('utf-8', 'replace')
        except Exception:
            body = ''
        return (False, err.code, body)
    except Exception as err:
        return (False, 0, str(err))

def tunnel_healthz_ok(url):
    ok, tunnel_status_show, body = tunnel_probe_url(url)
    if not ok:
        return False
    try:
        data = json.loads(body)
    except Exception:
        return False
    return data.get('service') == 'mcx-miner-ws' and data.get('status') == 'ok'

def tunnel_local_node_up():
    ok, _, _ = tunnel_probe_url('http://127.0.0.1:%d/healthz' % TUNNEL_WS_PORT)
    return ok

def tunnel_find_node_file(node_dir):
    candidates = []
    if node_dir:
        candidates.append(os.path.join(node_dir, 'node.py'))
    candidates.append(os.path.join(os.getcwd(), 'node.py'))
    candidates.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'node.py'))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None

def tunnel_node_is_r21(node_dir):
    path = tunnel_find_node_file(node_dir)
    if not path:
        return None
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except Exception:
        return None
    return b'CF-Connecting-IP' in data

def tunnel_bucket_check(node_dir):
    result = tunnel_node_is_r21(node_dir)
    if result is None:
        tunnel_say('I could not find your node.py, so I cannot check its version.')
        tunnel_say('Make sure your node is the R21 build or newer before using a tunnel.')
        return True
    if result:
        tunnel_say('Good: your node is R21 or newer, it tells tunnelled miners apart,')
        tunnel_say('so each miner gets its own connection and rate-limit bucket.')
        return True
    tunnel_say('WARNING: your node is older than R21.')
    tunnel_say('Through a tunnel every miner arrives looking like one address, so on')
    tunnel_say('an old node all of them share a single bucket of 20 connections and')
    tunnel_say('one rate limit. The 21st miner gets kicked off with error 1013, and')
    tunnel_say('miners start getting rate-limited even though each one is innocent.')
    tunnel_say('R21 fixes this by reading the real address Cloudflare passes along.')
    tunnel_say('Update your node to the R21 build first if you can.')
    answer = tunnel_ask('Set up the tunnel anyway', 'N')
    return answer.lower() in ('y', 'yes')

def tunnel_find_cloudflared(explicit):
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit
        return None
    found = shutil.which('cloudflared')
    if found:
        return found
    local = os.path.join(os.getcwd(), 'cloudflared.exe' if platform.system() == 'Windows' else 'cloudflared')
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return None

def tunnel_download_cloudflared():
    system = platform.system()
    machine = platform.machine()
    url = os.environ.get('MCX_CLOUDFLARED_URL')
    if not url:
        url = TUNNEL_DOWNLOAD_URLS.get((system, machine))
    if not url:
        return (None, 'I do not know a download for ' + system + ' ' + machine + '.')
    name = 'cloudflared.exe' if system == 'Windows' else 'cloudflared'
    target = os.path.join(os.getcwd(), name)
    tunnel_say('Downloading cloudflared from ' + url)
    try:
        request = urllib.request.Request(url, headers={'User-Agent': 'munex-tunnel/1.0'})
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
    except Exception as err:
        return (None, 'Download failed: ' + str(err))
    if url.endswith('.tgz'):
        tmp = target + '.tgz'
        with open(tmp, 'wb') as handle:
            handle.write(data)
        try:
            with tarfile.open(tmp, 'r:gz') as archive:
                member = None
                for item in archive.getmembers():
                    if item.name.endswith('cloudflared'):
                        member = item
                        break
                if member is None:
                    return (None, 'The download did not contain a cloudflared file.')
                member.name = 'cloudflared'
                archive.extract(member, os.getcwd())
        except Exception as err:
            return (None, 'Could not unpack the download: ' + str(err))
        finally:
            try:
                os.remove(tmp)
            except Exception:
                pass
    else:
        with open(target, 'wb') as handle:
            handle.write(data)
    if system != 'Windows':
        os.chmod(target, 493)
    return (target, None)

def tunnel_install_instructions():
    tunnel_say('')
    tunnel_say('cloudflared is not installed, and I could not fetch it for you.')
    tunnel_say('Install it by hand, then run this helper again:')
    tunnel_say('  Windows: winget install Cloudflare.cloudflared')
    tunnel_say('           or download cloudflared-windows-amd64.exe from')
    tunnel_say('           https://github.com/cloudflare/cloudflared/releases')
    tunnel_say('  Linux:   download cloudflared-linux-amd64 from the same page')
    tunnel_say('           and put it somewhere on your PATH')
    tunnel_say('  Mac:     brew install cloudflared')
    tunnel_say('Then run: python node.py --tunnel-setup')

def tunnel_register_host(host, registry_url):
    url = registry_url.rstrip('/') + '/register'
    payload = json.dumps({'host': host}).encode('utf-8')
    request = urllib.request.Request(url, data=payload, method='POST', headers={'Content-Type': 'application/json', 'User-Agent': 'munex-tunnel/1.0'})
    try:
        with urllib.request.urlopen(request, timeout=TUNNEL_REGISTER_TIMEOUT) as response:
            body = response.read(2000).decode('utf-8', 'replace')
            return (True, response.status, body)
    except urllib.error.HTTPError as err:
        try:
            body = err.read(2000).decode('utf-8', 'replace')
        except Exception:
            body = ''
        return (False, err.code, body)
    except Exception as err:
        return (False, 0, str(err))

def tunnel_register_link(host, registry_url):
    ok, tunnel_status_show, body = tunnel_register_host(host, registry_url)
    if ok:
        tunnel_say('Registered ' + host + ' with the registry, miners can find it.')
        return True
    if tunnel_status_show == 429:
        tunnel_say('The registry asked us to slow down (429). It will pick the link up later.')
        return False
    tunnel_say('Could not register with the registry (status ' + str(tunnel_status_show) + ').')
    tunnel_say('The link still works, miners just have to type it in by hand.')
    return False

def tunnel_save_state(path, state):
    with open(path, 'w', encoding='utf-8') as handle:
        json.dump(state, handle, indent=2)
        handle.write('\n')

def tunnel_load_state(path):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)

def tunnel_host_of(url):
    text = url.split('://', 1)[-1].split('/', 1)[0]
    return text

def tunnel_start_process(command, log_path):
    log = open(log_path, 'ab')
    kwargs = {'stdout': log, 'stderr': subprocess.STDOUT, 'stdin': subprocess.DEVNULL}
    if os.name == 'posix':
        kwargs['start_new_session'] = True
    else:
        kwargs['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    proc = subprocess.Popen(command, **kwargs)
    log.close()
    return proc

def tunnel_read_log_text(log_path):
    try:
        with open(log_path, 'rb') as handle:
            return handle.read().decode('utf-8', 'replace')
    except Exception:
        return ''

def tunnel_wait_for_quick_url(log_path, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        text = tunnel_read_log_text(log_path)
        found = TUNNEL_QUICK_URL_RE.search(text)
        if found:
            return found.group(0)
        time.sleep(1)
    return None

def tunnel_kill_pid(pid):
    if not pid:
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception:
        pass
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        except Exception:
            return
        time.sleep(0.2)
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass

def tunnel_port_forwarding_path():
    tunnel_say('')
    tunnel_say('Port forwarding it is. In your router, forward these to this computer:')
    tunnel_say('  8080 TCP  miners connect here, the registry checks here')
    tunnel_say('  8081 TCP  node to node')
    tunnel_say('  8085 TCP  website and API')
    tunnel_say('  8083 UDP  peer discovery')
    tunnel_say('')
    tunnel_say("Find this computer's LAN address first:")
    tunnel_say('  Windows: open a terminal and run: ipconfig')
    tunnel_say('           look for IPv4 Address, it looks like 192.168.1.5')
    tunnel_say('  Linux or Mac: run: hostname -I')
    tunnel_say('Forward each port to that address, then restart your node.')
    tunnel_say('Nothing else to do here.')

def tunnel_quick_setup(cloudflared, state_path, registry_url):
    tunnel_say('')
    tunnel_say('Quick tunnel: free, no account, but the link is random and changes')
    tunnel_say('every time the tunnel restarts. This helper will print the new link')
    tunnel_say('and re-register it each time that happens.')
    links = {}
    hosts = {}
    pids = {}
    logs = {}
    for port in (TUNNEL_WS_PORT, TUNNEL_API_PORT):
        log_path = os.path.join(os.getcwd(), 'cloudflared-%d.log' % port)
        proc = tunnel_start_process([cloudflared, 'tunnel', '--url', 'http://localhost:%d' % port], log_path)
        tunnel_say('Starting a quick tunnel for port %d...' % port)
        url = tunnel_wait_for_quick_url(log_path, timeout=90)
        if not url:
            tunnel_kill_pid(proc.pid)
            tunnel_say('cloudflared did not print a link for port %d. Check %s' % (port, log_path))
            return False
        links[str(port)] = url
        hosts[str(port)] = tunnel_host_of(url)
        pids[str(port)] = proc.pid
        logs[str(port)] = log_path
    state = {'kind': 'quick', 'links': links, 'hosts': hosts, 'pids': pids, 'logs': logs, 'registry_url': registry_url, 'created': time.strftime('%Y-%m-%dT%H:%M:%S')}
    tunnel_save_state(state_path, state)
    tunnel_say('')
    tunnel_say('Your tunnel links:')
    tunnel_say('  miners (8080): ' + links[str(TUNNEL_WS_PORT)])
    tunnel_say('  website and API (8085): ' + links[str(TUNNEL_API_PORT)])
    tunnel_say('Share the miners link with anyone who wants to mine on your node.')
    tunnel_register_link(hosts[str(TUNNEL_WS_PORT)], registry_url)
    tunnel_say('')
    tunnel_say('Keep this tunnel running. To watch it and restart it if it dies, run:')
    tunnel_say('  python node.py --tunnel-watch')
    return True

def tunnel_named_setup(cloudflared, state_path, registry_url):
    tunnel_say('')
    tunnel_say('Named tunnel: a stable address that survives restarts. You need a')
    tunnel_say('Cloudflare account and a domain whose DNS Cloudflare manages.')
    name = tunnel_ask('Tunnel name', 'munex-node')
    tunnel_say('Logging in to Cloudflare (a browser window will open, log in once)...')
    result = subprocess.run([cloudflared, 'tunnel', 'login'], stdin=sys.stdin)
    if result.returncode != 0:
        tunnel_say('Login did not finish. Run the helper again after logging in.')
        return False
    tunnel_say('Creating the tunnel...')
    result = subprocess.run([cloudflared, 'tunnel', 'create', name], capture_output=True, text=True)
    combined = (result.stdout or '') + (result.stderr or '')
    tunnel_id = None
    credentials_file = None
    try:
        data = json.loads(result.stdout)
        tunnel_id = data.get('id')
        credentials_file = data.get('credentials_file')
    except Exception:
        found = re.search('"id"\\s*:\\s*"([0-9a-f\\-]{36})"', combined)
        if found:
            tunnel_id = found.group(1)
    if not tunnel_id:
        tunnel_say("I could not read the tunnel id from cloudflared's output:")
        tunnel_say(combined[:500])
        tunnel_id = tunnel_ask('Paste the tunnel id here')
    if not credentials_file:
        credentials_file = os.path.join(os.path.expanduser('~'), '.cloudflared', tunnel_id + '.json')
    domain = tunnel_ask('Your domain (for example smchuzza.tech)')
    host_8080 = tunnel_ask('Hostname for miners, port 8080', 'munex-8080.' + domain)
    host_8085 = tunnel_ask('Hostname for website and API, port 8085', 'munex-8085.' + domain)
    config_path = os.path.join(os.getcwd(), 'cloudflared-config.yml')
    lines = ['tunnel: ' + tunnel_id, 'credentials-file: ' + credentials_file, 'ingress:', '  - hostname: ' + host_8080, '    service: http://localhost:8080', '  - hostname: ' + host_8085, '    service: http://localhost:8085', '  - service: http_status:404', '']
    with open(config_path, 'w', encoding='utf-8') as handle:
        handle.write('\n'.join(lines))
    for host in (host_8080, host_8085):
        tunnel_say('Pointing ' + host + ' at the tunnel...')
        result = subprocess.run([cloudflared, 'tunnel', 'route', 'dns', name, host], capture_output=True, text=True)
        if result.returncode != 0:
            tunnel_say('Could not point ' + host + ' at the tunnel:')
            tunnel_say((result.stdout or '') + (result.stderr or ''))
            tunnel_say('Check the domain is in your Cloudflare account, then run the helper again.')
            return False
    log_path = os.path.join(os.getcwd(), 'cloudflared.log')
    proc = tunnel_start_process([cloudflared, 'tunnel', '--config', config_path, 'run', name], log_path)
    state = {'kind': 'named', 'tunnel': name, 'tunnel_id': tunnel_id, 'hostnames': {'8080': host_8080, '8085': host_8085}, 'config': config_path, 'pid': proc.pid, 'log': log_path, 'registry_url': registry_url, 'created': time.strftime('%Y-%m-%dT%H:%M:%S')}
    tunnel_save_state(state_path, state)
    tunnel_say('')
    tunnel_say('Your tunnel links:')
    tunnel_say('  miners (8080): https://' + host_8080 + '/ws')
    tunnel_say('  website and API (8085): https://' + host_8085)
    tunnel_say('Share the miners link with anyone who wants to mine on your node.')
    tunnel_register_link(host_8080, registry_url)
    tunnel_say('')
    tunnel_say('Keep this tunnel running. To watch it and restart it if it dies, run:')
    tunnel_say('  python node.py --tunnel-watch')
    return True

def tunnel_setup(cloudflared, node_dir, state_path, registry_url):
    tunnel_say('')
    tunnel_say('One thing first: the bucket problem.')
    tunnel_say('Through a tunnel, every miner arrives looking like a single address.')
    tunnel_say('On a node older than R21 they all share one bucket of 20 connections')
    tunnel_say('and one rate limit, so the 21st miner gets kicked off and the rest')
    tunnel_say('start getting rate-limited for no reason of their own.')
    tunnel_say('R21 fixed that by reading the real address Cloudflare passes along.')
    if not tunnel_bucket_check(node_dir):
        tunnel_say('Stopped. Update your node first, then run the helper again.')
        return False
    if tunnel_local_node_up():
        tunnel_say('Your node is answering on 8080, good.')
    else:
        tunnel_say('Your node is not answering on 8080 yet. That is fine, the tunnel')
        tunnel_say('will start working once the node is running.')
    choice = tunnel_ask_choice('Named tunnel or quick tunnel?', [('1', 'named - a stable address, needs a Cloudflare account and a domain'), ('2', 'quick - free, no account, but the link changes on every restart')])
    if choice == '1':
        return tunnel_named_setup(cloudflared, state_path, registry_url)
    return tunnel_quick_setup(cloudflared, state_path, registry_url)

def tunnel_setup_flow(args):
    tunnel_say('Munex tunnel setup.')
    tunnel_say('This asks one question, then sets your node up so people can reach it')
    tunnel_say('without you forwarding ports. It changes nothing in your node.')
    choice = tunnel_ask_choice('How will people reach your node?', [('1', 'port forwarding - I forward ports in my router'), ('2', 'Cloudflare Tunnel - no port forwarding, Cloudflare carries it')])
    if choice == '1':
        tunnel_port_forwarding_path()
        return 0
    cloudflared = tunnel_find_cloudflared(args.cloudflared)
    if not cloudflared:
        tunnel_say('cloudflared is not installed yet.')
        path, error = tunnel_download_cloudflared()
        if path:
            tunnel_say('Downloaded cloudflared to ' + path)
            cloudflared = path
        else:
            tunnel_say(error)
            tunnel_install_instructions()
            return 1
    ok = tunnel_setup(cloudflared, args.node_dir, args.state, args.registry_url)
    return 0 if ok else 1

def tunnel_restart_quick_link(state, port, cloudflared):
    log_path = os.path.join(os.getcwd(), 'cloudflared-%d.log' % port)
    old_pid = state.get('pids', {}).get(str(port))
    tunnel_kill_pid(old_pid)
    proc = tunnel_start_process([cloudflared, 'tunnel', '--url', 'http://localhost:%d' % port], log_path)
    url = tunnel_wait_for_quick_url(log_path, timeout=90)
    if not url:
        tunnel_kill_pid(proc.pid)
        return None
    state.setdefault('links', {})[str(port)] = url
    state.setdefault('hosts', {})[str(port)] = tunnel_host_of(url)
    state.setdefault('pids', {})[str(port)] = proc.pid
    state.setdefault('logs', {})[str(port)] = log_path
    return url

def tunnel_restart_named(state, cloudflared):
    old_pid = state.get('pid')
    tunnel_kill_pid(old_pid)
    log_path = state.get('log') or os.path.join(os.getcwd(), 'cloudflared.log')
    proc = tunnel_start_process([cloudflared, 'tunnel', '--config', state['config'], 'run', state['tunnel']], log_path)
    state['pid'] = proc.pid
    state['log'] = log_path
    return True

def tunnel_watch_loop(args):
    if not os.path.isfile(args.state):
        tunnel_say('No tunnel saved yet. Run the setup first: python node.py --tunnel-setup')
        return 1
    lock_path = os.path.join(os.getcwd(), 'munex_tunnel.watch.lock')
    if os.path.isfile(lock_path):
        try:
            with open(lock_path, 'r', encoding='utf-8') as handle:
                old_pid = int(handle.read().strip())
            os.kill(old_pid, 0)
            tunnel_say('A watcher is already running (process ' + str(old_pid) + ').')
            tunnel_say('Only one watcher at a time, or two of them would restart the')
            tunnel_say('tunnel at once and fight each other. Stop the other one first.')
            return 1
        except ProcessLookupError:
            pass
        except Exception:
            pass
    with open(lock_path, 'w', encoding='utf-8') as handle:
        handle.write(str(os.getpid()))
    cloudflared = tunnel_find_cloudflared(args.cloudflared)
    if not cloudflared:
        tunnel_say('cloudflared is not installed. Run the setup first: python node.py --tunnel-setup')
        try:
            os.remove(lock_path)
        except Exception:
            pass
        return 1
    tunnel_say('Watching your tunnel. Checks every ' + str(args.interval) + ' seconds.')
    tunnel_say('The checks are plain web requests, they never open a miner connection,')
    tunnel_say('so the watcher itself can never eat up the connection bucket.')
    tunnel_say('Press Ctrl-C to stop watching. The tunnel keeps running.')
    failures = {'8080': 0, '8085': 0}
    registered = set()
    try:
        while True:
            state = tunnel_load_state(args.state)
            kind = state.get('kind')
            links = {}
            if kind == 'quick':
                links = state.get('links', {})
            else:
                for port, host in state.get('hostnames', {}).items():
                    links[port] = 'https://' + host
            node_up = tunnel_local_node_up()
            changed = False
            for port in ('8080', '8085'):
                url = links.get(port)
                if not url:
                    continue
                if port == '8080':
                    probe = url.rstrip('/') + '/healthz'
                    good = tunnel_healthz_ok(probe)
                else:
                    probe = url.rstrip('/') + '/health'
                    ok, tunnel_status_show, _ = tunnel_probe_url(probe)
                    good = ok and tunnel_status_show == 200
                stamp = time.strftime('%H:%M:%S')
                if good:
                    failures[port] = 0
                    tunnel_say(stamp + ' port ' + port + ' ok')
                    if port == '8080' and url not in registered:
                        registered.add(url)
                        tunnel_register_link(tunnel_host_of(url), state.get('registry_url') or args.registry_url)
                    continue
                failures[port] += 1
                tunnel_say(stamp + ' port ' + port + ' failed (' + str(failures[port]) + '/' + str(args.failures) + ')')
                if failures[port] < args.failures:
                    continue
                failures[port] = 0
                if not node_up:
                    tunnel_say('Your node itself is not answering on 8080. The tunnel')
                    tunnel_say('cannot fix that. Start your node first, then I will')
                    tunnel_say('keep watching the tunnel.')
                    continue
                tunnel_say('Port ' + port + ' looks dead. Restarting its tunnel...')
                if kind == 'quick':
                    new_url = tunnel_restart_quick_link(state, int(port), cloudflared)
                    if not new_url:
                        tunnel_say('The restart did not print a new link. I will try again next round.')
                        continue
                    changed = True
                    tunnel_say('New link for port ' + port + ': ' + new_url)
                    if port == '8080':
                        tunnel_register_link(tunnel_host_of(new_url), state.get('registry_url') or args.registry_url)
                elif tunnel_restart_named(state, cloudflared):
                    changed = True
                    tunnel_say('Tunnel restarted, same links as before.')
                else:
                    tunnel_say('The restart failed. I will try again next round.')
            if changed:
                tunnel_save_state(args.state, state)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        tunnel_say('')
        tunnel_say('Stopped watching. Your tunnel keeps running.')
        return 0
    finally:
        try:
            os.remove(lock_path)
        except Exception:
            pass
    return 0

def tunnel_status_show(args):
    if not os.path.isfile(args.state):
        tunnel_say('No tunnel saved yet. Run the setup first: python node.py --tunnel-setup')
        return 1
    state = tunnel_load_state(args.state)
    tunnel_say('Tunnel kind: ' + str(state.get('kind')))
    if state.get('kind') == 'quick':
        for port, url in state.get('links', {}).items():
            tunnel_say('  port ' + port + ': ' + url)
    else:
        for port, host in state.get('hostnames', {}).items():
            tunnel_say('  port ' + port + ': https://' + host)
    tunnel_say('Your node on this computer: ' + ('up' if tunnel_local_node_up() else 'not answering on 8080'))
    return 0

def tunnel_main(argv):
    import argparse
    parser = argparse.ArgumentParser(description='Munex tunnel setup and watcher.')
    parser.add_argument('--tunnel-setup', action='store_true', help='set up a tunnel (asks port forwarding or tunnel)')
    parser.add_argument('--tunnel-watch', action='store_true', help='watch a saved tunnel and restart it if it dies')
    parser.add_argument('--tunnel-status', action='store_true', help='check a saved tunnel once and print its state')
    parser.add_argument('--cloudflared', default=None, help='path to the cloudflared program')
    parser.add_argument('--node-dir', default=None, help='folder holding node.py, for the version check')
    parser.add_argument('--state', default=os.path.join(os.getcwd(), 'tunnel_state.json'), help='where the tunnel setup is saved')
    parser.add_argument('--interval', type=int, default=TUNNEL_DEFAULT_INTERVAL, help='seconds between watcher checks')
    parser.add_argument('--failures', type=int, default=TUNNEL_DEFAULT_FAILURES, help='failed checks in a row before a restart')
    parser.add_argument('--registry-url', default=os.environ.get('MCX_REGISTRY_URL', TUNNEL_DEFAULT_REGISTRY), help='registry to register the tunnel link with')
    args = parser.parse_args(argv)
    if args.tunnel_watch:
        return tunnel_watch_loop(args)
    if args.tunnel_status:
        return tunnel_status_show(args)
    return tunnel_setup_flow(args)

def tunnel_start_watcher_thread(state_path):
    args = types.SimpleNamespace(cloudflared=None, node_dir=None, state=state_path, interval=TUNNEL_DEFAULT_INTERVAL, failures=TUNNEL_DEFAULT_FAILURES, registry_url=os.environ.get('MCX_REGISTRY_URL', TUNNEL_DEFAULT_REGISTRY))
    thread = threading.Thread(target=tunnel_watch_loop, args=(args,), daemon=True, name='tunnel-watcher')
    thread.start()
    return thread

def tunnel_startup_prompt():
    state_path = os.path.join(os.getcwd(), 'tunnel_state.json')
    choice_path = os.path.join(os.getcwd(), 'tunnel_choice.json')
    if os.path.isfile(state_path):
        tunnel_start_watcher_thread(state_path)
        return
    if os.path.isfile(choice_path):
        try:
            with open(choice_path, encoding='utf-8') as handle:
                saved = json.load(handle).get('choice')
        except Exception:
            saved = None
        if saved == 'forwarding':
            return
        if saved == 'tunnel':
            tunnel_start_watcher_thread(state_path)
            return
    if not sys.stdin.isatty():
        tunnel_say('This is not an interactive terminal, so I will not ask about the tunnel. The node starts without one.')
        return
    tunnel_say('One question before the node starts: how will people reach it?')
    tunnel_say('I will remember your answer, so I only ask once.')
    try:
        answer = tunnel_ask_choice('How will people reach your node?', [('1', 'port forwarding - I forward ports in my router'), ('2', 'Cloudflare Tunnel - no port forwarding, Cloudflare carries it')])
    except (EOFError, KeyboardInterrupt, SystemExit):
        tunnel_say('No answer (no input available), continuing without a tunnel.')
        return
    if answer == '1':
        with open(choice_path, 'w', encoding='utf-8') as handle:
            json.dump({'choice': 'forwarding'}, handle)
        return
    cloudflared = tunnel_find_cloudflared(None)
    if not cloudflared:
        tunnel_say('cloudflared is not installed yet.')
        path, error = tunnel_download_cloudflared()
        if path:
            tunnel_say('Downloaded cloudflared to ' + path)
            cloudflared = path
        else:
            tunnel_say(error)
            tunnel_install_instructions()
            tunnel_say('Tunnel setup did not finish. The node starts without a tunnel; run the setup again with: python node.py --tunnel-setup')
            return
    try:
        ok = tunnel_setup(cloudflared, None, state_path, os.environ.get('MCX_REGISTRY_URL', TUNNEL_DEFAULT_REGISTRY))
    except SystemExit:
        ok = False
    if not ok:
        tunnel_say('Tunnel setup did not finish. The node starts without a tunnel; run the setup again with: python node.py --tunnel-setup')
        return
    with open(choice_path, 'w', encoding='utf-8') as handle:
        json.dump({'choice': 'tunnel'}, handle)
    tunnel_start_watcher_thread(state_path)
