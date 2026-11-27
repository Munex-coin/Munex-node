// munex-registry-worker.js — v5
//
// Munex node registry — Cloudflare Worker, no UI, JSON only.
//
// What it is:
//   A pool of live Munex nodes. Miners fetch it to find a node to mine
//   against, nodes fetch it to find peers to connect to. It is NOT part of
//   the chain and it never touches consensus, blocks, wallets or keys.
//
//   Live at:
//     https://munex-registry.animax-plorer22.workers.dev
//
// How it learns nodes (no node code changes needed for any of these):
//   1. Seed DNS — it resolves munexseed.duckdns.org (DNS-over-HTTPS) on
//      every refresh, exactly like a node does with its dns_seeds. The seed
//      IP is always a registry entry while DNS returns it, even when this
//      edge location cannot reach it (listed with probed: false): miners
//      connect from their own networks, which may reach it fine, and they
//      already trust the seed DNS directly as fallback.
//   2. Static tunnels (v4) — Cloudflare Tunnel nodes configured by the
//      operator in STATIC_TUNNELS below. A tunnel node has no public IP,
//      so it cannot be found by DNS or an IP probe. It is listed with
//      ws_url wss://<host>/ws, p2p "" (raw TCP does not go through a
//      tunnel) and p2p_ws wss://<host>/p2p (P2P over WebSocket — see
//      below). Like the seed it stays listed while configured, with
//      probed:false when the HTTPS probe cannot reach it.
//   3. Crawl — for any known node whose HTTP API port (8085) is reachable
//      it reads GET /peers and learns the peers that node knows. By default
//      a node binds that API to 127.0.0.1, so this only works for nodes
//      whose operator set node.rpc_bind_ip to 0.0.0.0. It is opportunistic:
//      the registry works fine without it. Tunnel nodes are never crawled
//      as a source (v5): their API port is not exposed through the tunnel —
//      but a tunnel node CAN be learned as a crawled peer: when a crawled
//      /peers list names a tunnel hostname, the worker probes it over
//      HTTPS and lists it like any other node, with p2p_ws set. A tunnel
//      entry is still never dialled over raw TCP.
//   4. Push — a node (or its operator) POSTs its own IP to /register, or
//      its tunnel hostname as {"host": "..."}. Miners never push. A
//      register payload may also carry an optional integer "height" (v5):
//      the node's current chain height, stored with a timestamp and
//      served as height + height_at; older than 10 minutes it is served
//      with height_stale true. The worker probes the claimed address
//      first and only lists it if it answers
//      like a Munex node, so nobody can poison the pool with fake IPs or
//      hostnames.
//
// Tunnel nodes — what works and what does not:
//   - Miners CAN find and mine against a tunnel node: miners read ws_url
//     directly, and wss://<host>/ws goes through the tunnel to the node's
//     miner WebSocket (port 8080). The tunnel must forward its root to the
//     node's port 8080, so that https://<host>/healthz (the probe) and
//     wss://<host>/ws (miners) both reach it.
//   - P2P to a tunnel node goes over WebSocket (v5, tunnel parity): a
//     tunnel entry is served with p2p_ws "wss://<host>/p2p", and the
//     node's P2P-over-WS endpoint on its WS port (8080) carries the same
//     framed P2P bytes as raw TCP. Raw TCP on port 8081 still does NOT go
//     through an HTTP tunnel, so p2p stays "" and a node that only speaks
//     raw TCP still skips the entry. The tunnel node itself still syncs
//     by dialing OUT to the seed and other nodes as well.
//   - The node's API port (8085) is not reachable through the tunnel
//     either, so a tunnel node's chain height is unknown (null) UNLESS
//     the node reports it when it registers (v5): POST /register accepts
//     an optional integer "height", stored with a "height_at" timestamp
//     and served as height + height_at; older than 10 minutes it is
//     served with height_stale true instead of being dropped.
//
// How dead entries are cleared:
//   Every refresh the worker probes each listed IP with
//   GET http://<ip>:8080/healthz — the public miner-WS endpoint that every
//   node answers with {"status":"ok","service":"mcx-miner-ws"}. If that
//   fails, it falls back to GET http://<ip>:8085/health and accepts a
//   body with a "PoSW" version string and an integer height (the status
//   is ignored: /health returns 503 when a node has no peers/miners).
//   The fallback exists because some networks cannot reach a home ISP's
//   port 8080 while port 8085 answers fine. An IP that fails 3 refreshes
//   in a row is dropped from the pool. Tunnel hostnames are probed with
//   GET https://<host>/healthz instead (same service check); a registered
//   tunnel is dropped after 3 failed refreshes, a static tunnel stays
//   listed like the seed.
//
// Endpoints:
//   GET  /  and  GET /nodes   -> {"nodes":[{ip, host, tunnel, ws_port,
//                                p2p_port, ws_url, p2p, p2p_ws, last_ok,
//                                height, height_at, height_stale, source,
//                                probed}], "count", "updated_at"}
//                                Miners connect to ws_url, nodes peer with
//                                p2p (raw TCP) or p2p_ws (tunnel, WS).
//                                Tunnel entries have ip "", host set,
//                                tunnel true, ws_url wss://<host>/ws,
//                                p2p "", p2p_ws wss://<host>/p2p.
//   POST /register            -> {"ip", "ws_port", "p2p_port"} for an IP
//                                node, or {"host"} for a tunnel node.
//                                Either may also carry an optional integer
//                                "height" (v5, the node's current height).
//                                ip may be left out: the worker then uses
//                                the connecting IP. Probed before listing.
//                                200 listed, 400 bad input, 429 too soon,
//                                502 node did not answer the probe.
//   GET  /health              -> {"ok":true, "nodes", "last_refresh"}
//
// Deploy (wrangler.toml next to this file):
//   name = "munex-registry"
//   main = "munex-registry-worker-v5.js"
//   compatibility_date = "2026-11-19"
//   [triggers]
//   crons = ["*/5 * * * *"]                   # refresh every 5 minutes
//   [[kv_namespaces]] binding = "REGISTRY_KV"    # optional but recommended:
//   # id = "<your KV namespace id>"               # without KV the pool lives
//                                                 # in memory and resets when
//                                                 # the isolate restarts.
//   Then:  npx wrangler deploy
//
// A node operator pushes their node with one curl (no node change):
//   curl -X POST https://munex-registry.animax-plorer22.workers.dev/register \
//     -H 'Content-Type: application/json' -d '{"ip": "1.2.3.4"}'
// A tunnel operator pushes their tunnel hostname the same way:
//   curl -X POST https://munex-registry.animax-plorer22.workers.dev/register \
//     -H 'Content-Type: application/json' -d '{"host": "friend-node.trycloudflare.com"}'
//   A tunnel node that reports its height (v5) posts it with the register:
//   curl -X POST https://munex-registry.animax-plorer22.workers.dev/register \
//     -H 'Content-Type: application/json' -d '{"host": "friend-node.trycloudflare.com", "height": 1234}'
//
// Honest limits (checked against launch/v11/node.py, R19 136ada78...):
//   - The node's /peers and /health HTTP endpoints bind to rpc_bind_ip,
//     default 127.0.0.1, so a default node cannot be crawled over HTTP.
//   - The P2P wire protocol (port 8081) is encrypted with a Noise-like
//     handshake, so the worker does not speak it. It never needs to: the
//     public /healthz probe on port 8080 proves a node is alive.
//   - The WS API (port 8080) has no peer-list message, only a peer count.
//     So without a push, a node is found only through the seed or a crawl.
//   - A tunnel node is never a raw-TCP P2P peer: P2P to it goes over WS (/p2p, see "Tunnel nodes" above).

const SEED_HOST = "munexseed.duckdns.org";
const SEED_WS_PORT = 8080;
const SEED_P2P_PORT = 8081;
const API_PORT = 8085;
const DOH_URL = "https://cloudflare-dns.com/dns-query";
const KV_KEY = "pool:v1";
const MAX_NODES = 500;
const FAILS_TO_DROP = 3;
const PROBE_TIMEOUT_MS = 4000;
const CRAWL_TIMEOUT_MS = 4000;
const REFRESH_MIN_INTERVAL_MS = 60_000;
const REGISTER_MIN_INTERVAL_MS = 60_000;
const HEIGHT_STALE_MS = 600_000; // 10 minutes: a height older than this is served with height_stale true, not dropped

// Static Cloudflare Tunnel nodes, configured by the operator.
// Put each tunnel hostname here (just the hostname, no scheme, no path)
// and redeploy; the registry lists it to miners on the next refresh.
// The tunnel MUST forward its root to the node's miner-WS port (8080).
const STATIC_TUNNELS = [
  // (none) — the friend's old tunnel was removed 2026-11-27 (DNS gone) and
  // must not come back. Add a tunnel hostname here to list it statically.
];

const state = {
  pool: null, // Map<key, entry> when KV is absent; null until first load
  lastRefresh: 0,
  refreshing: false,
  lastRegister: new Map(), // key (ip or "host:"+host) -> timestamp, abuse throttle for /register
};

function now() {
  return Date.now();
}

function bracket(ip) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

function isIPv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
}

function isPublicIP(s) {
  if (typeof s !== "string" || !s) return false;
  if (isIPv4(s)) {
    const [a, b] = s.split(".").map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0 && (s.startsWith("192.0.0.") || s.startsWith("192.0.2."))) return false;
    if (s.startsWith("198.51.100.") || s.startsWith("203.0.113.")) return false;
    return true;
  }
  // IPv6 (loose check: hex groups and colons only, then reject special ranges)
  if (!/^[0-9a-fA-F:]+$/.test(s) || !s.includes(":")) return false;
  const low = s.toLowerCase();
  if (low === "::" || low === "::1") return false;
  if (low.startsWith("fe8") || low.startsWith("fe9") || low.startsWith("fea") || low.startsWith("feb")) return false;
  if (low.startsWith("fc") || low.startsWith("fd")) return false;
  if (low.startsWith("ff")) return false;
  if (low.startsWith("2001:db8")) return false;
  return true;
}

// A public DNS hostname (not an IP, not localhost). Used for tunnel nodes.
function isValidHostname(s) {
  if (typeof s !== "string") return false;
  const h = s.trim().toLowerCase();
  if (!h || h.length > 253) return false;
  if (h === "localhost" || h.endsWith(".localhost")) return false;
  if (isIPv4(h) || h.includes(":")) return false; // an IP, not a hostname
  if (!h.includes(".")) return false; // needs a dot: a real public name
  const labels = h.split(".");
  for (const lab of labels) {
    if (!lab || lab.length > 63) return false;
    if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(lab)) return false;
  }
  const tld = labels[labels.length - 1];
  if (/^\d+$/.test(tld)) return false; // TLD must not be all digits
  return true;
}

// Pool key for an entry: the IP itself, or "host:"+hostname for tunnels.
function entryKey(e) {
  if (e.key) return e.key;
  if (e.host) return "host:" + String(e.host).toLowerCase();
  return e.ip;
}

// "http://1.2.3.4:8085/rpc" or "1.2.3.4:8081" or "[2001:db8::1]:8081" -> host
function hostFromUrlOrAddr(value) {
  if (typeof value !== "string") return null;
  let v = value.trim();
  if (!v) return null;
  const scheme = v.indexOf("://");
  if (scheme !== -1) v = v.slice(scheme + 3);
  v = v.split("/")[0].split("?")[0].split("#")[0];
  if (!v) return null;
  if (v.startsWith("[")) {
    const end = v.indexOf("]");
    if (end === -1) return null;
    return v.slice(1, end);
  }
  const colon = v.lastIndexOf(":");
  if (colon !== -1 && v.indexOf(":") === colon) return v.slice(0, colon); // host:port
  if (v.includes(":")) return v; // bare IPv6 without port
  return v;
}

function portFromUrlOrAddr(value, fallback) {
  if (typeof value !== "string") return fallback;
  let v = value.trim();
  const scheme = v.indexOf("://");
  if (scheme !== -1) v = v.slice(scheme + 3);
  v = v.split("/")[0];
  if (v.startsWith("[")) {
    const rest = v.slice(v.indexOf("]") + 1);
    const m = rest.match(/^:(\d+)$/);
    return m ? Number(m[1]) : fallback;
  }
  const colon = v.lastIndexOf(":");
  if (colon !== -1 && v.indexOf(":") === colon) {
    const p = Number(v.slice(colon + 1));
    return Number.isInteger(p) && p > 0 && p <= 65535 ? p : fallback;
  }
  return fallback;
}

function publicEntry(ip, source, extra) {
  return {
    ip,
    host: "",
    tunnel: false,
    key: ip,
    ws_port: SEED_WS_PORT,
    p2p_port: SEED_P2P_PORT,
    ws_url: `ws://${bracket(ip)}:${SEED_WS_PORT}/ws`,
    p2p: `${bracket(ip)}:${SEED_P2P_PORT}`,
    p2p_ws: "", // IP nodes peer over raw TCP (p2p); p2p_ws is the tunnel-parity field (v5)
    source,
    first_seen: now(),
    last_seen: now(),
    last_ok: 0,
    fails: 0,
    height: null,
    height_at: null, // timestamp (ms) of the height value, or null when unknown
    probed: false, // true only when a probe actually reached this node
    ...(extra || {}),
  };
}

function tunnelEntry(host, source, extra) {
  const h = String(host).toLowerCase();
  return {
    ip: "",
    host: h,
    tunnel: true,
    key: "host:" + h,
    ws_port: 443,
    p2p_port: 0,
    ws_url: `wss://${h}/ws`,
    p2p: "", // raw TCP does not go through an HTTP tunnel; nodes that only speak raw TCP skip this entry
    p2p_ws: `wss://${h}/p2p`, // (v5) P2P over WebSocket: same framed P2P bytes as raw TCP, on the node's WS port
    source,
    first_seen: now(),
    last_seen: now(),
    last_ok: 0,
    fails: 0,
    height: null, // API port (8085) is not exposed through the tunnel; set from /register "height" (v5) or a /health probe
    height_at: null, // timestamp (ms) of the height value, or null when unknown
    probed: false, // true only when a probe actually reached this node
    ...(extra || {}),
  };
}

async function loadPool(env) {
  if (env && env.REGISTRY_KV) {
    try {
      const raw = await env.REGISTRY_KV.get(KV_KEY);
      if (raw) {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          const map = new Map();
          for (const e of arr) {
            if (!e) continue;
            if (e.host && isValidHostname(e.host)) {
              e.key = "host:" + String(e.host).toLowerCase();
              map.set(e.key, e);
            } else if (e.ip && isPublicIP(e.ip)) {
              e.key = e.ip;
              map.set(e.key, e);
            }
          }
          state.pool = map;
          return map;
        }
      }
    } catch {
      // fall through to the in-memory pool
    }
  }
  if (!state.pool) state.pool = new Map();
  return state.pool;
}

async function savePool(env) {
  if (!state.pool) return;
  if (env && env.REGISTRY_KV) {
    try {
      await env.REGISTRY_KV.put(KV_KEY, JSON.stringify([...state.pool.values()]));
    } catch {
      // KV write failed; the in-memory pool still serves this isolate
    }
  }
}

function upsert(pool, ip, source, extra) {
  const existing = pool.get(ip);
  if (existing) {
    existing.last_seen = now();
    if (extra) {
      if (extra.p2p_port) existing.p2p_port = extra.p2p_port;
      if (extra.ws_port) existing.ws_port = extra.ws_port;
      existing.ws_url = `ws://${bracket(ip)}:${existing.ws_port}/ws`;
      existing.p2p = `${bracket(ip)}:${existing.p2p_port}`;
    }
    return existing;
  }
  const entry = publicEntry(ip, source, extra);
  pool.set(ip, entry);
  return entry;
}

function upsertHost(pool, host, source, extra) {
  const h = String(host).toLowerCase();
  const key = "host:" + h;
  const existing = pool.get(key);
  if (existing) {
    existing.last_seen = now();
    return existing;
  }
  const entry = tunnelEntry(h, source, extra);
  pool.set(key, entry);
  return entry;
}

// Record a height with the time it was learned (v5). Returns false when
// the value is not a usable height; the entry is left unchanged then.
function setHeight(entry, height, t) {
  if (!Number.isInteger(height) || height < 0) return false;
  entry.height = height;
  entry.height_at = t;
  return true;
}

// True when the entry carries a height that is too old to trust fresh
// (v5): older than HEIGHT_STALE_MS, or a height with no timestamp at all
// (e.g. an entry stored by v4, before height_at existed). A stale height
// is still served — with height_stale true — never silently dropped.
function isHeightStale(entry, t) {
  if (entry.height === null || entry.height === undefined) return false;
  if (!entry.height_at) return true;
  return t - entry.height_at > HEIGHT_STALE_MS;
}

// Resolve the seed hostname to IPs via DNS-over-HTTPS.
async function resolveSeedIPs() {
  try {
    const url = `${DOH_URL}?name=${encodeURIComponent(SEED_HOST)}&type=A`;
    const res = await fetch(url, {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return [];
    const data = await res.json();
    const ips = [];
    for (const a of data.Answer || []) {
      if (a.type === 1 && typeof a.data === "string" && isPublicIP(a.data)) ips.push(a.data);
    }
    return ips;
  } catch {
    return [];
  }
}

// Prove an IP is a live Munex node. First try the public /healthz on
// port 8080, which answers {"status":"ok","service":"mcx-miner-ws"}.
// Fallback: port 8085 /health. Some networks (notably Cloudflare's edge)
// cannot reach a home ISP's port 8080 while port 8085 answers fine, so
// a node whose API is bound to 0.0.0.0 is also accepted on its /health
// body: a version string containing "PoSW" plus an integer height.
// /health returns 503 when the node has no peers/miners, so the status
// is NOT checked here — the body is the proof. Best effort on both
// paths: also read the chain height when the API answers.
async function probeNode(ip, wsPort) {
  const port = wsPort || SEED_WS_PORT;
  try {
    const res = await fetch(`http://${bracket(ip)}:${port}/healthz`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      headers: { "User-Agent": "munex-registry/1.0" },
    });
    if (res.ok) {
      const body = await res.json().catch(() => null);
      if (body && body.service === "mcx-miner-ws") {
        let height = null;
        try {
          const h = await fetch(`http://${bracket(ip)}:${API_PORT}/health`, {
            signal: AbortSignal.timeout(2500),
            headers: { "User-Agent": "munex-registry/1.0" },
          });
          const hj = await h.json().catch(() => null);
          if (hj && Number.isInteger(hj.height)) height = hj.height;
        } catch {
          // API port not exposed; height stays unknown
        }
        return { ok: true, height };
      }
    }
  } catch {
    // 8080 unreachable from here; try the 8085 fallback below
  }
  try {
    const h = await fetch(`http://${bracket(ip)}:${API_PORT}/health`, {
      signal: AbortSignal.timeout(2500),
      headers: { "User-Agent": "munex-registry/1.0" },
    });
    const hj = await h.json().catch(() => null);
    if (
      hj &&
      typeof hj.version === "string" &&
      hj.version.includes("PoSW") &&
      Number.isInteger(hj.height)
    ) {
      return { ok: true, height: hj.height };
    }
  } catch {
    // API port not exposed either
  }
  return { ok: false };
}

// Prove a tunnel hostname is a live Munex node: the tunnel forwards its
// root to the node's miner-WS port (8080), so GET https://<host>/healthz
// must answer {"status":"ok","service":"mcx-miner-ws"}. The /health height
// is best effort only — the API port (8085) is normally not exposed
// through the tunnel, so height usually stays unknown (null).
async function probeHost(host) {
  try {
    const res = await fetch(`https://${host}/healthz`, {
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
      headers: { "User-Agent": "munex-registry/1.0" },
    });
    if (res.ok) {
      const body = await res.json().catch(() => null);
      if (body && body.service === "mcx-miner-ws") {
        let height = null;
        try {
          const h = await fetch(`https://${host}/health`, {
            signal: AbortSignal.timeout(2500),
            headers: { "User-Agent": "munex-registry/1.0" },
          });
          const hj = await h.json().catch(() => null);
          if (hj && Number.isInteger(hj.height)) height = hj.height;
        } catch {
          // API port not exposed via the tunnel; height stays unknown
        }
        return { ok: true, height };
      }
    }
  } catch {
    // tunnel unreachable from here
  }
  return { ok: false };
}

// Ask a node for the peers it knows (GET /peers on its API port).
// Returns [{kind: "ip", ip, p2p_port} | {kind: "host", host}] — public
// IPs and public tunnel hostnames only (v5: a peer may name itself by
// url, ws_url or p2p_ws; any of those may carry the hostname). Empty
// when the node does not expose its API, which is the default. Private
// IPs, localhost and garbage are still skipped.
async function crawlPeers(ip) {
  try {
    const res = await fetch(`http://${bracket(ip)}:${API_PORT}/peers`, {
      signal: AbortSignal.timeout(CRAWL_TIMEOUT_MS),
      headers: { "User-Agent": "munex-registry/1.0" },
    });
    if (!res.ok) return [];
    const data = await res.json().catch(() => null);
    if (!data || !Array.isArray(data.peers)) return [];
    const out = [];
    const seen = new Set();
    for (const p of data.peers) {
      if (!p || typeof p !== "object") continue;
      let host = null;
      for (const s of [p.p2p_ws, p.ws_url, p.url]) {
        host = hostFromUrlOrAddr(s);
        if (host) break;
      }
      if (!host || seen.has(host.toLowerCase())) continue;
      seen.add(host.toLowerCase());
      if (isPublicIP(host)) {
        out.push({ kind: "ip", ip: host, p2p_port: portFromUrlOrAddr(p.url || p.ws_url || p.p2p_ws, SEED_P2P_PORT) });
      } else if (isValidHostname(host)) {
        out.push({ kind: "host", host: host.toLowerCase() });
      }
      // anything else (private IP, localhost, garbage) is skipped
    }
    return out;
  } catch {
    return [];
  }
}

// One maintenance pass: seed -> static tunnels -> probe all -> crawl the
// live IP ones -> prune.
// The seed DNS name is the operator's own bootstrap, so a seed IP that
// this edge location cannot reach is still listed (probed: false, height
// unknown) as long as DNS keeps returning it: miners connect from their
// own networks, which may reach it fine, and miners already trust the
// seed DNS directly as fallback, so this adds no new trust. A seed IP
// that DNS stops returning ages out like any other entry (3 failed
// refreshes). Static tunnels get the same treatment: they are operator
// configured, so they stay listed while configured, with probed:false
// when the HTTPS probe cannot reach them. Random pushes and crawled peers
// still need a live probe.
async function refresh(env) {
  if (state.refreshing) return;
  state.refreshing = true;
  try {
    const pool = await loadPool(env);
    const t = now();

    const seedIPs = new Set(await resolveSeedIPs());
    for (const ip of seedIPs) upsert(pool, ip, "seed");

    const staticHosts = new Set();
    for (const host of STATIC_TUNNELS) {
      if (isValidHostname(host)) {
        staticHosts.add(String(host).toLowerCase());
        upsertHost(pool, host, "tunnel-static");
      }
    }

    for (const entry of [...pool.values()]) {
      const isHost = !!entry.host;
      const probe = isHost ? await probeHost(entry.host) : await probeNode(entry.ip, entry.ws_port);
      if (probe.ok) {
        entry.last_ok = t;
        entry.fails = 0;
        entry.last_seen = t;
        entry.probed = true;
        if (probe.height !== null && probe.height !== undefined) setHeight(entry, probe.height, t);
        if (!isHost) {
          for (const cand of await crawlPeers(entry.ip)) {
            if (cand.kind === "host") {
              // v5: a tunnel node learned from a /peers list. Probed over
              // HTTPS like any other tunnel entry; never over raw TCP.
              const key = "host:" + cand.host;
              if (pool.has(key)) continue;
              const cp = await probeHost(cand.host);
              if (cp.ok) {
                const added = upsertHost(pool, cand.host, "crawl");
                added.last_ok = t;
                added.fails = 0;
                added.probed = true;
                if (cp.height !== null && cp.height !== undefined) setHeight(added, cp.height, t);
              }
            } else {
              if (pool.has(cand.ip)) continue;
              const cp = await probeNode(cand.ip, SEED_WS_PORT);
              if (cp.ok) {
                const added = upsert(pool, cand.ip, "crawl", { p2p_port: cand.p2p_port });
                added.last_ok = t;
                added.fails = 0;
                added.probed = true;
                if (cp.height !== null && cp.height !== undefined) setHeight(added, cp.height, t);
              }
            }
          }
        }
      } else if (entry.source === "seed" && seedIPs.has(entry.ip)) {
        entry.last_ok = t;
        entry.fails = 0;
        entry.last_seen = t;
        entry.probed = false;
      } else if (entry.source === "tunnel-static" && staticHosts.has(String(entry.host).toLowerCase())) {
        entry.last_ok = t;
        entry.fails = 0;
        entry.last_seen = t;
        entry.probed = false;
      } else {
        entry.fails += 1;
      }
    }

    for (const [k, entry] of pool) {
      if (entry.fails >= FAILS_TO_DROP) pool.delete(k);
    }
    if (pool.size > MAX_NODES) {
      const sorted = [...pool.values()].sort((a, b) => (b.last_ok || 0) - (a.last_ok || 0));
      for (const e of sorted.slice(MAX_NODES)) pool.delete(entryKey(e));
    }

    state.lastRefresh = t;
    await savePool(env);
  } finally {
    state.refreshing = false;
  }
}

function servedList(pool) {
  return [...pool.values()]
    .filter((e) => e.fails === 0 && e.last_ok > 0)
    .sort((a, b) => (b.last_ok || 0) - (a.last_ok || 0))
    .map((e) => ({
      ip: e.ip || "",
      host: e.host || "",
      tunnel: e.tunnel === true,
      ws_port: e.ws_port,
      p2p_port: e.p2p_port,
      ws_url: e.ws_url,
      p2p: e.p2p,
      // v5: tunnel entries carry p2p_ws. Entries stored by v4 have no
      // p2p_ws field, so derive it from the hostname here (the same
      // value tunnelEntry() writes for new entries).
      p2p_ws: e.tunnel === true && e.host ? `wss://${e.host}/p2p` : e.p2p_ws || "",
      last_ok: e.last_ok,
      height: e.height,
      height_at: e.height_at || null,
      height_stale: isHeightStale(e, now()),
      source: e.source,
      probed: e.probed === true, // false = listed on seed-DNS / operator trust only
    }));
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

async function handleRegister(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "body must be JSON" }, 400);
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ ok: false, error: "body must be a JSON object" }, 400);
  }

  // v5: an optional integer height (the registering node's current
  // height). Validated once here so the host and IP paths share one
  // rule; a bad height is a 400 and does not consume the throttle.
  let regHeight = null;
  if (body.height !== undefined && body.height !== null) {
    if (!Number.isInteger(body.height) || body.height < 0) {
      return json({ ok: false, error: "height must be a non-negative integer" }, 400);
    }
    regHeight = body.height;
  }

  // Tunnel / hostname registration: {"host": "friend-node.trycloudflare.com"}
  const hostRaw = typeof body.host === "string" ? body.host.trim() : "";
  if (hostRaw) {
    if (!isValidHostname(hostRaw)) {
      return json({ ok: false, error: "host must be a public DNS hostname (not an IP, not localhost)" }, 400);
    }
    const host = hostRaw.toLowerCase();
    const key = "host:" + host;
    const last = state.lastRegister.get(key) || 0;
    if (now() - last < REGISTER_MIN_INTERVAL_MS) {
      return json({ ok: false, error: "already registered recently, try again later" }, 429);
    }
    state.lastRegister.set(key, now());

    // Prove it before listing it: a dead or fake hostname never enters the pool.
    const probe = await probeHost(host);
    if (!probe.ok) {
      return json({ ok: false, error: "node did not answer the probe (https://<host>/healthz)" }, 502);
    }
    const pool = await loadPool(env);
    const entry = upsertHost(pool, host, "register");
    entry.last_ok = now();
    entry.fails = 0;
    entry.probed = true;
    if (probe.height !== null && probe.height !== undefined) setHeight(entry, probe.height, now());
    if (regHeight !== null) setHeight(entry, regHeight, now()); // the node's own report wins over the probe
    await savePool(env);
    return json({ ok: true, node: servedList(pool).find((n) => n.host === host) || null, count: servedList(pool).length });
  }

  // IP registration (unchanged from v3).
  const callerIp = request.headers.get("CF-Connecting-IP");
  let ip = typeof body.ip === "string" ? body.ip.trim() : "";
  if (!ip) ip = callerIp || "";
  if (!isPublicIP(ip)) {
    return json({ ok: false, error: "ip must be a public IP address" }, 400);
  }
  const wsPort = body.ws_port === undefined ? SEED_WS_PORT : Number(body.ws_port);
  const p2pPort = body.p2p_port === undefined ? SEED_P2P_PORT : Number(body.p2p_port);
  if (!Number.isInteger(wsPort) || wsPort < 1 || wsPort > 65535) {
    return json({ ok: false, error: "ws_port must be 1-65535" }, 400);
  }
  if (!Number.isInteger(p2pPort) || p2pPort < 1 || p2pPort > 65535) {
    return json({ ok: false, error: "p2p_port must be 1-65535" }, 400);
  }
  const last = state.lastRegister.get(ip) || 0;
  if (now() - last < REGISTER_MIN_INTERVAL_MS) {
    return json({ ok: false, error: "already registered recently, try again later" }, 429);
  }
  state.lastRegister.set(ip, now());

  // Prove it before listing it: a dead or fake IP never enters the pool.
  const probe = await probeNode(ip, wsPort);
  if (!probe.ok) {
    return json({ ok: false, error: "node did not answer the probe (http://<ip>:8080/healthz)" }, 502);
  }
  const pool = await loadPool(env);
  const entry = upsert(pool, ip, "register", { ws_port: wsPort, p2p_port: p2pPort });
  entry.last_ok = now();
  entry.fails = 0;
  entry.probed = true;
  if (probe.height !== null && probe.height !== undefined) setHeight(entry, probe.height, now());
  if (regHeight !== null) setHeight(entry, regHeight, now()); // the node's own report wins over the probe
  await savePool(env);
  return json({ ok: true, node: servedList(pool).find((n) => n.ip === ip) || null, count: servedList(pool).length });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }
    if (path === "/health" && request.method === "GET") {
      const pool = await loadPool(env);
      return json({ ok: true, nodes: servedList(pool).length, last_refresh: state.lastRefresh || null, seed: SEED_HOST });
    }
    if (path === "/register" && request.method === "POST") {
      return handleRegister(request, env);
    }
    if ((path === "/" || path === "/nodes") && request.method === "GET") {
      const pool = await loadPool(env);
      if (pool.size === 0) {
        // Cold start: build the list now so the first fetch is not empty.
        await refresh(env);
      } else if (now() - state.lastRefresh > REFRESH_MIN_INTERVAL_MS && ctx && ctx.waitUntil) {
        ctx.waitUntil(refresh(env));
      }
      const nodes = servedList(pool);
      return json({ nodes, count: nodes.length, updated_at: state.lastRefresh || null, seed: SEED_HOST });
    }
    return json({ ok: false, error: "not found" }, 404);
  },

  // Cloudflare Cron Trigger: refresh the pool every few minutes so dead
  // entries are cleared even when nobody is fetching the list.
  async scheduled(_event, env, _ctx) {
    await refresh(env);
  },
};
