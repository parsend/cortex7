# Cortex7

Caddy fork with built-in **cortex7**: L7 DDoS/WAF middleware (in-memory vector store, rate limits, JS challenge, WAF rules). Optimized for high RPS.

**Repository:** [github.com/parsend/cortex7](https://github.com/parsend/cortex7)  
**Author:** parsend (c0redev)

Based on [Caddy](https://github.com/caddyserver/caddy) v2. All Caddy features, docs, and config formats apply; cortex7 adds one extra handler and Caddyfile directive.

---

## Cortex7 at a glance

- **No Redis.** In-memory sharded store (256 shards).
- **Real IP:** Cf-Connecting-Ip, X-Forwarded-For, or a custom header.
- **Rate limits:** per-IP general limit; separate limits for sensitive paths (login, auth); per-host limit (ip:host); fingerprint limit (UA+Accept pattern); unique-URL throttle (scan/cache-bust); failed-auth limit with block.
- **Block list:** blocked IPs get 444 + `Connection: close` (optionally no body so browsers retry less).
- **Bypass and allowlist:** secret in header or cookie skips all checks; IP/CIDR allowlist skips all checks.
- **Honeypot and trap:** hit a honeypot path (e.g. /wp-admin) → block IP; path contains substring (e.g. .env, .git) → block IP.
- **Bot checks:** require User-Agent and/or Accept; block bad User-Agent list; max body size (reject if Content-Length > N).
- **JS challenge:** session tokens stored server-side (not derivable), bind to IP; configurable TTL and store reset interval (e.g. 10m); polymorphic cookie name and challenge path per instance; optional response jitter.
- **WAF:** path/query/header substring rules, block and add IP to block list.
- **Auto-enable:** turn protection on/off when global RPS crosses a threshold.
- **Caddyfile:** `cortex7 { ... }` and JSON in `handle` array.

---

## Build

Requirements: Go 1.25+

```bash
git clone https://github.com/parsend/cortex7.git
cd cortex7/cmd/caddy
go build -tags=nobadger,nomysql,nopgx
```

Linux, bind to low ports:

```bash
sudo setcap cap_net_bind_service=+ep ./caddy
```

---

## Caddyfile example

Put `cortex7` first in your `handle` block so it runs before other handlers.

```caddyfile
:8080 {
	cortex7 {
		enabled
		auto_enable 2000 500
		whitelist /health /metrics
		sensitive_paths /login /api/auth
		sensitive_limit 10
		general_prefix /api/
		general_limit 120
		failed_auth_limit 10
		block_duration 10m
		block_duration_failed_auth 30m
		real_ip_cf
		js_challenge
		challenge_path /.c7c
		close_no_body
		block_referer https://example.com/
		waf_rule sql path "union"
		waf_rule xss header "<script"
	}
	respond "OK" 200
}
```

**Cortex7 block options (Caddyfile):**

| Option | Args | Description |
|--------|------|-------------|
| `enabled` | - | Turn protection on manually |
| `auto_enable` | [enable_rpm] [disable_rpm] | Auto on/off by requests per minute |
| `whitelist` | paths... | Paths that skip all checks |
| `sensitive_paths` | paths... | Paths with stricter per-path limit |
| `sensitive_limit` | N | Requests/min per sensitive path |
| `general_prefix` | prefix | Apply general limit only to this path prefix (empty = all) |
| `general_limit` | N | Requests/min per IP (general); 0 = disable |
| `rate_limit_window` | duration | Bucket window for rate limits (default 1m) |
| `failed_auth_limit` | N | Failed auth events in 15 min → block |
| `block_duration` | duration | Block TTL for rate-limit hits |
| `block_duration_failed_auth` | duration | Block TTL for failed-auth |
| `reject_status_code` | N | Status code on block (default 444) |
| `max_body_reject_code` | N | Status code when max body exceeded (default 413) |
| `reject_redirect_url` | url | Redirect to URL instead of 444/403 |
| `reject_body` | path or HTML | Custom HTML body or path to file |
| `log_blocks` | - | Log reason, IP, path, method on block |
| `real_ip_cf` | - | Use Cf-Connecting-Ip |
| `real_ip_header` | name | Use custom header for client IP |
| `real_ip_xff_mode` | first\|last | X-Forwarded-For: first (default) or last IP |
| `js_challenge` | [path] | Enable JS challenge; optional path |
| `challenge_path` | path | Challenge URL path (default `/.c7c`) |
| `challenge_path_limit` | N | Requests/min per IP to challenge path; 0 = no limit |
| `challenge_store_max_size` | N | Max tokens in store; 0 = no limit |
| `cookie_name` | name | Challenge cookie name |
| `close_no_body` | - | 444 with no body (fewer browser retries) |
| `blocklist_file` | path | File with IP/CIDR per line (block list) |
| `blocklist_reload_interval` | duration | Reload blocklist file interval |
| `block_referer` | substrings... | Block request if Referer contains any |
| `waf_rule` | id type match [action] | type: path, query, header; action: block (default) or challenge |

---

## JSON config example

Same behaviour via JSON (e.g. `http.handlers.cortex7`):

```json
{
  "handler": "cortex7",
  "enabled": true,
  "auto_enable": true,
  "auto_enable_threshold": 2000,
  "auto_disable_threshold": 500,
  "whitelist": ["/health", "/metrics"],
  "sensitive_paths": ["/login", "/api/auth"],
  "sensitive_limit": 10,
  "general_prefix": "/api/",
  "general_limit": 120,
  "failed_auth_limit": 10,
  "block_duration": "10m",
  "block_duration_failed_auth": "30m",
  "js_challenge": true,
  "challenge_path": "/.c7c",
  "close_no_body": true,
  "waf_rules": [
    { "id": "sql", "type": "path", "match": "union", "action": "block" },
    { "id": "xss", "type": "header", "match": "<script", "action": "block" }
  ]
}
```

---

## Failed auth tracking

From your login/auth handler, call cortex7 so failed attempts are counted and can trigger a block:

```go
import "github.com/caddyserver/caddy/v2/modules/caddyhttp/cortex7"

// after failed auth:
if h := cortex7.HandlerFromContext(r.Context()); h != nil {
	h.TrackFailedAuth(ip)
}
```

To have the handler in context, inject it (e.g. via a wrapper or by storing the handler reference where your auth code can access it). The cortex7 handler itself does not set `Cortex7CtxKey`; you need to add it in your setup if you use `HandlerFromContext`.

---

## Licence and upstream

- **Cortex7 middleware:** parsend (c0redev).  
- **Caddy:** Apache 2.0; see [Caddy licence](https://github.com/caddyserver/caddy/blob/master/LICENSE) and [AUTHORS](AUTHORS).

This project is a fork of [Caddy](https://github.com/caddyserver/caddy). Caddy is a trademark of Stack Holdings GmbH.

---