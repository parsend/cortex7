// cortex7 Caddyfile parsing.
// github.com/parsend/cortex7 (parsend/c0redev)

package cortex7

import (
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("cortex7", parseCaddyfile)
}

// parseCaddyfile parses cortex7 { ... }.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	h.Next()

	handler := &Handler{}
	for h.NextBlock(0) {
		key := h.Val()
		switch key {
		case "enabled":
			if !h.NextArg() {
				return nil, h.ArgErr()
			}
			handler.Enabled = h.Val() == "true" || h.Val() == "1"
		case "auto_enable":
			handler.AutoEnable = true
			if h.NextArg() {
				n, _ := strconv.ParseInt(h.Val(), 10, 64)
				handler.AutoThresholdEnable = n
			}
			if h.NextArg() {
				n, _ := strconv.ParseInt(h.Val(), 10, 64)
				handler.AutoThresholdDisable = n
			}
		case "whitelist":
			for h.NextArg() {
				handler.WhitelistPaths = append(handler.WhitelistPaths, h.Val())
			}
		case "sensitive_paths":
			for h.NextArg() {
				handler.SensitivePaths = append(handler.SensitivePaths, h.Val())
			}
		case "sensitive_limit":
			if h.NextArg() {
				handler.SensitiveLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "general_prefix":
			if h.NextArg() {
				handler.GeneralPrefix = h.Val()
			}
		case "general_limit":
			if h.NextArg() {
				n, _ := strconv.ParseInt(h.Val(), 10, 64)
				handler.GeneralLimit = &n
			}
		case "burst_limit":
			if h.NextArg() {
				n, _ := strconv.ParseInt(h.Val(), 10, 64)
				handler.BurstLimit = n
			}
		case "burst_window":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.BurstWindow = caddy.Duration(d)
			}
		case "rate_limit_window":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.RateLimitWindow = caddy.Duration(d)
			}
		case "failed_auth_limit":
			if h.NextArg() {
				handler.FailedAuthLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "block_duration":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.BlockDuration = caddy.Duration(d)
			}
		case "block_duration_failed_auth":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.BlockDurationAuth = caddy.Duration(d)
			}
		case "real_ip_cf":
			handler.RealIPHeaderCF = "Cf-Connecting-Ip"
		case "real_ip_header":
			if h.NextArg() {
				handler.RealIPHeaderCustom = h.Val()
			}
		case "real_ip_xff_mode":
			if h.NextArg() {
				handler.RealIPXFFMode = h.Val()
			}
		case "reject_status_code":
			if h.NextArg() {
				n, _ := strconv.Atoi(h.Val())
				handler.RejectStatusCode = n
			}
		case "max_body_reject_code":
			if h.NextArg() {
				n, _ := strconv.Atoi(h.Val())
				handler.MaxBodyRejectCode = n
			}
		case "reject_redirect_url":
			if h.NextArg() {
				handler.RejectRedirectURL = h.Val()
			}
		case "reject_body":
			if h.NextArg() {
				handler.RejectBody = h.Val()
			}
		case "js_challenge":
			handler.JSChallenge = true
			if h.NextArg() {
				handler.ChallengePath = h.Val()
			}
		case "challenge_path":
			if h.NextArg() {
				handler.ChallengePath = h.Val()
			}
		case "challenge_path_limit":
			if h.NextArg() {
				handler.ChallengePathLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "challenge_store_max_size":
			if h.NextArg() {
				handler.ChallengeStoreMaxSize, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "cookie_name":
			if h.NextArg() {
				handler.CookieName = h.Val()
			}
		case "challenge_token_ttl":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.ChallengeTokenTTL = caddy.Duration(d)
			}
		case "challenge_store_reset_interval":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.ChallengeStoreResetInterval = caddy.Duration(d)
			}
		case "cookie_secure":
			handler.CookieSecure = true
		case "cookie_same_site":
			if h.NextArg() {
				handler.CookieSameSite = h.Val()
			}
		case "cookie_path":
			if h.NextArg() {
				handler.CookiePath = h.Val()
			}
		case "cookie_domain":
			if h.NextArg() {
				handler.CookieDomain = h.Val()
			}
		case "cookie_max_age":
			if h.NextArg() {
				handler.CookieMaxAge, _ = strconv.Atoi(h.Val())
			}
		case "cookie_random_suffix":
			handler.CookieRandomSuffix = true
		case "challenge_path_random_suffix":
			handler.ChallengePathRandomSuffix = true
		case "no_cookie_reject":
			handler.NoCookieReject = true
		case "response_jitter_min_ms":
			if h.NextArg() {
				handler.ResponseJitterMin, _ = strconv.Atoi(h.Val())
			}
		case "response_jitter_max_ms":
			if h.NextArg() {
				handler.ResponseJitterMax, _ = strconv.Atoi(h.Val())
			}
		case "close_no_body":
			handler.CloseNoBody = true
		case "block_referer":
			for h.NextArg() {
				handler.BlockRefererList = append(handler.BlockRefererList, h.Val())
			}
		case "waf_rule":
			if h.NextArg() {
				id := h.Val()
				typ := "path"
				match := ""
				action := "block"
				if h.NextArg() {
					typ = h.Val()
				}
				if h.NextArg() {
					match = h.Val()
				}
				if h.NextArg() {
					action = h.Val()
				}
				handler.WAFRules = append(handler.WAFRules, WAFRule{ID: id, Type: typ, Match: match, Action: action})
			}
		case "log_blocks":
			handler.LogBlocks = true
		case "bypass_secret":
			if h.NextArg() {
				handler.BypassSecret = h.Val()
			}
		case "bypass_secret_header":
			if h.NextArg() {
				handler.BypassSecretHeader = h.Val()
			}
		case "bypass_secret_cookie":
			if h.NextArg() {
				handler.BypassSecretCookie = h.Val()
			}
		case "allowlist_ips":
			for h.NextArg() {
				handler.AllowlistIPs = append(handler.AllowlistIPs, h.Val())
			}
		case "blocklist_file":
			if h.NextArg() {
				handler.BlocklistFile = h.Val()
			}
		case "blocklist_reload_interval":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.BlocklistReloadInterval = caddy.Duration(d)
			}
		case "honeypot_paths":
			for h.NextArg() {
				handler.HoneypotPaths = append(handler.HoneypotPaths, h.Val())
			}
		case "honeypot_block_duration":
			if h.NextArg() {
				d, _ := parseDuration(h.Val())
				handler.HoneypotDuration = caddy.Duration(d)
			}
		case "trap_paths":
			for h.NextArg() {
				handler.TrapPaths = append(handler.TrapPaths, h.Val())
			}
		case "require_user_agent":
			handler.RequireUserAgent = true
		case "bad_user_agents":
			for h.NextArg() {
				handler.BadUserAgents = append(handler.BadUserAgents, h.Val())
			}
		case "require_accept":
			handler.RequireAccept = true
		case "max_body_bytes":
			if h.NextArg() {
				handler.MaxBodyBytes, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "per_host_limit":
			if h.NextArg() {
				handler.PerHostLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "fingerprint_limit":
			if h.NextArg() {
				handler.FingerprintLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		case "max_unique_urls_per_minute":
			if h.NextArg() {
				handler.MaxUniqueURLsPerMinute, _ = strconv.ParseInt(h.Val(), 10, 64)
			}
		}
	}

	return handler, nil
}

func parseDuration(s string) (time.Duration, error) {
	return caddy.ParseDuration(s)
}
