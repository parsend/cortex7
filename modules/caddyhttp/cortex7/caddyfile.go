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
				handler.GeneralLimit, _ = strconv.ParseInt(h.Val(), 10, 64)
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
		case "js_challenge":
			handler.JSChallenge = true
			if h.NextArg() {
				handler.ChallengePath = h.Val()
			}
		case "challenge_path":
			if h.NextArg() {
				handler.ChallengePath = h.Val()
			}
		case "cookie_name":
			if h.NextArg() {
				handler.CookieName = h.Val()
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
				if h.NextArg() {
					typ = h.Val()
				}
				if h.NextArg() {
					match = h.Val()
				}
				handler.WAFRules = append(handler.WAFRules, WAFRule{ID: id, Type: typ, Match: match, Action: "block"})
			}
		}
	}

	return handler, nil
}

func parseDuration(s string) (time.Duration, error) {
	return caddy.ParseDuration(s)
}
