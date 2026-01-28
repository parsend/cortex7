// cortex7 L7 DDoS/WAF middleware, hyper-optimized for millions RPS. parsend(c0redev). github.com/parsend/cortex7

package cortex7

import (
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Handler{})
}

// Handler implements DDoS/WAF protection with in-memory store, JS challenge, cookies.
type Handler struct {
	Enabled               bool   `json:"enabled,omitempty"`
	AutoEnable            bool   `json:"auto_enable,omitempty"`
	AutoThresholdEnable   int64  `json:"auto_enable_threshold,omitempty"`
	AutoThresholdDisable  int64  `json:"auto_disable_threshold,omitempty"`

	WhitelistPaths   []string         `json:"whitelist,omitempty"`
	SensitivePaths   []string         `json:"sensitive_paths,omitempty"`
	SensitiveLimit   int64            `json:"sensitive_limit,omitempty"`
	SensitiveLimits  map[string]int64 `json:"sensitive_limits,omitempty"`
	GeneralPrefix    string           `json:"general_prefix,omitempty"`
	GeneralLimit     int64            `json:"general_limit,omitempty"`
	FailedAuthLimit  int64            `json:"failed_auth_limit,omitempty"`
	BlockDuration    caddy.Duration   `json:"block_duration,omitempty"`
	BlockDurationAuth caddy.Duration  `json:"block_duration_failed_auth,omitempty"`

	RealIPHeaderCF     string `json:"real_ip_cf_header,omitempty"`
	RealIPHeaderCustom string `json:"real_ip_custom_header,omitempty"`

	JSChallenge   bool   `json:"js_challenge,omitempty"`
	ChallengePath string `json:"challenge_path,omitempty"`
	CookieName    string `json:"cookie_name,omitempty"`
	CookieSecret  string `json:"cookie_secret,omitempty"`
	// challenge token: server-side store, unique per session, not derivable
	ChallengeTokenTTL           caddy.Duration `json:"challenge_token_ttl,omitempty"`
	ChallengeStoreResetInterval caddy.Duration `json:"challenge_store_reset_interval,omitempty"`
	// cookie options (configurable)
	CookieSecure   bool   `json:"cookie_secure,omitempty"`
	CookieSameSite string `json:"cookie_same_site,omitempty"` // Strict, Lax, None, ""
	CookiePath     string `json:"cookie_path,omitempty"`
	CookieDomain   string `json:"cookie_domain,omitempty"`
	CookieMaxAge   int    `json:"cookie_max_age,omitempty"`
	// polymorphism: random suffix per instance so scanners can't rely on fixed names
	CookieRandomSuffix        bool `json:"cookie_random_suffix,omitempty"`
	ChallengePathRandomSuffix bool `json:"challenge_path_random_suffix,omitempty"`
	// response jitter (ms) to thwart timing/bot fingerprinting; 0 = disabled
	ResponseJitterMin int `json:"response_jitter_min_ms,omitempty"`
	ResponseJitterMax int `json:"response_jitter_max_ms,omitempty"`

	BlockRefererList []string `json:"block_referer_list,omitempty"`
	CloseNoBody      bool     `json:"close_no_body,omitempty"`

	WAFRules []WAFRule `json:"waf_rules,omitempty"`

	// bypass: header or cookie value equals secret -> skip all checks
	BypassSecret       string `json:"bypass_secret,omitempty"`
	BypassSecretHeader string `json:"bypass_secret_header,omitempty"` // header name, e.g. X-C7-Bypass
	BypassSecretCookie string `json:"bypass_secret_cookie,omitempty"` // cookie name
	// allowlist IP/CIDR: skip all checks
	AllowlistIPs []string `json:"allowlist_ips,omitempty"`
	// honeypot: hit path -> block IP
	HoneypotPaths    []string        `json:"honeypot_paths,omitempty"`
	HoneypotDuration caddy.Duration  `json:"honeypot_block_duration,omitempty"`
	// trap: path contains substring -> block
	TrapPaths []string `json:"trap_paths,omitempty"`
	// bot: require UA, block bad UA list, optional require Accept
	RequireUserAgent bool     `json:"require_user_agent,omitempty"`
	BadUserAgents   []string `json:"bad_user_agents,omitempty"`
	RequireAccept   bool     `json:"require_accept_header,omitempty"`
	// max body: reject if Content-Length > N (413 or 444)
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`
	// per-host rate: key = ip:host
	PerHostLimit int64 `json:"per_host_limit,omitempty"`
	// fingerprint rate: key = hash(UA+Accept) per ip
	FingerprintLimit int64 `json:"fingerprint_limit,omitempty"`
	// unique URL throttle: scan/cache-bust
	MaxUniqueURLsPerMinute int64 `json:"max_unique_urls_per_minute,omitempty"`

	store *store
	logger *zap.Logger

	globalReqs   atomic.Int64
	lastMinute   atomic.Int64
	autoEnabled  atomic.Bool
	challengeNonce []byte

	// prebuilt for hot path, no alloc
	whitelistExact   map[string]struct{}
	whitelistPrefix  []string
	sensitiveExact   map[string]struct{}
	sensitivePrefix  []string
	sensitiveLimitMap map[string]int64
	wafPathBytes     [][]byte
	wafQueryBytes    [][]byte
	wafHeaderBytes   [][]byte
	wafRuleIdxPath   []int
	wafRuleIdxQuery  []int
	wafRuleIdxHeader []int
	generalPrefixLen int
	challengePathLen int

	allowlist     *allowlistChecker
	honeypotExact  map[string]struct{}
	honeypotPrefix []string
	trapBytes      [][]byte
	badUABytes     [][]byte
}

// WAFRule is a single WAF rule.
type WAFRule struct {
	ID     string `json:"id,omitempty"`
	Type   string `json:"type,omitempty"`
	Match  string `json:"match,omitempty"`
	Action string `json:"action,omitempty"`
}

// CaddyModule returns module info.
func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cortex7",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler and prebuilds matchers.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	if h.store == nil {
		h.store = newStore()
	}
	if h.BlockDuration == 0 {
		h.BlockDuration = caddy.Duration(10 * time.Minute)
	}
	if h.BlockDurationAuth == 0 {
		h.BlockDurationAuth = caddy.Duration(30 * time.Minute)
	}
	if h.SensitiveLimit == 0 {
		h.SensitiveLimit = 10
	}
	if h.GeneralLimit == 0 {
		h.GeneralLimit = 120
	}
	if h.FailedAuthLimit == 0 {
		h.FailedAuthLimit = 10
	}
	if h.AutoThresholdEnable == 0 {
		h.AutoThresholdEnable = 2000
	}
	if h.AutoThresholdDisable == 0 {
		h.AutoThresholdDisable = 500
	}
	if h.ChallengePath == "" {
		h.ChallengePath = "/.c7c"
	}
	if h.ChallengeTokenTTL == 0 {
		h.ChallengeTokenTTL = caddy.Duration(time.Hour)
	}
	if h.ChallengeStoreResetInterval == 0 {
		h.ChallengeStoreResetInterval = caddy.Duration(10 * time.Minute)
	}
	if h.CookieMaxAge == 0 {
		h.CookieMaxAge = 3600
	}
	// polymorphism lol
	if h.CookieRandomSuffix {
		suf := make([]byte, 4)
		crand.Read(suf)
		h.CookieName = h.CookieName + "_" + hex.EncodeToString(suf)
	}
	if h.ChallengePathRandomSuffix {
		suf := make([]byte, 4)
		crand.Read(suf)
		h.ChallengePath = h.ChallengePath + "_" + hex.EncodeToString(suf)
	}
	h.challengePathLen = len(h.ChallengePath)
	if h.CookiePath == "" {
		h.CookiePath = "/"
	}
	if h.HoneypotDuration == 0 {
		h.HoneypotDuration = h.BlockDuration
	}
	// allowlist IP/CIDR
	if len(h.AllowlistIPs) > 0 {
		var err error
		h.allowlist, err = buildAllowlist(h.AllowlistIPs)
		if err != nil {
			return err
		}
	}
	// honeypot: exact + prefix
	h.honeypotExact = make(map[string]struct{}, len(h.HoneypotPaths))
	for _, p := range h.HoneypotPaths {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") || strings.Contains(p[1:], "/") {
			h.honeypotPrefix = append(h.honeypotPrefix, p)
		} else {
			h.honeypotExact[p] = struct{}{}
		}
	}
	sort.Slice(h.honeypotPrefix, func(i, j int) bool { return len(h.honeypotPrefix[i]) > len(h.honeypotPrefix[j]) })
	// trap paths as byte slices
	for _, s := range h.TrapPaths {
		if s != "" {
			h.trapBytes = append(h.trapBytes, []byte(s))
		}
	}
	for _, s := range h.BadUserAgents {
		if s != "" {
			h.badUABytes = append(h.badUABytes, []byte(s))
		}
	}
	if h.CookieName == "" {
		h.CookieName = "_c7v"
	}
	if h.CookieSecret == "" {
		b := make([]byte, 32)
		if _, err := crand.Read(b); err != nil {
			return err
		}
		h.CookieSecret = hex.EncodeToString(b)
	}
	h.challengeNonce = make([]byte, 16)
	if _, err := crand.Read(h.challengeNonce); err != nil {
		return err
	}
	h.generalPrefixLen = len(h.GeneralPrefix)

	// prebuild whitelist: exact set + prefix slice (longest first)
	h.whitelistExact = make(map[string]struct{}, len(h.WhitelistPaths))
	for _, p := range h.WhitelistPaths {
		if strings.Contains(p, "*") {
			continue
		}
		if p == "" {
			continue
		}
		if p[len(p)-1] == '/' || strings.Contains(p[1:], "/") {
			h.whitelistPrefix = append(h.whitelistPrefix, p)
		} else {
			h.whitelistExact[p] = struct{}{}
		}
	}
	sort.Slice(h.whitelistPrefix, func(i, j int) bool { return len(h.whitelistPrefix[i]) > len(h.whitelistPrefix[j]) })

	// prebuild sensitive paths
	h.sensitiveExact = make(map[string]struct{}, len(h.SensitivePaths))
	for _, p := range h.SensitivePaths {
		if p == "" {
			continue
		}
		if strings.HasSuffix(p, "/") || strings.Contains(p[1:], "/") {
			h.sensitivePrefix = append(h.sensitivePrefix, p)
		} else {
			h.sensitiveExact[p] = struct{}{}
		}
	}
	sort.Slice(h.sensitivePrefix, func(i, j int) bool { return len(h.sensitivePrefix[i]) > len(h.sensitivePrefix[j]) })
	if h.SensitiveLimits != nil {
		h.sensitiveLimitMap = h.SensitiveLimits
	} else {
		h.sensitiveLimitMap = make(map[string]int64)
	}

	// precompile WAF rule matches as []byte and rule index
	for i := range h.WAFRules {
		m := h.WAFRules[i].Match
		if m == "" {
			continue
		}
		b := []byte(m)
		switch h.WAFRules[i].Type {
		case "path":
			h.wafPathBytes = append(h.wafPathBytes, b)
			h.wafRuleIdxPath = append(h.wafRuleIdxPath, i)
		case "query":
			h.wafQueryBytes = append(h.wafQueryBytes, b)
			h.wafRuleIdxQuery = append(h.wafRuleIdxQuery, i)
		default:
			h.wafHeaderBytes = append(h.wafHeaderBytes, b)
			h.wafRuleIdxHeader = append(h.wafRuleIdxHeader, i)
		}
	}

	// start prune loop
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			h.store.prune()
		}
	}()
	// challenge token store reset (configurable, default 10m): all cookies invalid, re-challenge
	go func() {
		iv := time.Duration(h.ChallengeStoreResetInterval)
		if iv < time.Minute {
			iv = time.Minute
		}
		t := time.NewTicker(iv)
		defer t.Stop()
		for range t.C {
			h.store.resetChallengeTokens()
		}
	}()
	return nil
}

// Validate checks config.
func (h *Handler) Validate() error {
	if h.SensitiveLimit < 1 || h.GeneralLimit < 1 {
		return fmt.Errorf("sensitive_limit and general_limit must be >= 1")
	}
	if h.JSChallenge && h.ChallengeTokenTTL < caddy.Duration(time.Second) {
		return fmt.Errorf("challenge_token_ttl must be >= 1s when js_challenge enabled")
	}
	if h.JSChallenge && h.ChallengeStoreResetInterval > 0 && h.ChallengeStoreResetInterval < caddy.Duration(time.Minute) {
		return fmt.Errorf("challenge_store_reset_interval must be >= 1m or 0 to disable")
	}
	if h.ResponseJitterMax > 0 && h.ResponseJitterMax < h.ResponseJitterMin {
		return fmt.Errorf("response_jitter_max_ms must be >= response_jitter_min_ms")
	}
	return nil
}

// ServeHTTP runs the protection chain; hot path optimized.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	enabled := h.Enabled || h.autoEnabled.Load()
	if !enabled {
		return next.ServeHTTP(w, r)
	}

	path := r.URL.Path
	pathLen := len(path)

	// bypass: secret in header or cookie
	if h.BypassSecret != "" {
		if h.BypassSecretHeader != "" && r.Header.Get(h.BypassSecretHeader) == h.BypassSecret {
			return next.ServeHTTP(w, r)
		}
		if h.BypassSecretCookie != "" {
			if c, _ := r.Cookie(h.BypassSecretCookie); c != nil && c.Value == h.BypassSecret {
				return next.ServeHTTP(w, r)
			}
		}
	}

	// tick global counter, get current minute bucket (one time.Now() for both)
	now := time.Now()
	bucketMin := now.Unix() / 60
	lm := h.lastMinute.Load()
	if lm != bucketMin {
		if h.lastMinute.CompareAndSwap(lm, bucketMin) && lm != 0 {
			c := h.globalReqs.Swap(0)
			if h.AutoEnable {
				if !h.Enabled && !h.autoEnabled.Load() && c >= h.AutoThresholdEnable {
					h.autoEnabled.Store(true)
				}
				if h.autoEnabled.Load() && c < h.AutoThresholdDisable {
					h.autoEnabled.Store(false)
				}
			}
		}
	}
	h.globalReqs.Add(1)

	// whitelist: exact then prefix
	if _, ok := h.whitelistExact[path]; ok {
		return next.ServeHTTP(w, r)
	}
	for _, p := range h.whitelistPrefix {
		if pathLen >= len(p) && path[:len(p)] == p {
			return next.ServeHTTP(w, r)
		}
	}

	// realIP once
	ip := h.realIP(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	if ip != "" {
		ip = trimIPv4Mapping(ip)
	}
	if ip == "" || !isValidIP(ip) {
		return next.ServeHTTP(w, r)
	}

	// allowlist IP/CIDR: skip all checks
	if h.allowlist != nil && h.allowlist.contains(ip) {
		return next.ServeHTTP(w, r)
	}

	if ok, _ := h.store.isBlocked(ip); ok {
		h.reject(w, r)
		return nil
	}

	// trap paths: path contains substring -> block IP
	for _, b := range h.trapBytes {
		if indexBytes(*(*[]byte)(unsafe.Pointer(&path)), b) >= 0 {
			h.store.block(ip, "trap_path", time.Duration(h.HoneypotDuration))
			h.reject(w, r)
			return nil
		}
	}

	// max body
	if h.MaxBodyBytes > 0 && r.ContentLength > h.MaxBodyBytes {
		h.reject(w, r)
		return nil
	}

	if len(h.BlockRefererList) > 0 {
		ref := r.Header.Get("Referer")
		for _, block := range h.BlockRefererList {
			if strings.Contains(ref, block) {
				h.reject(w, r)
				return nil
			}
		}
	}

	// WAF: precompiled byte contains
	pathB := *(*[]byte)(unsafe.Pointer(&path))
	for i, b := range h.wafPathBytes {
		if indexBytes(pathB, b) >= 0 {
			h.store.block(ip, "waf:"+h.WAFRules[h.wafRuleIdxPath[i]].ID, time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}
	query := r.URL.RawQuery
	queryB := *(*[]byte)(unsafe.Pointer(&query))
	for i, b := range h.wafQueryBytes {
		if indexBytes(queryB, b) >= 0 {
			h.store.block(ip, "waf:"+h.WAFRules[h.wafRuleIdxQuery[i]].ID, time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}
	for i, b := range h.wafHeaderBytes {
		if wafHeaderContains(r, b) {
			h.store.block(ip, "waf:"+h.WAFRules[h.wafRuleIdxHeader[i]].ID, time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}

	// bot checks: require UA, block bad UA, require Accept
	if h.RequireUserAgent && r.UserAgent() == "" {
		h.reject(w, r)
		return nil
	}
	ua := r.UserAgent()
	uaB := *(*[]byte)(unsafe.Pointer(&ua))
	for _, b := range h.badUABytes {
		if indexBytes(uaB, b) >= 0 {
			h.store.block(ip, "bad_user_agent", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}
	if h.RequireAccept && r.Header.Get("Accept") == "" {
		h.reject(w, r)
		return nil
	}

	// honeypot: hit path -> block IP
	if _, ok := h.honeypotExact[path]; ok {
		h.store.block(ip, "honeypot", time.Duration(h.HoneypotDuration))
		h.reject(w, r)
		return nil
	}
	for _, p := range h.honeypotPrefix {
		if pathLen >= len(p) && path[:len(p)] == p {
			h.store.block(ip, "honeypot", time.Duration(h.HoneypotDuration))
			h.reject(w, r)
			return nil
		}
	}

	if h.JSChallenge && h.ChallengePath != "" {
		if pathLen == h.challengePathLen && path == h.ChallengePath {
			return h.serveChallenge(w, r, next)
		}
		cookie, _ := r.Cookie(h.CookieName)
		if !h.verifyChallengeCookie(cookie, ip) {
			return h.serveChallengePage(w, r)
		}
	}

	// sensitive path: exact then prefix, single inc per request
	limit := h.SensitiveLimit
	if _, ok := h.sensitiveExact[path]; ok {
		if l, ok := h.sensitiveLimitMap[path]; ok {
			limit = l
		}
		n := h.store.incReqPath(ip, path, bucketMin)
		if n > limit {
			h.store.block(ip, "rate_limit_sensitive", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	} else {
		for _, p := range h.sensitivePrefix {
			if pathLen >= len(p) && path[:len(p)] == p {
				if l, ok := h.sensitiveLimitMap[path]; ok {
					limit = l
				}
				n := h.store.incReqPath(ip, path, bucketMin)
				if n > limit {
					h.store.block(ip, "rate_limit_sensitive", time.Duration(h.BlockDuration))
					h.reject(w, r)
					return nil
				}
				break
			}
		}
	}

	// per-host rate limit
	if h.PerHostLimit > 0 {
		hostKey := ip + ":" + r.Host
		n := h.store.incReqKey(hostKey, bucketMin)
		if n > h.PerHostLimit {
			h.store.block(ip, "rate_limit_per_host", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}

	// fingerprint rate limit (same UA+Accept pattern per IP)
	if h.FingerprintLimit > 0 {
		accept := r.Header.Get("Accept")
		fpKey := ip + ":" + fmt.Sprintf("%016x", hashPathQuery(ua+accept))
		n := h.store.incReqKey(fpKey, bucketMin)
		if n > h.FingerprintLimit {
			h.store.block(ip, "rate_limit_fingerprint", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}

	// unique URL throttle (scan/cache-bust)
	if h.MaxUniqueURLsPerMinute > 0 {
		pathQuery := path
		if r.URL.RawQuery != "" {
			pathQuery = path + "?" + r.URL.RawQuery
		}
		n := h.store.addUniqueURL(ip, pathQuery, bucketMin)
		if n > h.MaxUniqueURLsPerMinute {
			h.store.block(ip, "rate_limit_unique_url", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}

	// general rate limit
	useGeneral := h.generalPrefixLen == 0 || (pathLen >= h.generalPrefixLen && path[:h.generalPrefixLen] == h.GeneralPrefix)
	if useGeneral {
		n := h.store.incReq(ip, bucketMin)
		if n > h.GeneralLimit {
			h.store.block(ip, "rate_limit_general", time.Duration(h.BlockDuration))
			h.reject(w, r)
			return nil
		}
	}

	return next.ServeHTTP(w, r)
}

func indexBytes(s, sep []byte) int {
	if len(sep) == 0 || len(sep) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i] == sep[0] {
			j := 1
			for j < len(sep) && s[i+j] == sep[j] {
				j++
			}
			if j == len(sep) {
				return i
			}
		}
	}
	return -1
}

func wafHeaderContains(r *http.Request, needle []byte) bool {
	for _, v := range r.Header {
		for _, vv := range v {
			if indexBytes(*(*[]byte)(unsafe.Pointer(&vv)), needle) >= 0 {
				return true
			}
		}
	}
	return false
}

func (h *Handler) realIP(r *http.Request) string {
	return realIPFromHeaders(h.RealIPHeaderCF, h.RealIPHeaderCustom, "X-Forwarded-For", r.Header.Get)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request) {
	h.responseJitter()
	r.Close = true
	w.Header().Set("Connection", "close")
	w.WriteHeader(444)
}

// responseJitter adds random delay to thwart timing/bot fingerprinting
func (h *Handler) responseJitter() {
	min, max := h.ResponseJitterMin, h.ResponseJitterMax
	if min <= 0 || max < min {
		return
	}
	ms := min
	if max > min {
		ms = min + rand.Intn(max-min+1)
	}
	if ms > 0 {
		time.Sleep(time.Duration(ms) * time.Millisecond)
	}
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	urlToken := r.URL.Query().Get("t")
	ip := h.realIP(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ip = trimIPv4Mapping(ip)
	if urlToken == "" {
		return h.serveChallengePage(w, r)
	}
	// URL token derived from IP+nonce+secret so only real browser from this IP gets valid link
	expectedURL := h.challengeToken(ip)
	if !subtleCompare(urlToken, expectedURL) {
		h.reject(w, r)
		return nil
	}
	// issue unique session token (not derivable), store server-side, bind to IP
	raw := make([]byte, 32)
	if _, err := crand.Read(raw); err != nil {
		h.reject(w, r)
		return nil
	}
	sessionToken := hex.EncodeToString(raw)
	until := time.Now().Add(time.Duration(h.ChallengeTokenTTL)).UnixNano()
	h.store.setChallengeToken(sessionToken, ip, until)
	cookie := h.buildChallengeCookie(sessionToken, r)
	http.SetCookie(w, cookie)
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
	return nil
}

// challengeToken derives URL param token (IP+nonce+secret) so only real browser gets valid link
func (h *Handler) challengeToken(ip string) string {
	s := fmt.Sprintf("%s:%x:%s", ip, h.challengeNonce, h.CookieSecret)
	sum := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(sum[:])[:32]
}

// verifyChallengeCookie checks cookie against server-side store: token exists, IP match, not expired
func (h *Handler) verifyChallengeCookie(c *http.Cookie, ip string) bool {
	if c == nil || c.Value == "" {
		return false
	}
	return h.store.validateChallengeToken(c.Value, ip, time.Now().UnixNano())
}

func (h *Handler) buildChallengeCookie(value string, r *http.Request) *http.Cookie {
	secure := h.CookieSecure || r.TLS != nil
	sameSite := http.SameSiteLaxMode
	switch strings.ToLower(h.CookieSameSite) {
	case "strict":
		sameSite = http.SameSiteStrictMode
	case "none":
		sameSite = http.SameSiteNoneMode
	}
	return &http.Cookie{
		Name:     h.CookieName,
		Value:    value,
		Path:     h.CookiePath,
		Domain:   h.CookieDomain,
		MaxAge:   h.CookieMaxAge,
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	}
}

func subtleCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff uint8
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (h *Handler) serveChallengePage(w http.ResponseWriter, r *http.Request) error {
	h.responseJitter()
	ip := h.realIP(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ip = trimIPv4Mapping(ip)
	token := h.challengeToken(ip)
	dest := h.ChallengePath + "?t=" + token
	nonce := base64.StdEncoding.EncodeToString(h.challengeNonce)
	page := fmt.Sprintf(`<!DOCTYPE html><html><head><meta charset="utf-8"/><meta http-equiv="refresh" content="0;url=%s"/></head><body><script>document.location="%s";</script><noscript><a href="%s">Continue</a></noscript></body></html>`,
		dest, dest, dest)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-C7-Nonce", nonce)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(page))
	return nil
}

// TrackFailedAuth is called when auth fails.
func (h *Handler) TrackFailedAuth(ip string) {
	if h.store == nil {
		return
	}
	bucketAuth := time.Now().Truncate(15 * time.Minute).Unix()
	n := h.store.incFailedAuth(ip, bucketAuth)
	if n > h.FailedAuthLimit {
		h.store.block(ip, "too_many_failed_auth", time.Duration(h.BlockDurationAuth))
	}
}

var _ caddyhttp.MiddlewareHandler = (*Handler)(nil)

// Cortex7CtxKey is the context key for cortex7 handler.
type Cortex7CtxKey struct{}

// HandlerFromContext returns the cortex7 Handler from context if present.
func HandlerFromContext(ctx context.Context) *Handler {
	v := ctx.Value(Cortex7CtxKey{})
	if v == nil {
		return nil
	}
	h, _ := v.(*Handler)
	return h
}
