package cortex7

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
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
	GeneralLimit     *int64           `json:"general_limit,omitempty"`
	RateLimitWindow  caddy.Duration   `json:"rate_limit_window,omitempty"`
	FailedAuthLimit  int64            `json:"failed_auth_limit,omitempty"`
	BlockDuration    caddy.Duration   `json:"block_duration,omitempty"`
	BlockDurationAuth caddy.Duration  `json:"block_duration_failed_auth,omitempty"`

	RealIPHeaderCF     string `json:"real_ip_cf_header,omitempty"`
	RealIPHeaderCustom string `json:"real_ip_custom_header,omitempty"`
	RealIPXFFMode      string `json:"real_ip_xff_mode,omitempty"`

	JSChallenge   bool   `json:"js_challenge,omitempty"`
	ChallengePath string `json:"challenge_path,omitempty"`
	CookieName    string `json:"cookie_name,omitempty"`
	CookieSecret  string `json:"cookie_secret,omitempty"`
	ChallengeTokenTTL           caddy.Duration `json:"challenge_token_ttl,omitempty"`
	ChallengeStoreResetInterval caddy.Duration `json:"challenge_store_reset_interval,omitempty"`
	ChallengePathLimit          int64         `json:"challenge_path_limit,omitempty"`
	ChallengeStoreMaxSize       int64         `json:"challenge_store_max_size,omitempty"`
	CookieSecure   bool   `json:"cookie_secure,omitempty"`
	CookieSameSite string `json:"cookie_same_site,omitempty"`
	CookiePath     string `json:"cookie_path,omitempty"`
	CookieDomain   string `json:"cookie_domain,omitempty"`
	CookieMaxAge   int    `json:"cookie_max_age,omitempty"`
	CookieRandomSuffix        bool `json:"cookie_random_suffix,omitempty"`
	ChallengePathRandomSuffix bool `json:"challenge_path_random_suffix,omitempty"`
	NoCookieReject bool `json:"no_cookie_reject,omitempty"`
	ResponseJitterMin int `json:"response_jitter_min_ms,omitempty"`
	ResponseJitterMax int `json:"response_jitter_max_ms,omitempty"`

	BlockRefererList []string `json:"block_referer_list,omitempty"`
	CloseNoBody      bool     `json:"close_no_body,omitempty"`
	RejectStatusCode   int `json:"reject_status_code,omitempty"`
	MaxBodyRejectCode  int `json:"max_body_reject_code,omitempty"`
	RejectRedirectURL string `json:"reject_redirect_url,omitempty"`
	RejectBody       string `json:"reject_body,omitempty"`
	LogBlocks        bool   `json:"log_blocks,omitempty"`

	WAFRules []WAFRule `json:"waf_rules,omitempty"`

	BypassSecret       string `json:"bypass_secret,omitempty"`
	BypassSecretHeader string `json:"bypass_secret_header,omitempty"`
	BypassSecretCookie string `json:"bypass_secret_cookie,omitempty"`
	AllowlistIPs []string `json:"allowlist_ips,omitempty"`
	BlocklistFile           string        `json:"blocklist_file,omitempty"`
	BlocklistReloadInterval caddy.Duration `json:"blocklist_reload_interval,omitempty"`
	HoneypotPaths    []string        `json:"honeypot_paths,omitempty"`
	HoneypotDuration caddy.Duration  `json:"honeypot_block_duration,omitempty"`
	TrapPaths []string `json:"trap_paths,omitempty"`
	RequireUserAgent bool     `json:"require_user_agent,omitempty"`
	BadUserAgents   []string `json:"bad_user_agents,omitempty"`
	RequireAccept   bool     `json:"require_accept_header,omitempty"`
	MaxBodyBytes int64 `json:"max_body_bytes,omitempty"`
	PerHostLimit int64 `json:"per_host_limit,omitempty"`
	FingerprintLimit int64 `json:"fingerprint_limit,omitempty"`
	MaxUniqueURLsPerMinute int64 `json:"max_unique_urls_per_minute,omitempty"`
	BurstLimit  int64         `json:"burst_limit,omitempty"`
	BurstWindow caddy.Duration `json:"burst_window,omitempty"`

	store *store
	logger *zap.Logger

	globalReqs   atomic.Int64
	lastMinute   atomic.Int64
	autoEnabled  atomic.Bool

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
	burstWindowDur   time.Duration

	allowlist     *allowlistChecker
	blocklist     atomic.Pointer[allowlistChecker]
	honeypotExact  map[string]struct{}
	honeypotPrefix []string
	trapBytes      [][]byte
	badUABytes     [][]byte
	rejectBodyBytes []byte
}

type WAFRule struct {
	ID     string `json:"id,omitempty"`
	Type   string `json:"type,omitempty"`
	Match  string `json:"match,omitempty"`
	Action string `json:"action,omitempty"`
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.cortex7",
		New: func() caddy.Module { return new(Handler) },
	}
}

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
	if h.GeneralLimit == nil {
		var v int64 = 120
		h.GeneralLimit = &v
	}
	if h.RejectStatusCode == 0 {
		h.RejectStatusCode = 444
	}
	if h.MaxBodyRejectCode == 0 {
		h.MaxBodyRejectCode = 413
	}
	if h.RateLimitWindow == 0 {
		h.RateLimitWindow = caddy.Duration(time.Minute)
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
	if h.BurstWindow == 0 {
		h.BurstWindow = caddy.Duration(10 * time.Second)
	}
	h.burstWindowDur = time.Duration(h.BurstWindow)
	if h.burstWindowDur < time.Second {
		h.burstWindowDur = 10 * time.Second
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
	if h.RejectBody != "" {
		if strings.Contains(h.RejectBody, "<") {
			h.rejectBodyBytes = []byte(h.RejectBody)
		} else {
			b, err := os.ReadFile(h.RejectBody)
			if err == nil {
				h.rejectBodyBytes = b
			}
		}
	}
	if h.HoneypotDuration == 0 {
		h.HoneypotDuration = h.BlockDuration
	}
	if len(h.AllowlistIPs) > 0 {
		var err error
		h.allowlist, err = buildAllowlist(h.AllowlistIPs)
		if err != nil {
			return err
		}
	}
	if h.BlocklistFile != "" {
		bl, err := loadBlocklistFromFile(h.BlocklistFile)
		if err != nil {
			h.logger.Warn("blocklist file load failed, skipping", zap.String("file", h.BlocklistFile), zap.Error(err))
		} else {
			h.blocklist.Store(bl)
		}
		if h.BlocklistReloadInterval > 0 {
			iv := time.Duration(h.BlocklistReloadInterval)
			if iv < time.Minute {
				iv = time.Minute
			}
			path := h.BlocklistFile
			go func() {
				t := time.NewTicker(iv)
				defer t.Stop()
				for range t.C {
					bl, err := loadBlocklistFromFile(path)
					if err != nil {
						continue
					}
					h.blocklist.Store(bl)
				}
			}()
		}
	}
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
		h.CookieName = "v"
	}
	if h.CookieSecret == "" {
		b := make([]byte, 32)
		if _, err := crand.Read(b); err != nil {
			return err
		}
		h.CookieSecret = hex.EncodeToString(b)
	}
	h.generalPrefixLen = len(h.GeneralPrefix)

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

	pruneWindow := time.Duration(h.RateLimitWindow)
	if pruneWindow < time.Second {
		pruneWindow = time.Minute
	}
	go func() {
		t := time.NewTicker(2 * time.Minute)
		defer t.Stop()
		for range t.C {
			h.store.prune(pruneWindow, h.burstWindowDur)
		}
	}()
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

func (h *Handler) Validate() error {
	if h.SensitiveLimit < 1 {
		return fmt.Errorf("sensitive_limit must be >= 1")
	}
	if h.GeneralLimit != nil && *h.GeneralLimit < 0 {
		return fmt.Errorf("general_limit must be >= 0 (0 = disable)")
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

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	enabled := h.Enabled || h.autoEnabled.Load()
	if !enabled {
		return next.ServeHTTP(w, r)
	}

	path := r.URL.Path
	pathLen := len(path)

	if h.BypassSecret != "" {
		if h.BypassSecretHeader != "" {
			if subtleCompare(r.Header.Get(h.BypassSecretHeader), h.BypassSecret) {
				return next.ServeHTTP(w, r)
			}
		}
		if h.BypassSecretCookie != "" {
			if c, _ := r.Cookie(h.BypassSecretCookie); c != nil && subtleCompare(c.Value, h.BypassSecret) {
				return next.ServeHTTP(w, r)
			}
		}
	}

	now := time.Now()
	minuteBucket := now.Unix() / 60
	window := time.Duration(h.RateLimitWindow)
	if window < time.Second {
		window = time.Minute
	}
	bucketMin := now.Truncate(window).Unix()
	lm := h.lastMinute.Load()
	if lm != minuteBucket {
		if h.lastMinute.CompareAndSwap(lm, minuteBucket) && lm != 0 {
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

	if _, ok := h.whitelistExact[path]; ok {
		return next.ServeHTTP(w, r)
	}
	for _, p := range h.whitelistPrefix {
		if pathLen >= len(p) && path[:len(p)] == p {
			return next.ServeHTTP(w, r)
		}
	}

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

	if h.allowlist != nil && h.allowlist.contains(ip) {
		return next.ServeHTTP(w, r)
	}

	if ok, _ := h.store.isBlocked(ip); ok {
		h.rejectWithReason(w, r, "blocked")
		return nil
	}
	if bl := h.blocklist.Load(); bl != nil && bl.contains(ip) {
		h.rejectWithReason(w, r, "blocklist")
		return nil
	}

	if h.BurstLimit > 0 {
		bucketBurst := now.Truncate(h.burstWindowDur).Unix()
		n := h.store.incReqBurst(ip, bucketBurst)
		if n > h.BurstLimit {
			h.store.block(ip, "burst", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "burst")
			return nil
		}
	}

	for _, b := range h.trapBytes {
		if indexBytes(*(*[]byte)(unsafe.Pointer(&path)), b) >= 0 {
			h.store.block(ip, "trap_path", time.Duration(h.HoneypotDuration))
			h.rejectWithReason(w, r, "trap_path")
			return nil
		}
	}

	if h.MaxBodyBytes > 0 && r.ContentLength > h.MaxBodyBytes {
		h.rejectWithCode(w, r, h.maxBodyRejectCode(), "max_body")
		return nil
	}

	if len(h.BlockRefererList) > 0 {
		ref := r.Header.Get("Referer")
		for _, block := range h.BlockRefererList {
			if strings.Contains(ref, block) {
				h.rejectWithReason(w, r, "block_referer")
				return nil
			}
		}
	}

	pathB := *(*[]byte)(unsafe.Pointer(&path))
	for i, b := range h.wafPathBytes {
		if indexBytes(pathB, b) >= 0 {
			rule := h.WAFRules[h.wafRuleIdxPath[i]]
			if strings.EqualFold(rule.Action, "challenge") {
				cookie, _ := r.Cookie(h.CookieName)
				if h.verifyChallengeCookie(cookie, ip) {
					continue
				}
				if h.NoCookieReject {
					h.rejectWithReason(w, r, "waf_challenge_no_cookie")
					return nil
				}
				return h.serveChallengePage(w, r)
			}
			h.store.block(ip, "waf:"+rule.ID, time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "waf:"+rule.ID)
			return nil
		}
	}
	query := r.URL.RawQuery
	queryB := *(*[]byte)(unsafe.Pointer(&query))
	for i, b := range h.wafQueryBytes {
		if indexBytes(queryB, b) >= 0 {
			rule := h.WAFRules[h.wafRuleIdxQuery[i]]
			if strings.EqualFold(rule.Action, "challenge") {
				cookie, _ := r.Cookie(h.CookieName)
				if h.verifyChallengeCookie(cookie, ip) {
					continue
				}
				if h.NoCookieReject {
					h.rejectWithReason(w, r, "waf_challenge_no_cookie")
					return nil
				}
				return h.serveChallengePage(w, r)
			}
			h.store.block(ip, "waf:"+rule.ID, time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "waf:"+rule.ID)
			return nil
		}
	}
	for i, b := range h.wafHeaderBytes {
		if wafHeaderContains(r, b) {
			rule := h.WAFRules[h.wafRuleIdxHeader[i]]
			if strings.EqualFold(rule.Action, "challenge") {
				cookie, _ := r.Cookie(h.CookieName)
				if h.verifyChallengeCookie(cookie, ip) {
					continue
				}
				if h.NoCookieReject {
					h.rejectWithReason(w, r, "waf_challenge_no_cookie")
					return nil
				}
				return h.serveChallengePage(w, r)
			}
			h.store.block(ip, "waf:"+rule.ID, time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "waf:"+rule.ID)
			return nil
		}
	}

	if h.RequireUserAgent && r.UserAgent() == "" {
		h.rejectWithReason(w, r, "no_user_agent")
		return nil
	}
	ua := r.UserAgent()
	uaB := *(*[]byte)(unsafe.Pointer(&ua))
	for _, b := range h.badUABytes {
		if indexBytes(uaB, b) >= 0 {
			h.store.block(ip, "bad_user_agent", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "bad_user_agent")
			return nil
		}
	}
	if h.RequireAccept && r.Header.Get("Accept") == "" {
		h.rejectWithReason(w, r, "no_accept")
		return nil
	}

	if _, ok := h.honeypotExact[path]; ok {
		h.store.block(ip, "honeypot", time.Duration(h.HoneypotDuration))
		h.rejectWithReason(w, r, "honeypot")
		return nil
	}
	for _, p := range h.honeypotPrefix {
		if pathLen >= len(p) && path[:len(p)] == p {
			h.store.block(ip, "honeypot", time.Duration(h.HoneypotDuration))
			h.rejectWithReason(w, r, "honeypot")
			return nil
		}
	}

	if h.JSChallenge && h.ChallengePath != "" {
		if pathLen == h.challengePathLen && path == h.ChallengePath {
			if h.ChallengePathLimit > 0 {
				chKey := "challenge:" + ip
				n := h.store.incReqKey(chKey, bucketMin)
				if n > h.ChallengePathLimit {
					h.rejectWithReason(w, r, "challenge_path_limit")
					return nil
				}
			}
			return h.serveChallenge(w, r, next)
		}
		cookie, _ := r.Cookie(h.CookieName)
		if !h.verifyChallengeCookie(cookie, ip) {
			if h.NoCookieReject {
				h.rejectWithReason(w, r, "no_challenge_cookie")
				return nil
			}
			return h.serveChallengePage(w, r)
		}
	}

	limit := h.SensitiveLimit
	if _, ok := h.sensitiveExact[path]; ok {
		if l, ok := h.sensitiveLimitMap[path]; ok {
			limit = l
		}
		n := h.store.incReqPath(ip, path, bucketMin)
		if n > limit {
			h.store.block(ip, "rate_limit_sensitive", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "rate_limit_sensitive")
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
					h.rejectWithReason(w, r, "rate_limit_sensitive")
					return nil
				}
				break
			}
		}
	}

	if h.PerHostLimit > 0 {
		hostKey := ip + ":" + r.Host
		n := h.store.incReqKey(hostKey, bucketMin)
		if n > h.PerHostLimit {
			h.store.block(ip, "rate_limit_per_host", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "rate_limit_per_host")
			return nil
		}
	}

	if h.FingerprintLimit > 0 {
		accept := r.Header.Get("Accept")
		fpKey := ip + ":" + fmt.Sprintf("%016x", hashPathQuery(ua+accept))
		n := h.store.incReqKey(fpKey, bucketMin)
		if n > h.FingerprintLimit {
			h.store.block(ip, "rate_limit_fingerprint", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "rate_limit_fingerprint")
			return nil
		}
	}

	if h.MaxUniqueURLsPerMinute > 0 {
		pathQuery := path
		if r.URL.RawQuery != "" {
			pathQuery = path + "?" + r.URL.RawQuery
		}
		n := h.store.addUniqueURL(ip, pathQuery, bucketMin)
		if n > h.MaxUniqueURLsPerMinute {
			h.store.block(ip, "rate_limit_unique_url", time.Duration(h.BlockDuration))
			h.rejectWithReason(w, r, "rate_limit_unique_url")
			return nil
		}
	}

	if gl := h.getGeneralLimit(); gl > 0 {
		useGeneral := h.generalPrefixLen == 0 || (pathLen >= h.generalPrefixLen && path[:h.generalPrefixLen] == h.GeneralPrefix)
		if useGeneral {
			n := h.store.incReq(ip, bucketMin)
			if n > gl {
				h.store.block(ip, "rate_limit_general", time.Duration(h.BlockDuration))
				h.rejectWithReason(w, r, "rate_limit_general")
				return nil
			}
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
	xffLast := strings.EqualFold(h.RealIPXFFMode, "last")
	return realIPFromHeaders(h.RealIPHeaderCF, h.RealIPHeaderCustom, "X-Forwarded-For", xffLast, r.Header.Get)
}

func (h *Handler) reject(w http.ResponseWriter, r *http.Request) {
	h.rejectWithReason(w, r, "")
}

func (h *Handler) rejectWithReason(w http.ResponseWriter, r *http.Request, reason string) {
	h.rejectWithCode(w, r, h.rejectStatusCode(), reason)
}

func (h *Handler) rejectWithCode(w http.ResponseWriter, r *http.Request, code int, reason string) {
	if h.LogBlocks && reason != "" {
		h.logBlock(r, reason)
	}
	if reason != "blocked" && reason != "blocklist" {
		h.responseJitter()
	}
	if code <= 0 {
		code = 444
	}
	if h.RejectRedirectURL != "" {
		w.Header().Set("Location", h.RejectRedirectURL)
		w.WriteHeader(http.StatusFound)
		return
	}
	if len(h.rejectBodyBytes) > 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(code)
		_, _ = w.Write(h.rejectBodyBytes)
		return
	}
	r.Close = true
	w.Header().Set("Connection", "close")
	w.WriteHeader(code)
}

func (h *Handler) logBlock(r *http.Request, reason string) {
	ip := h.realIP(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ip = trimIPv4Mapping(ip)
	h.logger.Info("cortex7 block", zap.String("reason", reason), zap.String("ip", ip), zap.String("path", r.URL.Path), zap.String("method", r.Method))
}

func (h *Handler) rejectStatusCode() int {
	if h.RejectStatusCode <= 0 {
		return 444
	}
	return h.RejectStatusCode
}

func (h *Handler) maxBodyRejectCode() int {
	if h.MaxBodyRejectCode <= 0 {
		return 413
	}
	return h.MaxBodyRejectCode
}

func (h *Handler) getGeneralLimit() int64 {
	if h.GeneralLimit == nil {
		return 120
	}
	return *h.GeneralLimit
}

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
	now := time.Now().UnixNano()
	if !h.store.consumePageToken(urlToken, ip, now) {
		return h.serveChallengePage(w, r)
	}
	raw := make([]byte, 32)
	if _, err := crand.Read(raw); err != nil {
		h.reject(w, r)
		return nil
	}
	sessionToken := hex.EncodeToString(raw)
	until := time.Now().Add(time.Duration(h.ChallengeTokenTTL)).UnixNano()
	if !h.store.setChallengeToken(sessionToken, ip, until, h.ChallengeStoreMaxSize) {
		h.rejectWithReason(w, r, "challenge_store_full")
		return nil
	}
	cookie := h.buildChallengeCookie(sessionToken, r)
	http.SetCookie(w, cookie)
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusFound)
	return nil
}

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
 	raw := make([]byte, 24)
	if _, err := crand.Read(raw); err != nil {
		h.reject(w, r)
		return nil
	}
	pageTok := hex.EncodeToString(raw)
	now := time.Now()
	until := now.Add(2 * time.Minute).UnixNano()
	issuedAt := now.UnixNano()
	h.store.setPageToken(pageTok, ip, until, issuedAt)
	path := h.ChallengePath
	tokB64 := base64.StdEncoding.EncodeToString([]byte(pageTok))
	page := h.challengePageHTML(path, tokB64)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page)
	return nil
}

func (h *Handler) challengePageHTML(path, tokB64 string) []byte {
	const tpl = `<!DOCTYPE html><html><head><meta charset="utf-8"/><title></title></head><body><div id="q" data-r="%s"></div><script>
(function(){var d=document.getElementById("q");if(!d)return;var r=d.getAttribute("data-r");if(!r)return;
try{var s=atob(r);if(!s)return;}catch(e){return;}
if(typeof navigator!="undefined"&&navigator.webdriver===true)return;
var t=1500+Math.floor(Math.random()*1500);setTimeout(function(){try{location.replace("%s?t="+encodeURIComponent(s));}catch(e){}},t);
})();</script><noscript><p>Enable JavaScript to continue.</p></noscript></body></html>`
	pathEsc := strings.ReplaceAll(path, `\`, `\\`)
	pathEsc = strings.ReplaceAll(pathEsc, `"`, `\"`)
	return []byte(fmt.Sprintf(tpl, tokB64, pathEsc))
}

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

type Cortex7CtxKey struct{}

func HandlerFromContext(ctx context.Context) *Handler {
	v := ctx.Value(Cortex7CtxKey{})
	if v == nil {
		return nil
	}
	h, _ := v.(*Handler)
	return h
}
