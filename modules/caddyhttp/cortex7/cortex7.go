// cortex7 L7 DDoS/WAF middleware, hyper-optimized for millions RPS. parsend(c0redev). github.com/parsend/cortex7

package cortex7

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
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

	BlockRefererList []string `json:"block_referer_list,omitempty"`
	CloseNoBody      bool     `json:"close_no_body,omitempty"`

	WAFRules []WAFRule `json:"waf_rules,omitempty"`

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
	h.challengePathLen = len(h.ChallengePath)
	if h.CookieName == "" {
		h.CookieName = "_c7v"
	}
	if h.CookieSecret == "" {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		h.CookieSecret = hex.EncodeToString(b)
	}
	h.challengeNonce = make([]byte, 16)
	if _, err := rand.Read(h.challengeNonce); err != nil {
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
	return nil
}

// Validate checks config.
func (h *Handler) Validate() error {
	if h.SensitiveLimit < 1 || h.GeneralLimit < 1 {
		return fmt.Errorf("sensitive_limit and general_limit must be >= 1")
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

	if ok, _ := h.store.isBlocked(ip); ok {
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
	r.Close = true
	w.Header().Set("Connection", "close")
	w.WriteHeader(444)
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	token := r.URL.Query().Get("t")
	ip := h.realIP(r)
	if ip == "" {
		ip, _, _ = net.SplitHostPort(r.RemoteAddr)
	}
	ip = trimIPv4Mapping(ip)
	if token == "" {
		return h.serveChallengePage(w, r)
	}
	expected := h.challengeToken(ip)
	if subtleCompare(token, expected) {
		cookie := &http.Cookie{
			Name:     h.CookieName,
			Value:    expected,
			Path:     "/",
			MaxAge:   3600,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusFound)
		return nil
	}
	h.reject(w, r)
	return nil
}

func (h *Handler) challengeToken(ip string) string {
	s := fmt.Sprintf("%s:%x:%s", ip, h.challengeNonce, h.CookieSecret)
	sum := sha256.Sum256([]byte(s))
	return base64.URLEncoding.EncodeToString(sum[:])[:32]
}

func (h *Handler) verifyChallengeCookie(c *http.Cookie, ip string) bool {
	if c == nil {
		return false
	}
	return subtleCompare(c.Value, h.challengeToken(ip))
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
