// cortex7 in-memory store, sharded for millions RPS. parsend(c0redev)

package cortex7

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	windowMinute = time.Minute
	windowAuth   = 15 * time.Minute
	shardCount   = 256
)

type blockEntry struct {
	until  int64  // unix nano
	reason string
}

type windowCount struct {
	count int64
	until int64
}

type uniqueURLWindow struct {
	until int64
	urls  map[uint64]struct{}
}

// challengeEntry binds issued token to IP and expiry (server-side, not derivable)
type challengeEntry struct {
	ip   string
	until int64
}

type shard struct {
	mu               sync.RWMutex
	blocked          map[string]blockEntry
	reqCount         map[string]*windowCount
	reqBurst         map[string]*windowCount   // ip -> count in short window (anti-flood)
	reqByPath        map[string]map[string]*windowCount
	reqByKey         map[string]*windowCount   // per-host, fingerprint
	failedAuth       map[string]*windowCount
	uniqueURLs       map[string]*uniqueURLWindow
	challengeTokens  map[string]challengeEntry
}

func newShard() *shard {
	return &shard{
		blocked:         make(map[string]blockEntry, 64),
		reqCount:        make(map[string]*windowCount, 256),
		reqBurst:        make(map[string]*windowCount, 256),
		reqByPath:       make(map[string]map[string]*windowCount, 64),
		reqByKey:        make(map[string]*windowCount, 128),
		failedAuth:      make(map[string]*windowCount, 64),
		uniqueURLs:      make(map[string]*uniqueURLWindow, 64),
		challengeTokens: make(map[string]challengeEntry, 128),
	}
}

type store struct {
	shards             [shardCount]*shard
	challengeTokenCount atomic.Int64
}

func newStore() *store {
	s := &store{}
	for i := 0; i < shardCount; i++ {
		s.shards[i] = newShard()
	}
	return s
}

// hashIP returns shard index 0..shardCount-1. no alloc.
func hashIP(ip string) uint32 {
	var h uint32
	for i := 0; i < len(ip); i++ {
		h = h*31 + uint32(ip[i])
	}
	return h % shardCount
}

func (s *store) shard(ip string) *shard {
	return s.shards[hashIP(ip)]
}

func hashKey(key string) uint32 {
	var h uint32
	for i := 0; i < len(key); i++ {
		h = h*31 + uint32(key[i])
	}
	return h % shardCount
}

func (s *store) shardByKey(key string) *shard {
	return s.shards[hashKey(key)]
}

func (s *store) isBlocked(ip string) (bool, string) {
	sh := s.shard(ip)
	sh.mu.RLock()
	e, ok := sh.blocked[ip]
	sh.mu.RUnlock()
	if !ok {
		return false, ""
	}
	if time.Now().UnixNano() >= e.until {
		sh.mu.Lock()
		delete(sh.blocked, ip)
		sh.mu.Unlock()
		return false, ""
	}
	return true, e.reason
}

func (s *store) block(ip, reason string, duration time.Duration) {
	until := time.Now().Add(duration).UnixNano()
	sh := s.shard(ip)
	sh.mu.Lock()
	sh.blocked[ip] = blockEntry{until: until, reason: reason}
	sh.mu.Unlock()
}

func (s *store) incReqBurst(ip string, bucketBurst int64) int64 {
	sh := s.shard(ip)
	sh.mu.Lock()
	w, ok := sh.reqBurst[ip]
	if !ok || w.until != bucketBurst {
		w = &windowCount{count: 1, until: bucketBurst}
		sh.reqBurst[ip] = w
		sh.mu.Unlock()
		return 1
	}
	w.count++
	n := w.count
	sh.mu.Unlock()
	return n
}

func (s *store) incReq(ip string, bucketMin int64) int64 {
	sh := s.shard(ip)
	sh.mu.Lock()
	w, ok := sh.reqCount[ip]
	if !ok || w.until != bucketMin {
		w = &windowCount{count: 1, until: bucketMin}
		sh.reqCount[ip] = w
		sh.mu.Unlock()
		return 1
	}
	w.count++
	n := w.count
	sh.mu.Unlock()
	return n
}

func (s *store) incReqPath(ip, path string, bucketMin int64) int64 {
	sh := s.shard(ip)
	sh.mu.Lock()
	if sh.reqByPath[ip] == nil {
		sh.reqByPath[ip] = make(map[string]*windowCount, 4)
	}
	w, ok := sh.reqByPath[ip][path]
	if !ok || w.until != bucketMin {
		w = &windowCount{count: 1, until: bucketMin}
		sh.reqByPath[ip][path] = w
		sh.mu.Unlock()
		return 1
	}
	w.count++
	n := w.count
	sh.mu.Unlock()
	return n
}

func (s *store) incFailedAuth(ip string, bucketAuth int64) int64 {
	sh := s.shard(ip)
	sh.mu.Lock()
	w, ok := sh.failedAuth[ip]
	if !ok || w.until != bucketAuth {
		w = &windowCount{count: 1, until: bucketAuth}
		sh.failedAuth[ip] = w
		sh.mu.Unlock()
		return 1
	}
	w.count++
	n := w.count
	sh.mu.Unlock()
	return n
}

func (s *store) incReqKey(key string, bucketMin int64) int64 {
	sh := s.shardByKey(key)
	sh.mu.Lock()
	w, ok := sh.reqByKey[key]
	if !ok || w.until != bucketMin {
		w = &windowCount{count: 1, until: bucketMin}
		sh.reqByKey[key] = w
		sh.mu.Unlock()
		return 1
	}
	w.count++
	n := w.count
	sh.mu.Unlock()
	return n
}

func hashPathQuery(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// setChallengeToken stores token bound to IP and expiry. maxSize 0 = no limit. returns false if at capacity.
func (s *store) setChallengeToken(token, ip string, until int64, maxSize int64) bool {
	sh := s.shardByKey(token)
	sh.mu.Lock()
	sh.challengeTokens[token] = challengeEntry{ip: ip, until: until}
	sh.mu.Unlock()
	n := s.challengeTokenCount.Add(1)
	if maxSize > 0 && n > maxSize {
		sh.mu.Lock()
		delete(sh.challengeTokens, token)
		sh.mu.Unlock()
		s.challengeTokenCount.Add(-1)
		return false
	}
	return true
}

// validateChallengeToken checks token exists, IP matches, not expired. constant-time path.
func (s *store) validateChallengeToken(token, ip string, nowNano int64) bool {
	if token == "" || ip == "" {
		return false
	}
	sh := s.shardByKey(token)
	sh.mu.RLock()
	e, ok := sh.challengeTokens[token]
	sh.mu.RUnlock()
	if !ok {
		return false
	}
	if nowNano >= e.until {
		sh.mu.Lock()
		delete(sh.challengeTokens, token)
		sh.mu.Unlock()
		s.challengeTokenCount.Add(-1)
		return false
	}
	return constantTimeEqual(e.ip, ip)
}

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff uint8
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *store) resetChallengeTokens() {
	var removed int64
	for i := 0; i < shardCount; i++ {
		sh := s.shards[i]
		sh.mu.Lock()
		n := int64(len(sh.challengeTokens))
		for k := range sh.challengeTokens {
			delete(sh.challengeTokens, k)
		}
		sh.mu.Unlock()
		removed += n
	}
	if removed > 0 {
		s.challengeTokenCount.Add(-removed)
	}
}

func (s *store) addUniqueURL(ip, pathQuery string, bucketMin int64) int64 {
	sh := s.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	w, ok := sh.uniqueURLs[ip]
	if !ok || w.until != bucketMin {
		w = &uniqueURLWindow{until: bucketMin, urls: make(map[uint64]struct{}, 32)}
		sh.uniqueURLs[ip] = w
	}
	h := hashPathQuery(pathQuery)
	w.urls[h] = struct{}{}
	return int64(len(w.urls))
}

func (s *store) prune(rateLimitWindow, burstWindow time.Duration) {
	now := time.Now()
	if rateLimitWindow < time.Second {
		rateLimitWindow = windowMinute
	}
	if burstWindow < time.Second {
		burstWindow = 10 * time.Second
	}
	bucketMin := now.Truncate(rateLimitWindow).Unix()
	bucketBurst := now.Truncate(burstWindow).Unix()
	bucketAuth := now.Truncate(windowAuth).Unix()
	nowNano := now.UnixNano()
	for i := 0; i < shardCount; i++ {
		sh := s.shards[i]
		sh.mu.Lock()
		for ip, e := range sh.blocked {
			if nowNano >= e.until {
				delete(sh.blocked, ip)
			}
		}
		for ip, w := range sh.reqBurst {
			if w.until != bucketBurst {
				delete(sh.reqBurst, ip)
			}
		}
		for ip, w := range sh.reqCount {
			if w.until != bucketMin {
				delete(sh.reqCount, ip)
			}
		}
		for ip, m := range sh.reqByPath {
			for path, w := range m {
				if w.until != bucketMin {
					delete(m, path)
				}
			}
			if len(m) == 0 {
				delete(sh.reqByPath, ip)
			}
		}
		for ip, w := range sh.failedAuth {
			if w.until != bucketAuth {
				delete(sh.failedAuth, ip)
			}
		}
		for key, w := range sh.reqByKey {
			if w.until != bucketMin {
				delete(sh.reqByKey, key)
			}
		}
		for ip, w := range sh.uniqueURLs {
			if w.until != bucketMin {
				delete(sh.uniqueURLs, ip)
			}
		}
		for token, e := range sh.challengeTokens {
			if nowNano >= e.until {
				delete(sh.challengeTokens, token)
				s.challengeTokenCount.Add(-1)
			}
		}
		sh.mu.Unlock()
	}
}
