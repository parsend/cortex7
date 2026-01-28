// cortex7 in-memory store, sharded for millions RPS. parsend(c0redev)

package cortex7

import (
	"sync"
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

type shard struct {
	mu         sync.RWMutex
	blocked    map[string]blockEntry
	reqCount   map[string]*windowCount
	reqByPath  map[string]map[string]*windowCount
	failedAuth map[string]*windowCount
}

func newShard() *shard {
	return &shard{
		blocked:    make(map[string]blockEntry, 64),
		reqCount:   make(map[string]*windowCount, 256),
		reqByPath:  make(map[string]map[string]*windowCount, 64),
		failedAuth: make(map[string]*windowCount, 64),
	}
}

type store struct {
	shards [shardCount]*shard
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

func (s *store) prune() {
	now := time.Now()
	bucketMin := now.Truncate(windowMinute).Unix()
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
		sh.mu.Unlock()
	}
}
