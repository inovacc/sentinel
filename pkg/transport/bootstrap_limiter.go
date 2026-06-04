package transport

import (
	"net"
	"sync"
	"time"
)

// perIPLimiter throttles pre-auth bootstrap connections by source IP across two
// dimensions: a concurrent-connection cap and a token-bucket rate of new
// connections per second. It is keyed by IP (not device ID) because bootstrap
// is pre-authentication. Idle buckets are evicted by a periodic sweep to bound
// memory.
type perIPLimiter struct {
	mu         sync.Mutex
	buckets    map[string]*ipBucket
	maxConns   int
	ratePerSec int
}

type ipBucket struct {
	active   int       // currently-held concurrent connections
	tokens   int       // rate tokens remaining this second
	lastFill time.Time // last token refill
	lastSeen time.Time // last activity, for the idle sweep
}

// newPerIPLimiter builds a limiter allowing maxConns concurrent connections and
// ratePerSec new connections per second, per source IP.
func newPerIPLimiter(maxConns, ratePerSec int) *perIPLimiter {
	return &perIPLimiter{
		buckets:    make(map[string]*ipBucket),
		maxConns:   maxConns,
		ratePerSec: ratePerSec,
	}
}

// acquire attempts to admit one new connection from ip. It returns a release
// func and true on success; (nil, false) when either the concurrency cap or the
// rate cap is exceeded. The release func MUST be called when the connection
// closes so the concurrency slot is freed.
func (l *perIPLimiter) acquire(ip string) (release func(), ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b := l.buckets[ip]
	if b == nil {
		b = &ipBucket{tokens: l.ratePerSec, lastFill: now}
		l.buckets[ip] = b
	}
	b.lastSeen = now

	// Refill rate tokens once per elapsed second.
	if elapsed := now.Sub(b.lastFill); elapsed >= time.Second {
		b.tokens = l.ratePerSec
		b.lastFill = now
	}

	if b.tokens <= 0 {
		return nil, false // rate cap
	}
	if b.active >= l.maxConns {
		return nil, false // concurrency cap
	}

	b.tokens--
	b.active++
	released := false
	return func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if released {
			return
		}
		released = true
		if cur := l.buckets[ip]; cur != nil && cur.active > 0 {
			cur.active--
			cur.lastSeen = time.Now()
		}
	}, true
}

// sweep evicts buckets idle since before cutoff and with no active connections.
func (l *perIPLimiter) sweep(cutoff time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if b.active == 0 && b.lastSeen.Before(cutoff) {
			delete(l.buckets, ip)
		}
	}
}

// bucketCount reports the number of tracked IP buckets (used by the sweep test).
func (l *perIPLimiter) bucketCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// runSweeper sweeps idle buckets every interval until stop is closed.
func (l *perIPLimiter) runSweeper(interval, idle time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			l.sweep(now.Add(-idle))
		}
	}
}

// remoteIP extracts the source IP string from a net.Addr, falling back to the
// raw address string when it has no host:port form.
func remoteIP(addr net.Addr) string {
	if ta, ok := addr.(*net.TCPAddr); ok {
		return ta.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
