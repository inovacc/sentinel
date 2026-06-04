package transport

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"time"

	"github.com/inovacc/sentinel/internal/limits"
)

// connLimitOpts configures the connection-limiting listener wrapper.
type connLimitOpts struct {
	maxConns         int           // global concurrent mTLS connections
	perDevice        int           // per-device concurrent connections
	handshakeTimeout time.Duration // deadline around tls.Conn.Handshake
}

// connLimitListener wraps a net.Listener to enforce a global concurrent-conn
// cap and a per-device cap, and to bound the TLS handshake with a deadline so a
// slowloris half-open handshake cannot hold a file descriptor forever. The
// per-device counter is keyed once the certificate is verified (post-handshake);
// over-cap connections are closed under the breach contract.
//
// Global cap enforcement uses a counting semaphore (buffered channel of size
// maxConns). Accept blocks on the semaphore BEFORE calling the inner listener,
// so freeing a slot (by closing a countedConn) immediately unblocks a waiting
// Accept goroutine without requiring a new TCP connection to arrive first.
type connLimitListener struct {
	net.Listener
	opts     connLimitOpts
	recorder *limits.Recorder

	// sem is a counting semaphore of capacity maxConns. A token is taken when
	// Accept returns a conn and released when that conn is closed. When sem is
	// nil (maxConns == 0), no global cap is enforced.
	sem chan struct{}

	mu     sync.Mutex
	perDev map[string]int
}

// newConnLimitListener wraps inner with the given caps and breach recorder.
func newConnLimitListener(inner net.Listener, opts connLimitOpts, rec *limits.Recorder) *connLimitListener {
	var sem chan struct{}
	if opts.maxConns > 0 {
		sem = make(chan struct{}, opts.maxConns)
	}
	return &connLimitListener{
		Listener: inner,
		opts:     opts,
		recorder: rec,
		sem:      sem,
		perDev:   make(map[string]int),
	}
}

// Accept admits the next connection that fits within the caps. Over-cap and
// slow-handshake connections are closed and Accept continues, so the caller's
// serve loop only ever sees admitted, handshaken connections.
func (l *connLimitListener) Accept() (net.Conn, error) {
	for {
		// Acquire a global slot before blocking on the underlying Accept (T2.6).
		// This way, when a countedConn is closed and releases its token, a
		// goroutine already waiting here unblocks immediately.
		//
		// The global cap is back-pressure (block), not a drop: we never lose an
		// admitted connection. But a saturated cap is still a breach worth
		// observing, so we do a non-blocking probe first and, when the semaphore
		// is full, emit the conn_cap breach (once per saturated Accept) before
		// falling back to the blocking acquire. This records the DoS signal
		// without weakening the limit or changing the back-pressure behavior.
		if l.sem != nil {
			select {
			case l.sem <- struct{}{}:
				// Slot was immediately available; no breach.
			default:
				// Global cap saturated — record the breach, then block until a
				// slot frees (preserving back-pressure semantics).
				l.recorder.Record(context.TODO(), limits.KindConnCap, l.Listener.Addr().String())
				l.sem <- struct{}{}
			}
		}

		raw, err := l.Listener.Accept()
		if err != nil {
			if l.sem != nil {
				<-l.sem // return the token we just acquired
			}
			return nil, err
		}

		// Bound the handshake (T2.6). Only TLS conns have a handshake; the mTLS
		// listener always produces *tls.Conn.
		dev := ""
		if tc, ok := raw.(*tls.Conn); ok && l.opts.handshakeTimeout > 0 {
			_ = tc.SetDeadline(time.Now().Add(l.opts.handshakeTimeout))
			if herr := tc.Handshake(); herr != nil {
				l.recorder.Record(context.TODO(), limits.KindHandshakeTimeout, raw.RemoteAddr().String())
				if l.sem != nil {
					<-l.sem // release the slot; retry below
				}
				_ = raw.Close()
				continue
			}
			_ = tc.SetDeadline(time.Time{}) // clear the handshake deadline
			dev = deviceKeyFromTLS(tc)
		}

		// Per-device cap (T2.6), keyed by the verified peer cert.
		if dev != "" && !l.tryDevice(dev) {
			l.recorder.Record(context.TODO(), limits.KindPerDeviceCap, dev)
			if l.sem != nil {
				<-l.sem // release the global slot too
			}
			_ = raw.Close()
			continue
		}

		return &countedConn{Conn: raw, parent: l, dev: dev}, nil
	}
}

func (l *connLimitListener) tryDevice(dev string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.opts.perDevice > 0 && l.perDev[dev] >= l.opts.perDevice {
		return false
	}
	l.perDev[dev]++
	return true
}

func (l *connLimitListener) release(dev string) {
	l.mu.Lock()
	if dev != "" && l.perDev[dev] > 0 {
		l.perDev[dev]--
		if l.perDev[dev] == 0 {
			delete(l.perDev, dev)
		}
	}
	l.mu.Unlock()

	// Release the global semaphore slot.
	if l.sem != nil {
		<-l.sem
	}
}

// deviceKeyFromTLS derives a stable per-device key from the verified peer
// certificate chain. It returns "" when no verified peer cert is present.
func deviceKeyFromTLS(tc *tls.Conn) string {
	state := tc.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return ""
	}
	return state.PeerCertificates[0].Subject.CommonName
}

// countedConn decrements the listener's counters exactly once on Close.
type countedConn struct {
	net.Conn
	parent *connLimitListener
	dev    string
	once   sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.parent.release(c.dev) })
	return c.Conn.Close()
}

// NewLimitRecorderForTest builds a no-op breach recorder for tests in this
// package (nil audit logger; metric still increments).
func NewLimitRecorderForTest() *limits.Recorder { return limits.NewRecorder(nil) }
