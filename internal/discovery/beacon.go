package discovery

import (
	"log/slog"
	"sync"
	"time"
)

// DefaultWindow is the advertising window used when none is configured.
const DefaultWindow = 5 * time.Minute

// advertiserControl is the subset of Advertiser that Beacon drives. It exists so
// the windowing logic can be tested without binding real mDNS sockets.
type advertiserControl interface {
	Start() error
	Stop()
}

// Beacon advertises an mDNS service in time-boxed windows. Each Trigger opens
// (or extends) a window of the configured duration; when the window lapses with
// no further Trigger, advertising stops. This keeps the daemon discoverable only
// when it is likely needed — just after startup, and after a connection is lost —
// instead of broadcasting on the LAN continuously.
type Beacon struct {
	adv       advertiserControl
	window    time.Duration
	logger    *slog.Logger
	triggerC  chan struct{}
	closeC    chan struct{}
	doneC     chan struct{}
	closeOnce sync.Once
}

// NewBeacon starts a beacon goroutine driving adv. A window <= 0 uses
// DefaultWindow; a nil logger falls back to slog.Default(). Call Close to stop.
func NewBeacon(adv advertiserControl, window time.Duration, logger *slog.Logger) *Beacon {
	if window <= 0 {
		window = DefaultWindow
	}
	if logger == nil {
		logger = slog.Default()
	}
	b := &Beacon{
		adv:      adv,
		window:   window,
		logger:   logger,
		triggerC: make(chan struct{}, 1),
		closeC:   make(chan struct{}),
		doneC:    make(chan struct{}),
	}
	go b.run()
	return b
}

// Trigger opens or extends the advertising window. It is safe to call
// concurrently and never blocks; concurrent triggers are coalesced.
func (b *Beacon) Trigger() {
	select {
	case b.triggerC <- struct{}{}:
	default: // a trigger is already pending
	}
}

// Close stops advertising and shuts down the beacon goroutine. It blocks until
// teardown completes and is safe to call multiple times.
func (b *Beacon) Close() {
	b.closeOnce.Do(func() { close(b.closeC) })
	<-b.doneC
}

func (b *Beacon) run() {
	defer close(b.doneC)

	var (
		advertising bool
		deadline    time.Time
		timer       *time.Timer
		timerC      <-chan time.Time
	)
	stopAdvertising := func() {
		if advertising {
			b.adv.Stop()
			advertising = false
		}
		if timer != nil {
			timer.Stop()
			timer = nil
			timerC = nil
		}
	}

	for {
		select {
		case <-b.closeC:
			stopAdvertising()
			return

		case <-b.triggerC:
			deadline = time.Now().Add(b.window)
			if !advertising {
				if err := b.adv.Start(); err != nil {
					b.logger.Warn("discovery: could not open advertising window", "error", err)
					continue
				}
				advertising = true
				b.logger.Info("discovery: advertising window opened", "window", b.window.String())
			}
			if timer == nil {
				timer = time.NewTimer(b.window)
				timerC = timer.C
			}

		case <-timerC:
			// The timer fires at the original deadline; a later Trigger may have
			// pushed the deadline out, in which case re-arm for the remainder.
			if remaining := time.Until(deadline); remaining > 0 {
				timer.Reset(remaining) // safe: channel was just drained by this receive
				continue
			}
			b.logger.Info("discovery: advertising window closed")
			stopAdvertising()
		}
	}
}
