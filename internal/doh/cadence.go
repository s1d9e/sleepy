package doh

import (
	"context"
	"math/rand"
	"sync"
	"time"
)

// The cadence scheduler paces DoH exchanges so the tunnel blends with
// human browsing traffic.
//
// A naive constant rate (e.g. exactly one query every 250 ms) is a
// heartbeat fingerprint: NDRs flag machine-regular intervals immediately.
// Real interactive traffic is bursty — a page load fires a flurry of
// requests, then goes quiet. Sleepy mimics that:
//
//	idle --data pending--> BURST (up to burstRate) --exponential decay--> baseline keepalive
//
// The scheduler exposes Next(ctx), which blocks until the next exchange is
// due. Callers that have nothing to send simply let it tick at the
// baseline rate (keepalive); when data is queued, the scheduler ramps to
// the burst rate and decays back down.
type Scheduler struct {
	baseline time.Duration // idle keepalive interval
	burst    time.Duration // interval during a burst

	jitter float64 // +/- fraction applied to every interval

	rng *rand.Rand
	mu  sync.Mutex

	// decay models the ramp-down: after a burst the scheduler spaces
	// intervals geometrically from burst back to baseline over decay
	// steps, rather than dropping instantly.
	remaining int // burst steps left
}

// SchedulerConfig tunes the pacing profile.
type SchedulerConfig struct {
	// Baseline is the idle keepalive interval. Default 1500ms.
	Baseline time.Duration
	// Burst is the minimum interval when data is queued. Default 100ms.
	Burst time.Duration
	// BurstSteps is how many burst-rate exchanges happen before decay
	// begins. Default 12.
	BurstSteps int
	// Jitter is the +/- fraction applied to every interval (0.0-1.0).
	// Default 0.4.
	Jitter float64
	// Seed seeds the RNG; zero uses the clock.
	Seed int64
}

func (c SchedulerConfig) withDefaults() SchedulerConfig {
	if c.Baseline <= 0 {
		c.Baseline = 1500 * time.Millisecond
	}
	if c.Burst <= 0 {
		c.Burst = 100 * time.Millisecond
	}
	if c.BurstSteps <= 0 {
		c.BurstSteps = 12
	}
	if c.Jitter <= 0 {
		c.Jitter = 0.4
	}
	if c.Seed == 0 {
		c.Seed = time.Now().UnixNano()
	}
	return c
}

// NewScheduler builds a scheduler with the given profile.
func NewScheduler(cfg SchedulerConfig) *Scheduler {
	cfg = cfg.withDefaults()
	return &Scheduler{
		baseline:  cfg.Baseline,
		burst:     cfg.Burst,
		jitter:    cfg.Jitter,
		remaining: 0,
		rng:       rand.New(rand.NewSource(cfg.Seed)),
	}
}

// Notify tells the scheduler that data is pending, arming a burst.
func (s *Scheduler) Notify(steps int) {
	s.mu.Lock()
	if steps > s.remaining {
		s.remaining = steps
	}
	s.mu.Unlock()
}

// Next blocks until the next exchange is due. It returns false when ctx is
// done.
func (s *Scheduler) Next(ctx context.Context) bool {
	d := s.nextInterval()
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Scheduler) nextInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	var base time.Duration
	if s.remaining > 0 {
		// Burst phase with geometric decay toward baseline.
		s.remaining--
		frac := float64(s.remaining) / float64(12)
		if frac < 0 {
			frac = 0
		}
		base = time.Duration(float64(s.burst) + frac*float64(s.baseline-s.burst))
	} else {
		base = s.baseline
	}

	// Symmetric jitter in [1-j, 1+j).
	j := s.jitter
	if j > 0.9 {
		j = 0.9
	}
	span := 2 * j
	d := float64(base) * (1 - j + s.rng.Float64()*span)
	return time.Duration(d)
}
