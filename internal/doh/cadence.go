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
	steps    int           // burst steps before decay toward baseline

	jitter float64 // +/- fraction applied to every interval

	rng *rand.Rand
	mu  sync.Mutex

	// remaining is the number of fast (burst) exchanges still owed. It is
	// re-armed from the real uplink backlog each tick, so a large backlog
	// sustains the burst rate instead of collapsing to baseline after one
	// frame.
	remaining int
}

// SchedulerConfig tunes the pacing profile.
type SchedulerConfig struct {
	// Profile applies a named preset (see Profile constants) as a baseline;
	// any field set explicitly below overrides the preset's value. Empty
	// means "use the built-in defaults" (equivalent to ProfileBalanced).
	Profile string
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

// Cadence profiles. These trade throughput against how human the traffic
// looks. Throughput scales inversely with Burst (one frame per exchange):
// roughly 109 B of uplink payload per Burst interval.
const (
	// ProfileStealth minimizes fingerprint: long idle keepalive, slow
	// burst, heavy jitter. Lowest throughput, hardest to distinguish from
	// a human.
	ProfileStealth = "stealth"
	// ProfileBalanced is the default: human-like bursts with moderate
	// throughput.
	ProfileBalanced = "balanced"
	// ProfileFast favors throughput: aggressive burst, light jitter. Easier
	// for an NDR to flag as machine-like, but moves data ~10x faster.
	ProfileFast = "fast"
)

// profilePresets maps a profile name to its concrete settings. Zero-valued
// fields fall through to the built-in defaults in withDefaults.
var profilePresets = map[string]SchedulerConfig{
	ProfileStealth: {
		Baseline:   3000 * time.Millisecond,
		Burst:      250 * time.Millisecond,
		BurstSteps: 8,
		Jitter:     0.5,
	},
	ProfileBalanced: {
		Baseline:   1500 * time.Millisecond,
		Burst:      100 * time.Millisecond,
		BurstSteps: 12,
		Jitter:     0.4,
	},
	ProfileFast: {
		Baseline:   500 * time.Millisecond,
		Burst:      15 * time.Millisecond,
		BurstSteps: 32,
		Jitter:     0.15,
	},
}

// Profiles returns the known profile names, for CLI validation and help.
func Profiles() []string {
	return []string{ProfileStealth, ProfileBalanced, ProfileFast}
}

func (c SchedulerConfig) withDefaults() SchedulerConfig {
	// Apply the named preset first, then let explicit fields win.
	if preset, ok := profilePresets[c.Profile]; ok {
		if c.Baseline <= 0 {
			c.Baseline = preset.Baseline
		}
		if c.Burst <= 0 {
			c.Burst = preset.Burst
		}
		if c.BurstSteps <= 0 {
			c.BurstSteps = preset.BurstSteps
		}
		if c.Jitter <= 0 {
			c.Jitter = preset.Jitter
		}
	}
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
		steps:     cfg.BurstSteps,
		jitter:    cfg.Jitter,
		remaining: 0,
		rng:       rand.New(rand.NewSource(cfg.Seed)),
	}
}

// Notify tells the scheduler that `steps` more exchanges are owed at the
// fast burst rate. It takes the max with any steps already pending, so
// callers can re-arm on every queued frame without over-counting.
func (s *Scheduler) Notify(steps int) {
	s.mu.Lock()
	if steps > s.remaining {
		s.remaining = steps
	}
	s.mu.Unlock()
}

// ArmBurst re-arms a full burst (steps owed at the fast rate). Used for
// downlink self-clocking: when an exchange returned downlink data, more is
// likely pending server-side, so we poll faster until responses go empty.
func (s *Scheduler) ArmBurst() {
	s.mu.Lock()
	s.remaining = s.steps
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

// nextInterval returns the delay until the next exchange, advancing the
// decay state. While fast exchanges are owed (remaining > 0) the interval
// starts at the burst rate and, as remaining drains toward zero, ramps
// geometrically back up to the baseline keepalive. remaining is clamped so a
// large backlog can never push the interval past the burst floor.
func (s *Scheduler) nextInterval() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()

	var base time.Duration
	if s.remaining > 0 {
		s.remaining--
		// frac in [0,1]: 1 while a full burst is owed (remaining >=
		// steps), decaying toward 0 as remaining drains, so the interval
		// ramps from burst up to baseline. A large backlog therefore holds
		// the fast burst rate; only the tail of a burst eases back.
		frac := float64(s.remaining) / float64(s.steps)
		if frac > 1 {
			frac = 1
		}
		base = time.Duration(float64(s.burst) + (1-frac)*float64(s.baseline-s.burst))
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
