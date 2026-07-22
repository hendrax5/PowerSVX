package anomaly

import (
	"math"
	"sync"
	"time"
)

// Detector watches query/error rates with a simple EWMA baseline (no external ML).
type Detector struct {
	mu sync.Mutex

	window time.Duration
	bucket time.Time
	qCount uint64
	eCount uint64 // SERVFAIL + REFUSED + FORMERR style

	qRateEWMA float64
	eRateEWMA float64
	warm      int

	alerts []Alert
	max    int
}

type Alert struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`
	Message string    `json:"message"`
	Score   float64   `json:"score"`
	Current float64   `json:"current"`
	Baseline float64  `json:"baseline"`
}

func New(maxAlerts int) *Detector {
	if maxAlerts <= 0 {
		maxAlerts = 50
	}
	return &Detector{
		window: 10 * time.Second,
		bucket: time.Now().UTC().Truncate(10 * time.Second),
		max:    maxAlerts,
	}
}

// Observe records one query; rcode is DNS RCODE string.
func (d *Detector) Observe(rcode string) {
	if d == nil {
		return
	}
	now := time.Now().UTC()
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(now)
	d.qCount++
	switch rcode {
	case "SERVFAIL", "REFUSED", "FORMERR", "NOTIMP":
		d.eCount++
	}
}

func (d *Detector) rollLocked(now time.Time) {
	b := now.Truncate(d.window)
	if b.Equal(d.bucket) {
		return
	}
	elapsed := b.Sub(d.bucket).Seconds()
	if elapsed <= 0 {
		elapsed = d.window.Seconds()
	}
	qRate := float64(d.qCount) / elapsed
	eRate := float64(d.eCount) / elapsed

	const alpha = 0.2
	if d.warm == 0 {
		d.qRateEWMA = qRate
		d.eRateEWMA = eRate
	} else {
		d.qRateEWMA = alpha*qRate + (1-alpha)*d.qRateEWMA
		d.eRateEWMA = alpha*eRate + (1-alpha)*d.eRateEWMA
	}
	d.warm++

	// Need a few windows before alerting.
	if d.warm >= 3 {
		if d.qRateEWMA > 0.5 && qRate > d.qRateEWMA*3 && qRate-d.qRateEWMA > 2 {
			d.pushLocked(Alert{
				Time: now, Kind: "query_spike",
				Message:  "Query rate spike vs baseline",
				Score:    qRate / math.Max(d.qRateEWMA, 0.01),
				Current:  qRate,
				Baseline: d.qRateEWMA,
			})
		}
		if d.eRateEWMA >= 0 && eRate > math.Max(d.eRateEWMA*4, 1) && eRate > 0.5 {
			d.pushLocked(Alert{
				Time: now, Kind: "error_spike",
				Message:  "Error RCODE rate elevated",
				Score:    eRate / math.Max(d.eRateEWMA, 0.01),
				Current:  eRate,
				Baseline: d.eRateEWMA,
			})
		}
		// Absolute ratio: catches sustained outages where EWMA baseline also rises.
		if qRate >= 5 && eRate >= qRate*0.5 {
			d.pushLocked(Alert{
				Time: now, Kind: "error_ratio_high",
				Message:  "More than half of queries returning error RCODEs",
				Score:    eRate / math.Max(qRate, 0.01),
				Current:  eRate,
				Baseline: qRate,
			})
		}
	}

	d.bucket = b
	d.qCount = 0
	d.eCount = 0
}

func (d *Detector) pushLocked(a Alert) {
	d.alerts = append([]Alert{a}, d.alerts...)
	if len(d.alerts) > d.max {
		d.alerts = d.alerts[:d.max]
	}
}

func (d *Detector) Snapshot() map[string]any {
	if d == nil {
		return map[string]any{"alerts": []Alert{}, "warm": 0}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now().UTC())
	alerts := make([]Alert, len(d.alerts))
	copy(alerts, d.alerts)
	return map[string]any{
		"alerts":          alerts,
		"warm":            d.warm,
		"qps_baseline":    round2(d.qRateEWMA),
		"error_baseline":  round2(d.eRateEWMA),
		"window_seconds":  int(d.window.Seconds()),
		"note":            "EWMA spike detector (not cloud ML). Alerts when rate ≫ baseline.",
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}
