package core

import (
	"errors"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// The directives that lower the limits of a request, with the meaning
// JetBrains gives the first two.
const (
	Timeout           = "timeout"            // read: how long to wait for data once the request is sent
	ConnectionTimeout = "connection-timeout" // connect: DNS, TCP and the TLS handshake
	MaxTime           = "max-time"           // total: the whole exchange, as curl's --max-time
)

// The phases of a request that a timeout can end, as Error.Phase names
// them.
const (
	PhaseConnect = "connect"
	PhaseRead    = "read"
	PhaseTotal   = "total"
)

var timeoutRE = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+)?) *(ms|s|m)?$`)

// ParseTimeout parses a time limit as JetBrains writes it, a number with
// a unit, ms, s or m, or without one for seconds (30, 30 s, 500ms, 2 m),
// or as a Go duration (1m30s). 0 and "none", which FormatTimeout writes,
// are no limit; a time too short to be one is an error, not none.
func ParseTimeout(s string) (time.Duration, error) {
	bad := errors.New("want a time such as 30 (seconds), 500ms, 2m or 1m30s")
	s = strings.TrimSpace(s)
	var d time.Duration
	var err error
	if m := timeoutRE.FindStringSubmatch(s); m != nil {
		unit := map[string]time.Duration{"": time.Second, "s": time.Second, "ms": time.Millisecond, "m": time.Minute}[m[2]]
		var n float64
		if n, err = strconv.ParseFloat(m[1], 64); err != nil || n*float64(unit) >= math.MaxInt64 {
			return 0, bad
		}
		d = time.Duration(n * float64(unit))
	} else if s == "none" {
		return 0, nil
	} else if d, err = time.ParseDuration(s); err != nil || d < 0 {
		return 0, bad
	}
	if d == 0 && strings.ContainsAny(s, "123456789") {
		return 0, bad
	}
	return d, nil
}

// FormatTimeout writes d as a Go duration without zero minutes or
// seconds at its end (2m, not 2m0s), or "none" for 0.
func FormatTimeout(d time.Duration) string {
	if d == 0 {
		return "none"
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}
