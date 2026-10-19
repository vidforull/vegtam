package core

import (
	"testing"
	"time"
)

func TestParseTimeout(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want time.Duration
	}{
		{"30", 30 * time.Second},
		{"30 s", 30 * time.Second},
		{"30s", 30 * time.Second},
		{"0", 0},
		{"500 ms", 500 * time.Millisecond},
		{"500ms", 500 * time.Millisecond},
		{"2 m", 2 * time.Minute},
		{"1.5", 1500 * time.Millisecond},
		{"1m30s", 90 * time.Second},
		{" 10 ", 10 * time.Second},
		{"2h", 2 * time.Hour},
		{"none", 0},
		{"0s", 0},
		{"0.0", 0},
	} {
		if got, err := ParseTimeout(tt.in); err != nil || got != tt.want {
			t.Errorf("ParseTimeout(%q) = %v, %v; want %v", tt.in, got, err, tt.want)
		}
	}
	for _, in := range []string{"", "-1", "-1s", "ten", "30 sec", "1e3", "5 h", "9999999999999 m", "1,5", "0.1ns", "0.0000000001", "None"} {
		if got, err := ParseTimeout(in); err == nil {
			t.Errorf("ParseTimeout(%q) = %v, want an error", in, got)
		}
	}
}

func TestFormatTimeout(t *testing.T) {
	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{0, "none"},
		{10 * time.Second, "10s"},
		{2 * time.Minute, "2m"},
		{90 * time.Second, "1m30s"},
		{time.Hour, "1h"},
		{500 * time.Millisecond, "500ms"},
		{time.Hour + time.Second, "1h0m1s"},
	} {
		if got := FormatTimeout(tt.d); got != tt.want {
			t.Errorf("FormatTimeout(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
