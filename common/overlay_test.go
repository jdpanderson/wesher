package common

import (
	"math"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_MaxHost(t *testing.T) {
	tests := map[string]uint64{
		"10.0.0.0/8":    1<<24 - 2,
		"10.0.0.0/24":   254,
		"10.0.0.0/30":   2,
		"10.0.0.0/31":   0,
		"10.1.2.3/32":   0,
		"fd00:10::/64":  math.MaxUint64 - 1,
		"fd00:10::/48":  math.MaxUint64 - 1,
		"fd00:10::/120": 255,
		"fd00:10::/127": 1,
	}
	for prefix, want := range tests {
		assert.Equal(t, want, MaxHost(netip.MustParsePrefix(prefix)), prefix)
	}
}

func Test_OverlayAddr(t *testing.T) {
	tests := []struct {
		prefix string
		host   uint64
		want   string
	}{
		{"10.0.0.0/8", 1, "10.0.0.1"},
		{"10.0.0.0/8", 256, "10.0.1.0"},
		{"10.0.0.0/8", 1<<24 - 2, "10.255.255.254"},
		{"10.20.30.40/20", 5, "10.20.16.5"}, // non-aligned prefix bits are masked off
		{"10.0.0.0/24", 254, "10.0.0.254"},
		{"fd00:10::/64", 1, "fd00:10::1"},
		{"fd00:10::/64", 1<<32 + 2, "fd00:10::1:0:2"},
		{"fd00:10::1234/120", 255, "fd00:10::12ff"},
	}
	for _, tt := range tests {
		got, ok := OverlayAddr(netip.MustParsePrefix(tt.prefix), tt.host)
		assert.True(t, ok, tt.want)
		assert.Equal(t, tt.want, got.String())
	}

	_, ok := OverlayAddr(netip.MustParsePrefix("10.0.0.0/24"), 0)
	assert.False(t, ok, "slot 0 is the network address")
	_, ok = OverlayAddr(netip.MustParsePrefix("10.0.0.0/24"), 255)
	assert.False(t, ok, "slot 255 is the broadcast address")
	_, ok = OverlayAddr(netip.MustParsePrefix("fd00:10::/120"), 256)
	assert.False(t, ok, "slot outside the prefix")
}
