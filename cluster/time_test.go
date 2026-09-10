package cluster

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_unixTime(t *testing.T) {
	assert.Equal(t, time.Unix(1_700_000_000, 0), unixTime(func() int64 { return 1_700_000_000 }))
	assert.WithinDuration(t, time.Now(), unixTime(nil), time.Minute, "nil means the wall clock")
}
