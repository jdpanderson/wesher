package cluster

import "time"

// unixTime adapts an optional unix-seconds clock (nil means time.Now) to time.Time.
func unixTime(now func() int64) time.Time {
	if now == nil {
		return time.Now()
	}
	return time.Unix(now(), 0)
}
