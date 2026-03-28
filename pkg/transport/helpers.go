package transport

import "time"

// timeNow is a variable for testing (allows mocking time).
var timeNow = time.Now

// daysToDuration converts days to a time.Duration.
func daysToDuration(days int) time.Duration {
	return time.Duration(days) * 24 * time.Hour
}
