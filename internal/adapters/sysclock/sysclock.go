// Package sysclock is the real ports.Clock.
package sysclock

import "time"

// Clock returns the system time in UTC.
type Clock struct{}

// Now implements ports.Clock.
func (Clock) Now() time.Time { return time.Now().UTC() }
