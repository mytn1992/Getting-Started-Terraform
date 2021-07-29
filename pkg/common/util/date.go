package util

import "time"

func MidnightUTC() time.Time {
	t := time.Now().UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
}
