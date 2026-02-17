package clock

import (
	"time"
)

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (RealClock) Now() time.Time {
	return time.Now()
}

type FakeClock struct {
	time time.Time
}

func (c FakeClock) Now() time.Time {
	return c.time
}

func NewFakePassiveClock(t time.Time) *FakeClock {
	return &FakeClock{
		time: t,
	}
}
