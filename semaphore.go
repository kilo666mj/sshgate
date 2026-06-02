package main

// semaphore bounds the number of connections processed concurrently,
// regardless of source IP.
type semaphore struct {
	slots chan struct{}
}

func newSemaphore(n int) *semaphore {
	return &semaphore{slots: make(chan struct{}, n)}
}

func (s *semaphore) acquire() bool {
	if s == nil {
		return true
	}
	select {
	case s.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *semaphore) release() {
	if s == nil {
		return
	}
	<-s.slots
}
