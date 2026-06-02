package main

import "testing"

func TestSemaphoreAcquireRelease(t *testing.T) {
	sem := newSemaphore(1)
	if !sem.acquire() {
		t.Fatal("first acquire should succeed")
	}
	if sem.acquire() {
		t.Fatal("second acquire should fail")
	}
	sem.release()
	if !sem.acquire() {
		t.Fatal("acquire after release should succeed")
	}
}
