package main

import (
	"fmt"
	"testing"
)

func TestSSHObservationCapsIPsForControlPlane(t *testing.T) {
	ips := make([]string, maxControlPlaneObservationValues+1)
	for i := range ips {
		ips[i] = fmt.Sprintf("192.0.2.%d", i)
	}

	got := sshObservation("fingerprint", Entry{IPs: ips}).IPs
	if len(got) != maxControlPlaneObservationValues {
		t.Fatalf("len(IPs) = %d, want %d", len(got), maxControlPlaneObservationValues)
	}
	for i := range got {
		if got[i] != ips[i] {
			t.Fatalf("IPs[%d] = %q, want %q", i, got[i], ips[i])
		}
	}
}
