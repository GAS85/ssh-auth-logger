package common

import "testing"

func TestIsPrivateIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		// private
		{"10.0.0.1", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.100", true},
		{"fd00::1", true},
		{"fc00::1", true},
		// loopback and link-local
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.10.10", true},
		{"fe80::1", true},
		// public
		{"8.8.8.8", false},
		{"203.0.113.9", false},
		{"172.15.255.255", false},
		{"172.32.0.1", false},
		{"192.169.0.1", false},
		{"2001:db8::1", false},
		{"2606:4700::1111", false},
		// not an IP
		{"", false},
		{"not-an-ip", false},
		{"10.0.0.1:22", false},
		{"10.0.0", false},
	}
	for _, tc := range cases {
		if got := IsPrivateIP(tc.ip); got != tc.want {
			t.Errorf("IsPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}
