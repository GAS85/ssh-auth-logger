package common

import "net"

// IsPrivateIP reports whether s is a literal IP address that should not show up as the source of a connection to an internet-facing honeypot: private ranges (RFC 1918 and IPv6 unique local fc00::/7), loopback and link-local addresses. Anything that is not a valid IP (empty, host names, "host:port") yields false.
func IsPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
