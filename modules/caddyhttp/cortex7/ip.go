// ip helpers, zero alloc where possible. parsend(c0redev)

package cortex7

import (
	"net/netip"
	"strings"
)

const prefixIPv4Map = "::ffff:"

func trimIPv4Mapping(s string) string {
	if len(s) >= 8 && s[:7] == "::ffff:" {
		return s[7:]
	}
	return s
}

// firstIP returns first IP from comma-separated list, in-place (no alloc for typical "x" or "x, y").
func firstIP(s string) string {
	// trim leading space
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	if len(s) == 0 {
		return ""
	}
	idx := strings.IndexByte(s, ',')
	if idx >= 0 {
		s = s[:idx]
		for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
			s = s[:len(s)-1]
		}
	}
	if len(s) == 0 {
		return ""
	}
	if _, err := netip.ParseAddr(s); err != nil {
		return ""
	}
	return s
}

func realIPFromHeaders(headerCf, headerCustom, headerXFF string, getHeader func(string) string) string {
	if headerCf != "" {
		if v := getHeader("Cf-Connecting-Ip"); v != "" {
			ip := firstIP(v)
			if ip != "" {
				return trimIPv4Mapping(ip)
			}
		}
	}
	if headerCustom != "" {
		if v := getHeader(headerCustom); v != "" {
			ip := firstIP(v)
			if ip != "" {
				return trimIPv4Mapping(ip)
			}
		}
	}
	if headerXFF != "" {
		if v := getHeader("X-Forwarded-For"); v != "" {
			ip := firstIP(v)
			if ip != "" {
				return trimIPv4Mapping(ip)
			}
		}
	}
	return ""
}

func isValidIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

var (
	privateV4 = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	privateV6 = []netip.Prefix{
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("::1/128"),
	}
)

func isPrivateIP(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if ip.Is4() {
		for _, p := range privateV4 {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	for _, p := range privateV6 {
		if p.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsLinkLocalUnicast()
}
