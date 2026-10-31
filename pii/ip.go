package pii

import (
	"net/netip"
	"strings"
)

// --- IP addresses (public IPv4 and IPv6, IPv4-mapped)

// An address names a person's connection when it is public: the private,
// loopback, link-local, multicast, unspecified, broadcast and reserved
// ranges are infrastructure and stay in clear (see ipPublic).

// maxIPRun bounds a run of address characters tried as one address: the
// longest IPv6 text form with an embedded IPv4 is 45 bytes.
const maxIPRun = 64

// findIPs returns the public IPv6 addresses (2000::/3, and IPv4-mapped or
// IPv4-compatible forms of a public IPv4) and the public IPv4 addresses of
// s. An address glued to a letter, a digit or a dot ("v1.2.3.4",
// "1.2.3.4.5") is a version or a name, not an address.
func findIPs(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isHex(c) && c != ':' {
			continue
		}
		// An IPv6 address starts after neither an address character nor a
		// letter; an IPv4 one may follow a colon ("client:203.0.113.9").
		b := before(s, i)
		v6ok := !isAlnum(b) && b != ':' && b != '.'
		v4ok := isDigit(c) && !isAlnum(b) && b != '.'
		if !v6ok && !v4ok {
			continue
		}
		// The run of characters an address may be written with.
		j := i
		for j < len(s) && j-i <= maxIPRun && (isHex(s[j]) || s[j] == ':' || s[j] == '.') {
			j++
		}
		if j-i > maxIPRun {
			// A longer run (a hex dump, a MAC list) is not one address:
			// skip it whole.
			for j < len(s) && (isHex(s[j]) || s[j] == ':' || s[j] == '.') {
				j++
			}
			i = j - 1
			continue
		}
		run := s[i:j]
		if v6ok && strings.Count(run, ":") >= 2 {
			if end, ok := ipv6At(s, i, j); ok {
				out = append(out, span{i, end})
				i = end - 1
				continue
			}
		}
		if v4ok {
			if end, ok := ipv4At(s, i); ok {
				out = append(out, span{i, end})
				i = end - 1
				continue
			}
		}
		// Not an address here: skip the alphanumeric part of the run, so
		// that the scan stays linear, but retry after each separator.
		for i+1 < len(s) && isHex(s[i+1]) {
			i++
		}
	}
	return out
}

func isHex(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// ipv6At tries s[i:j] as an IPv6 address, then shorter prefixes cut at a
// colon or a dot ("2001:db8::1:", "2001:db8::1." at the end of a
// sentence, "2001:db8:0:0:0:0:1:2:443" with a port glued on).
func ipv6At(s string, i, j int) (int, bool) {
	for end := j; end > i; {
		cand := s[i:end]
		if strings.Count(cand, ":") < 2 {
			return 0, false
		}
		if a, err := netip.ParseAddr(cand); err == nil && a.Is6() && !isAlnum(after(s, end)) {
			return end, ipv6Public(a)
		}
		k := strings.LastIndexAny(cand, ":.")
		if k <= 0 {
			return 0, false
		}
		end = i + k
	}
	return 0, false
}

func ipv6Public(a netip.Addr) bool {
	if a.Is4In6() {
		return ipPublic(a.Unmap())
	}
	b := a.As16()
	// IPv4-compatible (::a.b.c.d, deprecated but still logged).
	if b[0]|b[1]|b[2]|b[3]|b[4]|b[5]|b[6]|b[7]|b[8]|b[9]|b[10]|b[11] == 0 && (b[12]|b[13]) != 0 {
		return ipPublic(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	// Global unicast is the only allocated public range: 2000::/3. That
	// also keeps "add::face" and other hex words in clear.
	if b[0]&0xe0 != 0x20 {
		return false
	}
	return ipPublic(a)
}

// ipv4At reads a dotted quad at s[i:] (octets of 1 to 3 digits, 0 to 255;
// a leading zero is read as decimal) and returns its end when the address
// is public.
func ipv4At(s string, i int) (int, bool) {
	var oct [4]byte
	j := i
	for k := 0; k < 4; k++ {
		if k > 0 {
			if after(s, j) != '.' || !isDigit(after(s, j+1)) {
				return 0, false
			}
			j++
		}
		n, d := 0, 0
		for j < len(s) && isDigit(s[j]) && d < 4 {
			n = n*10 + int(s[j]-'0')
			j++
			d++
		}
		if d == 0 || d > 3 || n > 255 {
			return 0, false
		}
		oct[k] = byte(n)
	}
	// "1.2.3.4.5" (a version) and "1.2.3.4a" are not addresses; a final
	// dot ending a sentence is fine.
	if a := after(s, j); isAlnum(a) || a == '.' && isDigit(after(s, j+1)) {
		return 0, false
	}
	return j, ipPublic(netip.AddrFrom4(oct))
}

// ipPublic reports an address that is not infrastructure: not private
// (RFC 1918, fc00::/7), loopback, link-local, multicast, unspecified,
// broadcast, "this network" (0/8) or reserved (240/4). Shared CGNAT
// addresses (100.64/10) and the documentation ranges are masked: the first
// names a subscriber, the second is what examples and test data use for a
// real address.
func ipPublic(a netip.Addr) bool {
	if !a.IsValid() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	if a.Is4() {
		b := a.As4()
		if b[0] == 0 || b[0] >= 240 {
			return false
		}
	}
	return true
}
