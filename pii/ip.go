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
//
// The text is read in runs of address characters (hex digits, ':' and
// '.'). An address is tried at the start of a run and, when none is
// there, after each ':' or '.' inside it, so that an address glued to a
// hex dump or a MAC list is still found. Each try reads at most maxIPRun
// bytes, so the scan stays linear.
func findIPs(s string) []span {
	var out []span
	for i := 0; i < len(s); i++ {
		if !isIPByte(s[i]) {
			continue
		}
		j := i
		for j < len(s) && isIPByte(s[j]) {
			j++
		}
		// A run glued to a letter ("client:203.0.113.9", "v1.2.3.4") is
		// tried only after its separators.
		if strings.IndexByte(s[i:j], ':') >= 0 || !versionContext(s, i) {
			out = ipsInRun(s, i, j, isAlnum(before(s, i)), out)
		}
		i = j - 1
	}
	return out
}

// versionContext reports a run that a version or an OID label precedes
// ("version=1.8.0.201", "oid 2.5.4.3"): a dotted quad there is no address.
func versionContext(s string, i int) bool {
	if i >= 2 && s[i-1] == '/' && (s[i-2] >= 'A' && s[i-2] <= 'Z' || s[i-2] >= 'a' && s[i-2] <= 'z') {
		return true // a product token: "Chrome/124.0.0.0"
	}
	pre := strings.ToLower(s[max(0, i-12):i])
	pre = strings.TrimRight(pre, " \t:=\"'")
	for _, l := range []string{"version", "oid", "build", "release"} {
		if strings.HasSuffix(pre, l) {
			k := len(pre) - len(l)
			return k == 0 || !isAlnum(pre[k-1])
		}
	}
	return false
}

func isIPByte(c byte) bool { return isHex(c) || c == ':' || c == '.' }

// ipsInRun appends the public addresses of the run s[i:j].
func ipsInRun(s string, i, j int, glued bool, out []span) []span {
	for pos := i; pos < j; {
		inner := pos > i || glued
		b := before(s, pos)
		w := min(j, pos+maxIPRun)
		if !glued || pos > i {
			if end, public, ok := ipsAt(s, pos, w, inner, b); ok && (public || !inner && end == j) {
				// A non-public address is consumed only when it is the
				// whole run ("fd12:3456::1"); otherwise it may be a
				// fragment of something longer, so the scan goes on.
				if public {
					out = append(out, span{pos, end})
				} else if k := strings.LastIndexByte(s[pos:end], ':'); k >= 0 && strings.IndexByte(s[pos+k:end], '.') > 0 {
					// fe80::203.0.113.9: the dotted quad is masked on its own.
					if e4, pub4, ok4 := ipv4At(s, pos+k+1); ok4 && pub4 {
						out = append(out, span{pos + k + 1, e4})
					}
				}
				pos = end
				continue
			}
		}
		// Nothing here: try after the next separator.
		k := pos
		for k < j && s[k] != ':' && s[k] != '.' {
			k++
		}
		for k < j && (s[k] == ':' || s[k] == '.') {
			k++
		}
		if k <= pos {
			k = pos + 1
		}
		pos = k
	}
	return out
}

// ipsAt tries an IPv6 then an IPv4 address at s[pos:w]. Inside a run, an
// IPv6 address must follow a colon and an IPv4 one must not follow a dot.
func ipsAt(s string, pos, w int, inner bool, b byte) (end int, public, ok bool) {
	if !inner || b == ':' {
		if end, public, ok := ipv6At(s, pos, w); ok {
			return end, public, true
		}
	}
	if isDigit(s[pos]) && b != '.' {
		return ipv4At(s, pos)
	}
	return 0, false, false
}

func isHex(c byte) bool { return isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// ipv6At tries s[i:j] as an IPv6 address, then shorter prefixes cut at a
// colon or a dot ("2001:db8::1:", "2001:db8::1." at the end of a
// sentence, "2001:db8:0:0:0:0:1:2:443" with a port glued on). ok reports
// that an address was read, public that it is a public one.
func ipv6At(s string, i, j int) (end int, public, ok bool) {
	// An address has at most 7 colons: cut the try at the 8th.
	for k, n := i, 0; k < j; k++ {
		if s[k] == ':' {
			if n++; n == 8 {
				j = k
				break
			}
		}
	}
	for end := j; end > i; {
		cand := s[i:end]
		if strings.Count(cand, ":") < 2 {
			return 0, false, false
		}
		if a, err := netip.ParseAddr(cand); err == nil && a.Is6() && !isAlnum(after(s, end)) {
			return end, ipv6Public(a, strings.IndexByte(cand, '.') >= 0), true
		}
		k := strings.LastIndexAny(cand, ":.")
		if k <= 0 {
			return 0, false, false
		}
		end = i + k
	}
	return 0, false, false
}

func ipv6Public(a netip.Addr, dotted bool) bool {
	if a.Is4In6() {
		return ipPublic(a.Unmap())
	}
	b := a.As16()
	// IPv4-compatible (::a.b.c.d, deprecated but still logged), written
	// with its dotted quad: "::dead:beef" is a hex word, not an address.
	if b[0]|b[1]|b[2]|b[3]|b[4]|b[5]|b[6]|b[7]|b[8]|b[9]|b[10]|b[11] == 0 && (b[12]|b[13]) != 0 && dotted {
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
// a leading zero is read as decimal). ok reports that an address was
// read, public that it is a public one.
func ipv4At(s string, i int) (end int, public, ok bool) {
	var oct [4]byte
	j := i
	for k := 0; k < 4; k++ {
		if k > 0 {
			if after(s, j) != '.' || !isDigit(after(s, j+1)) {
				return 0, false, false
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
			return 0, false, false
		}
		oct[k] = byte(n)
	}
	// "1.2.3.4.5" (a version) and "1.2.3.4a" are not addresses; a final
	// dot ending a sentence is fine.
	if a := after(s, j); isAlnum(a) || a == '.' && isDigit(after(s, j+1)) {
		return 0, false, false
	}
	return j, ipPublic(netip.AddrFrom4(oct)), true
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
