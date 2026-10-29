package ticket

import (
	"crypto/rand"
	"time"
)

// crockford is the ULID alphabet (Crockford's base32, upper case).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// NewID is a fresh ticket id: a ULID (48-bit Unix milliseconds, then 80
// random bits), 26 upper-case characters that sort by creation time.
func NewID(now time.Time) string {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ticket: crypto/rand: " + err.Error())
	}
	return encodeULID(b)
}

func encodeULID(b [16]byte) string {
	// 128 bits as 26 base32 digits: the first digit holds the top 3 bits.
	var out [26]byte
	var acc uint64
	bits := 0
	j := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && j >= 0 {
			out[j] = crockford[acc&31]
			acc >>= 5
			bits -= 5
			j--
		}
	}
	out[0] = crockford[acc&31]
	return string(out[:])
}

// ValidID reports whether s is a ULID in canonical form: 26 characters of
// the upper-case alphabet, the first at most '7'.
func ValidID(s string) bool {
	if len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		ok := false
		for j := 0; j < len(crockford); j++ {
			if s[i] == crockford[j] {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}
