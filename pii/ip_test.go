package pii

import (
	"strings"
	"testing"
)

func TestIPMasks(t *testing.T) {
	d := detector(t, "ip")
	cases := []struct {
		in     string
		masked []string
		kept   []string
	}{
		{in: "client 203.0.113.9 connected", masked: []string{"203.0.113.9"}, kept: []string{"client ", " connected"}},
		{in: "remote_addr=8.8.8.8 status=502", masked: []string{"8.8.8.8"}, kept: []string{"remote_addr=", " status=502"}},
		{in: `{"ip":"81.246.12.7"}`, masked: []string{"81.246.12.7"}, kept: []string{`{"ip":"`, `"}`}},
		{in: "from 81.246.12.7:51234 to", masked: []string{"81.246.12.7"}, kept: []string{":51234"}},
		{in: "client:203.0.113.9", masked: []string{"203.0.113.9"}},
		{in: "X-Forwarded-For: 198.51.100.4, 10.0.0.2", masked: []string{"198.51.100.4"}, kept: []string{"10.0.0.2"}},
		{in: "net 203.0.113.0/24.", masked: []string{"203.0.113.0"}, kept: []string{"/24."}},
		{in: "CGNAT 100.64.1.2", masked: []string{"100.64.1.2"}},
		{in: "leading zeros 081.246.012.007", masked: []string{"081.246.012.007"}},
		{in: "v6 2001:db8::1 ok", masked: []string{"2001:db8::1"}, kept: []string{"v6 ", " ok"}},
		{in: "[2a02:a03f:6b4c:f100:1c4e:9d3f:ab12:77e1]:443", masked: []string{"2a02:a03f", "77e1"}, kept: []string{"[", "]:443"}},
		{in: "2A02:A03F:6B4C:F100::1", masked: []string{"2A02:A03F"}},
		{in: "mapped ::ffff:81.246.12.7 here", masked: []string{"81.246.12.7", "ffff"}},
		{in: "mapped ::ffff:5af6:c07 here", masked: []string{"5af6"}},
		{in: "compat ::81.246.12.7", masked: []string{"81.246.12.7"}},
		{in: "end of sentence 2001:db8::7.", masked: []string{"2001:db8::7"}},
		{in: "ip=2001:db8:0:0:0:0:0:1:8080", masked: []string{"2001:db8:0:0"}},
	}
	for _, c := range cases {
		got := d.Mask(c.in)
		for _, m := range c.masked {
			if strings.Contains(got, m) {
				t.Errorf("ip.Mask(%q) = %q, still contains %q", c.in, got, m)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(got, k) {
				t.Errorf("ip.Mask(%q) = %q, lost %q", c.in, got, k)
			}
		}
	}
}

// Infrastructure addresses and address-like text stay in clear.
func TestIPKeeps(t *testing.T) {
	d := detector(t, "ip")
	for _, in := range []string{
		"10.0.0.1", "172.16.4.2", "192.168.1.10", "127.0.0.1", "169.254.169.254", "0.0.0.0",
		"255.255.255.255", "224.0.0.251", "240.1.2.3", "::1", "::", "fe80::1%eth0", "fd12:3456::1",
		"ff02::1", "fc00::5",
		"v1.2.3.4", "1.2.3.4.5", "version 10.0.19041.1", "1.2.3", "256.1.1.1", "1.2.3.4a", "a1.2.3.4",
		"12:30:45", "2026-10-30T14:02:11.204Z", "aa:bb:cc:dd:ee:ff", "00:1A:2B:3C:4D:5E",
		"std::string", "add::face", "dead:beef::1", "Foo::Bar::baz", "a::b",
		"sha 3f786850e387550fdab836ed7e6dc881de23001b", "uuid 123e4567-e89b-12d3-a456-426614174000",
		"took 1.234.567 ms", "list 1.5.2.0.1", "version=1.8.0.201", "oid 2.5.4.3", `"version":"5.15.0.91"`, "build 20.11.3.4",
	} {
		if got := d.Mask(in); got != in {
			t.Errorf("ip.Mask(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestIPHexDumpStaysLinear(t *testing.T) {
	in := strings.Repeat("ab:", DetectLimit/3) + " 203.0.113.9"
	got := detector(t, "ip").Mask(in)
	if strings.Contains(got, "203.0.113.9") {
		t.Error("address after a long hex run not masked")
	}
}

// Addresses glued to a long hex or colon run are still found.
func TestIPInsideLongRuns(t *testing.T) {
	d := detector(t, "ip")
	for _, in := range []string{
		strings.Repeat("deadbeef:", 12) + "203.0.113.9",
		strings.Repeat("ab:", 40) + "203.0.113.9 x",
		strings.Repeat("ab:", 40) + "2001:db8::7 x",
		"aa:bb:cc:dd:ee:ff:2001:db8::7",
		strings.Repeat("0", 80) + ":203.0.113.9",
	} {
		got := d.Mask(in)
		if strings.Contains(got, "203.0.113.9") || strings.Contains(got, "2001:db8::7") {
			t.Errorf("ip.Mask(%q) = %q", in, got)
		}
	}
}

// A canary address after any prefix is masked, or the prefix glues it
// into a word or a version (letter, digit or dot right before it).
func FuzzIPCanaryAfterPrefix(f *testing.F) {
	for _, s := range []string{"", "x:", strings.Repeat("ab:", 30), "::", "fe80::", "1.2.", "deadbeef"} {
		f.Add(s, false)
	}
	d, _ := Detectors([]string{"ip"})
	f.Fuzz(func(t *testing.T, pre string, v6 bool) {
		if len(pre) > 512 {
			return
		}
		canary := "203.0.113.77"
		if v6 {
			canary = "2001:db8:77::77"
		}
		if strings.Contains(pre, canary) {
			return
		}
		if b := before(pre+" ", len(pre)); isAlnum(b) || b == '.' || v6 && b == ':' {
			// "v203.0.113.77", "1.203.0.113.77", "ab::2001:db8:…": not
			// an address boundary; only a separator is checked.
			pre += " "
		}
		if !v6 && versionContext(pre+canary, len(pre)) {
			return // "version 203.0.113.77": a version by design
		}
		in := pre + canary + " end"
		out := d[0].Mask(in)
		if strings.Contains(out, canary) {
			t.Errorf("Mask(%q) = %q keeps %s", in, out, canary)
		}
	})
}
