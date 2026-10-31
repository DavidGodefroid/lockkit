package pii

import (
	"bufio"
	"os"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"
)

// Fake credentials, built at run time so that no secret scanner flags this
// file.
var (
	fakeJWT    = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + ".eyJzdWIiOiIxMjM0NTY3ODkwIn0" + ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	fakeAWS    = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeGH     = "ghp_" + strings.Repeat("aB3dE6gH9j", 4)
	fakeSlack  = "xoxb-" + "1234567890-0987654321-AbCdEfGhIjKl"
	fakeStripe = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"
	fakeGoogle = "AIza" + "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"
	fakeOpenAI = "sk-proj-" + "Ab12Cd34Ef56Gh78Ij90Kl12Mn34"
	fakeRandom = "Zq8Lr2Vt6Wn0Yp4Xs7Ub1Tc5Ra9Qd3Me"
	fakeBasic  = "dXNlcjpodW50ZXIy" // user:hunter2
	pemKey     = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7bq\nabc123\n-----END RSA PRIVATE KEY-----"
)

func TestSecretMasks(t *testing.T) {
	d := detector(t, "secret")
	cases := []struct {
		in     string
		masked []string
		kept   []string
	}{
		// Headers.
		{in: "Authorization: Bearer " + fakeJWT, masked: []string{"eyJhbGci", "dozjg"}, kept: []string{"Authorization: Bearer "}},
		{in: "authorization: Bearer abc123def456", masked: []string{"abc123def456"}, kept: []string{"Bearer"}},
		{in: "Proxy-Authorization: Basic " + fakeBasic, masked: []string{fakeBasic}, kept: []string{"Proxy-Authorization: Basic "}},
		{in: "Authorization: Digest username=\"bob\", response=\"6629fae49393a05397450978507c4ef1\"", masked: []string{"username=", "bob"}},
		{in: "Cookie: session=AbC123; theme=dark; csrftoken=Zz9", masked: []string{"AbC123", "theme=dark", "Zz9"}, kept: []string{"Cookie: "}},
		{in: "Set-Cookie: sid=31d4d96e407aad42; Path=/; Secure\nnext line", masked: []string{"31d4d96e407aad42"}, kept: []string{"Set-Cookie: ", "next line"}},
		{in: "X-Api-Key: k3y-v4lu3-1234", masked: []string{"k3y-v4lu3-1234"}, kept: []string{"X-Api-Key: "}},
		{in: "X-Auth-Token: tok_abc", masked: []string{"tok_abc"}},
		{in: "Ocp-Apim-Subscription-Key: 0123abcd", masked: []string{"0123abcd"}},
		{in: `{"headers":{"authorization":"Bearer t0ken.value.123","accept":"*/*"}}`, masked: []string{"t0ken.value.123"}, kept: []string{`"authorization":"Bearer `, `"accept":"*/*"`}},
		{in: `msg="{\"password\":\"hunter2\",\"user\":\"bob\"}"`, masked: []string{"hunter2"}, kept: []string{`\"user\":\"bob\"`}},
		// Pairs.
		{in: "password=hunter2 user=bob", masked: []string{"hunter2"}, kept: []string{"password=", " user=bob"}},
		{in: `{"password": "hunter 2 with spaces", "ok": true}`, masked: []string{"hunter 2"}, kept: []string{`"ok": true`}},
		{in: `{"pass":"x\"y\"z","n":1}`, masked: []string{`x\"y\"z`}, kept: []string{`"n":1`}},
		{in: "client_secret=s3cr3t&grant_type=client_credentials", masked: []string{"s3cr3t"}, kept: []string{"grant_type=client_credentials"}},
		{in: "GET /cb?code=abc&access_token=Ya29abc&state=x", masked: []string{"Ya29abc"}, kept: []string{"state=x", "code=abc"}},
		{in: "api_key: 'k-123'", masked: []string{"k-123"}},
		{in: "apiKey=abcdef123", masked: []string{"abcdef123"}},
		{in: "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", masked: []string{"wJalrXUtnFEMI"}},
		{in: "Server=db;User Id=sa;Password=P@ss;Database=x", masked: []string{"P@ss"}, kept: []string{"Database=x"}},
		{in: "wachtwoord=geheim mot_de_passe=secret2 passwort=geheim2", masked: []string{"=geheim ", "secret2", "geheim2"}},
		{in: "db_pwd=xyz", masked: []string{"xyz"}},
		{in: "token=" + fakeRandom, masked: []string{fakeRandom}},
		{in: "--password=hunter2 --password hunter3 --api-token tok9", masked: []string{"hunter2", "hunter3", "tok9"}},
		// High entropy in a key position.
		{in: "x_custom=" + fakeRandom, masked: []string{fakeRandom}},
		{in: `"blob": "` + fakeRandom + `"`, masked: []string{fakeRandom}},
		// Shapes, anywhere.
		{in: "jwt " + fakeJWT + " end", masked: []string{"eyJhbGci"}, kept: []string{"jwt ", " end"}},
		{in: "key " + fakeAWS, masked: []string{fakeAWS}},
		{in: "push with " + fakeGH, masked: []string{fakeGH}},
		{in: "slack " + fakeSlack, masked: []string{fakeSlack}},
		{in: "https://hooks." + "slack.com/services/" + "T00000000/B00000000/" + strings.Repeat("X", 24), masked: []string{"XXXXXXXX"}, kept: []string{"https://hooks.slack.com/"}},
		{in: "stripe " + fakeStripe, masked: []string{fakeStripe}},
		{in: "google " + fakeGoogle, masked: []string{fakeGoogle}},
		{in: "openai " + fakeOpenAI, masked: []string{fakeOpenAI}},
		{in: "glpat-" + "aBcD1234eFgH5678iJkL", masked: []string{"aBcD1234"}},
		{in: "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=" + strings.Repeat("Ab1+", 22) + "==;EndpointSuffix=core.windows.net", masked: []string{"Ab1+"}, kept: []string{"AccountName=x", "EndpointSuffix"}},
		// PEM.
		{in: "key:\n" + pemKey + "\nafter", masked: []string{"MIIEow", "abc123", "BEGIN RSA"}, kept: []string{"after"}},
		{in: `"key":"-----BEGIN PRIVATE KEY-----\nMIIEvQ` + `IBADANBg"`, masked: []string{"MIIEvQ"}},
		{in: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk", masked: []string{"b3BlbnNzaC1rZXk"}},
		// URL userinfo, curl, mysql.
		{in: "dial postgres://app:s3cret@db.internal:5432/shop", masked: []string{"app:s3cret"}, kept: []string{"postgres://", "@db.internal:5432/shop"}},
		{in: "redis://:pa55@cache:6379", masked: []string{"pa55"}},
		{in: "curl -u admin:hunter2 https://x", masked: []string{"admin:hunter2"}},
		{in: "curl --user admin:pw https://x", masked: []string{"admin:pw"}},
		{in: "mysql -h db -uroot -phunter2 shop", masked: []string{"hunter2"}, kept: []string{"-uroot", "shop"}},
		// Schemes in prose.
		{in: "sent Bearer abcdefgh1234 upstream", masked: []string{"abcdefgh1234"}, kept: []string{"Bearer ", " upstream"}},
		{in: "using basic " + fakeBasic, masked: []string{fakeBasic}},
	}
	for _, c := range cases {
		got := d.Mask(c.in)
		for _, m := range c.masked {
			if strings.Contains(got, m) {
				t.Errorf("secret.Mask(%q) = %q, still contains %q", c.in, got, m)
			}
		}
		for _, k := range c.kept {
			if !strings.Contains(got, k) {
				t.Errorf("secret.Mask(%q) = %q, lost %q", c.in, got, k)
			}
		}
		if got != c.in && !strings.Contains(got, Redacted) {
			t.Errorf("secret.Mask(%q) = %q, not masked as %s", c.in, got, Redacted)
		}
	}
}

// The benign corpus: log lines with versions, hashes, ids, timestamps,
// metadata about credentials and prose about authentication. Neither the
// secret nor the ip detector may change one.
func TestSecretAndIPFalsePositiveCorpus(t *testing.T) {
	f, err := os.Open("testdata/benign-log-lines.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	ds, err := Detectors([]string{"secret", "ip"})
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(f)
	n := 0
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n++
		for _, d := range ds {
			if got := d.Mask(line); got != line {
				t.Errorf("%s.Mask(%q) = %q, want unchanged", d.Name(), line, got)
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("corpus has %d lines, want at least 100", n)
	}
}

func TestLooksSecret(t *testing.T) {
	for name, want := range map[string]bool{
		"password": true, "Password": true, "user_password": true, "passwd": true, "PASS": true,
		"secret": true, "client_secret": true, "clientSecret": true, "token": true, "access_token": true,
		"accessToken": true, "refresh_token": true, "id_token": true, "api_key": true, "apiKey": true,
		"APIKEY": true, "X-Api-Key": true, "X-Goog-Api-Key": true, "private_key": true, "secret_key": true,
		"aws_secret_access_key": true, "Authorization": true, "Proxy-Authorization": true, "Cookie": true,
		"Set-Cookie": true, "credentials": true, "PHPSESSID": true, "JSESSIONID": true, "sessionid": true,
		"auth": true, "basic_auth": true, "db_pwd": true, "mot_de_passe": true, "motDePasse": true,
		"wachtwoord": true, "Passwort": true, "contraseña": true, "--password": true, "tokens": false,
		"csrf_token": true, "otp": true, "sig": true, "hmac_key": true, "webhook_secret": true,

		"token_type": false, "token_count": false, "max_tokens": false, "prompt_tokens": false,
		"completion_tokens": false, "total_tokens": false, "password_changed_at": false,
		"password_policy": false, "access_token_ttl": false, "token_endpoint": false, "secret_name": false,
		"api_key_id": false, "auth_method": false, "auth_type": false, "password_reset_sent_at": false,
		"cookie_consent": false, "PWD": false, "OLDPWD": false, "key": false, "cache_key": false,
		"primary_key": false, "sort_key": false, "keyboard": false, "passenger": false, "bypass": false,
		"user": false, "email": false, "status": false, "token_file": false, "secrets_manager": false,
		"": false, "pass_count": false,
	} {
		if got := LooksSecret(name); got != want {
			t.Errorf("LooksSecret(%q) = %v, want %v", name, got, want)
		}
	}
}

// Secrets run first: a password in a URL is redacted, not masked as an
// e-mail address, and a later detector never sees it.
func TestSecretRunsFirst(t *testing.T) {
	ds, err := Detectors([]string{"email", "ip", "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if ds[0].Name() != "secret" {
		t.Fatalf("first detector %s, want secret", ds[0].Name())
	}
	got := Detect("smtp://bob:hunter2@mail.example.com from 203.0.113.9", ds)
	s, _ := got.(string)
	for _, leak := range []string{"hunter2", "bob:", "203.0.113.9"} {
		if strings.Contains(s, leak) {
			t.Errorf("Detect = %q, still contains %q", s, leak)
		}
	}
}

// The opt-in detectors are not in AllDetectors: a product upgrading
// lockkit masks what it masked before until it names them.
func TestAllDetectorsLeavesOptInOut(t *testing.T) {
	for _, d := range AllDetectors() {
		if optInDetectors[d.Name()] {
			t.Errorf("AllDetectors includes opt-in %s", d.Name())
		}
	}
}

// A secret's mask carries neither its first character nor its length.
// A key at the very end of the text, with no value, is no crash.
func TestSecretKeyAtEnd(t *testing.T) {
	d := detector(t, "secret")
	for _, in := range []string{"Cookie:", "password=", "Authorization: ", "--password", "x=password:", "Bearer", "mysql -p", `"token":`, `\"`} {
		_ = d.Mask(in)
	}
}

func TestSecretMaskCarriesNothing(t *testing.T) {
	d := detector(t, "secret")
	a := d.Mask("password=a")
	b := d.Mask("password=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	if a != b || a != "password="+Redacted {
		t.Errorf("Mask = %q and %q, want both password=%s", a, b, Redacted)
	}
}

func TestSecretLongValuesStayBounded(t *testing.T) {
	d := detector(t, "secret")
	in := `password="` + strings.Repeat("x", 2*DetectLimit)
	if got := d.Mask(in); strings.Contains(got, "xxxx") {
		t.Errorf("a long unterminated secret kept %d bytes in clear", strings.Count(got, "x"))
	}
}

// Inputs built to make the secret and ip detectors read a byte many times
// stay linear.
func TestSecretPathologicalInputs(t *testing.T) {
	ds, err := Detectors([]string{"secret", "ip"})
	if err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{
		"long keys":   strings.Repeat(strings.Repeat("x", 65)+"=", DetectLimit/66),
		"dotted keys": strings.Repeat(strings.Repeat("a.", 32)+"a=", DetectLimit/67),
		"cookie args": strings.Repeat("'Cookie:x'", DetectLimit/10),
		"auth args":   strings.Repeat(`"Authorization: Bearer `, DetectLimit/23),
		"pairs":       strings.Repeat("a=", DetectLimit/2),
		"secret keys": strings.Repeat("password=", DetectLimit/9),
		"quotes":      strings.Repeat(`x="`, DetectLimit/3),
		"tokens":      strings.Repeat("k="+fakeRandom[:31]+" ", DetectLimit/40),
		"aws4":        strings.Repeat("AWS4-HMAC-SHA256 ", DetectLimit/17),
		"bearer":      strings.Repeat("Bearer ", DetectLimit/7),
		"mysql":       strings.Repeat("mysql ", DetectLimit/6),
		"pem":         strings.Repeat("-----BEGIN PRIVATE KEY-----", DetectLimit/27),
		"urls":        strings.Repeat("a://b:", DetectLimit/6),
		"flags":       strings.Repeat("--password ", DetectLimit/11),
		"colons":      strings.Repeat("1:", DetectLimit/2),
		"dots":        strings.Repeat("1.", DetectLimit/2),
		"jwt-like":    strings.Repeat("eyJ", DetectLimit/3),
	}
	for name, in := range inputs {
		start := time.Now()
		Detect(in, ds)
		if d := time.Since(start); d > 500*time.Millisecond {
			t.Errorf("%s: %v over %d bytes", name, d, len(in))
		}
	}
}

// A credential appended to any text is masked: what comes before it can
// neither swallow it into a value left in clear nor hide it.
func FuzzSecretMasksAppendedCredential(f *testing.F) {
	for _, s := range []string{"", `password="`, "x=", `{"a":"`, "\\", "-----BEGIN", "Bearer", "mysql -p", "\u00a0"} {
		f.Add(s)
	}
	ds, _ := Detectors([]string{"secret", "ip"})
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 4096 {
			return
		}
		for _, c := range []struct{ tail, secret string }{
			{"\nAuthorization: Bearer " + fakeRandom + "\n", fakeRandom},
			{"\npassword=" + fakeRandom + "\n", fakeRandom},
			{"\n" + fakeJWT + "\n", fakeJWT[10:30]},
			{" https://" + fakeGH + "@h", fakeGH},
			{"/" + fakeJWT, fakeJWT[40:60]},
			{"=" + fakeAWS, fakeAWS},
		} {
			in := s + c.tail
			out, _ := Detect(in, ds).(string)
			if strings.Count(out, c.secret) > strings.Count(s, c.secret) {
				t.Errorf("Detect(%q) = %q keeps the appended credential", in, out)
			}
		}
	})
}

// Bypasses found in review: a credential is found wherever its key sits
// (inside another value, after a separator), whatever its quoting and the
// blanks around it.
func TestSecretReviewBypasses(t *testing.T) {
	d := detector(t, "secret")
	for in, leak := range map[string]string{
		"x: password=hunter2":                                                "hunter2",
		"a=password=hunter2":                                                 "hunter2",
		`msg="password=hunter2"`:                                             "hunter2",
		`msg="login ok" password=hunter2`:                                    "hunter2",
		"key=" + fakeGH:                                                      fakeGH,
		"a:" + fakeAWS:                                                       fakeAWS,
		"url=/x/" + fakeStripe:                                               fakeStripe,
		`--password "s3cr3t value"`:                                          "s3cr3t",
		`--token 'tok123'`:                                                   "tok123",
		`run --name x --password "p w"`:                                      "p w",
		`mysql -uroot -p"pass word" shop`:                                    "pass word",
		`mysql -uroot -p'pa ss' shop`:                                        "pa ss",
		`Cookie: a="b"; session=SECRET1`:                                     "SECRET1",
		`Set-Cookie: x="y"; sid=SECRET1; Path=/`:                             "SECRET1",
		"password=    SECRET2":                                               "SECRET2",
		"password=\t\t\t\t\tSECRET3":                                         "SECRET3",
		"password    =    SECRET4":                                           "SECRET4",
		"Bearer Bearer abcdef123456":                                         "abcdef123456",
		"docker login -u bob -p hunter2 registry.example.com":                "hunter2",
		"podman login -u bob -p=hunter2 quay.io":                             "hunter2",
		"mongosh -u admin -p hunter2 mongodb://db":                           "hunter2",
		"MAILER_DSN=smtp://bob@example.com:hunter2@smtp.example.com:465":     "hunter2",
		"user=admin pass=123456 host=ftp":                                    "123456",
		"curl --user=bob:hunter2 https://api.example.com":                    "hunter2",
		"curl -s https://example.com/dump.sql | mysql -uroot -phunter2 shop": "hunter2",
		"mysqldump -uroot -px shop | curl -T - -ubob:pw77 ftp://x/":          "pw77",
		`mysql -uroot -p"pa;ss" shop`:                                        "pa;ss",
		`mysql -uroot -p'pa|ss' shop`:                                        "pa|ss",
		"sessionId=AbCdEf123456":                                             "AbCdEf123456",
		`"sessionId":"s3cr3t-sess"`:                                          "s3cr3t-sess",
		"session_id=abc123":                                                  "abc123",
		"contraseña=abcxyz":                                                  "abcxyz",
		`{"name":"DB_PASSWORD","value":"hunter2"}`:                           "hunter2",
		`curl -H "Authorization: Bearer abcdefgh" x`:                         "abcdefgh",
		`curl -H "Authorization: Token abcdefgh9" x`:                         "abcdefgh9",
		`curl -H "Proxy-Authorization: Digest username=\"a\", response=\"6629fae4\"" x`: "6629fae4",
		`curl -H "Cookie: theme=dark; session=SECRETVALUE" x`:                           "SECRETVALUE",
		`curl -H 'Cookie: a=1; sid=SECRETVALUE' x`:                                      "SECRETVALUE",
		`{"password"=>"hunter2"}`:                                                       "hunter2",
		`{:password=>"hunter2"}`:                                                        "hunter2",
		`'password' => 'hunter2'`:                                                       "hunter2",
		"[password] => hunter2":                                                         "hunter2",
		"curl -ubob:hunter2 x":                                                          "hunter2",
		"session=SECRETVALUE laravel_session=SECRET2":                                   "SECRET",
		"git clone https://" + fakeGH + "@github.com/o/r.git":                           fakeGH,
		"next=/login/" + fakeJWT:                                                        fakeJWT[40:60],
		"https://example.com/cb/" + fakeSlack:                                           fakeSlack,
		"path=/hooks/" + fakeOpenAI:                                                     fakeOpenAI,
		"file:///home/u/" + fakeAWS:                                                     fakeAWS,
		"url=/api/v1?x=" + fakeStripe:                                                   fakeStripe,
		"PGPASSWORD=hunter2 psql -h db":                                                 "hunter2",
		"DBPASS_WORD=x GITHUBTOKEN=tok77":                                               "tok77",
		"postgres://app:p@ss@db.example.com/x":                                          "ss@db",
		"postgres://app:pa/ss@db/x":                                                     "pa/ss",
		`"authorization": \"Bearer tok123456\"`:                                         "tok123456",
	} {
		if got := d.Mask(in); strings.Contains(got, leak) {
			t.Errorf("secret.Mask(%q) = %q, keeps %q", in, got, leak)
		}
	}
}

// A differential fuzz over the shapes a credential pair takes: key,
// separator, blanks, quoting and what precedes it. The canary never
// survives.
func FuzzSecretPairVariants(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), uint8(0), uint8(0), "x")
	f.Add(uint8(3), uint8(1), uint8(5), uint8(2), uint8(4), "a=")
	keys := []string{"password", "client_secret", "api_key", "X-Api-Key", "access_token", "--password", "Authorization", "Cookie", "db_pwd", `\"password\"`, `"token"`, "'secret'"}
	seps := []string{"=", ":", " = ", ": ", "=\t\t\t\t\t", ":      "}
	quotes := []string{"", `"`, "'", `\"`}
	prefixes := []string{"", " ", "x: ", "a=", `msg="`, "{", ",", "\t", "&", "?", "; ", "k=v "}
	f.Fuzz(func(t *testing.T, ki, si, qi, pi, ti uint8, pre string) {
		if len(pre) > 256 || strings.ContainsAny(pre, "\n\r") {
			return
		}
		key, sep, q, p := keys[int(ki)%len(keys)], seps[int(si)%len(seps)], quotes[int(qi)%len(quotes)], prefixes[int(pi)%len(prefixes)]
		canary := "Kq7Canary" + string(rune('A'+ti%26)) + "Zx"
		r, _ := utf8.DecodeLastRuneInString(pre)
		if n := len(pre); p == "" && n > 0 && (isAlnum(pre[n-1]) || strings.IndexByte(".-\\", pre[n-1]) >= 0 || unicode.IsLetter(r) || unicode.IsDigit(r)) {
			p = " " // "xpassword" is another key
		}
		in := pre + p + key + sep + q + canary + q + " tail"
		out, _ := Detect(in, mustDetectors(t, "secret")).(string)
		if strings.Contains(out, canary) && !strings.Contains(pre, canary) {
			t.Errorf("Detect(%q) = %q keeps the canary", in, out)
		}
	})
}

func mustDetectors(t *testing.T, names ...string) []Detector {
	ds, err := Detectors(names)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}
