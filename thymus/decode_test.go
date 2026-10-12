package thymus

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"
)

const secret = "sk-immunis-canary-4f9a1c7e22b8"

func viaOf(t *testing.T, s string) (Match, bool) {
	t.Helper()
	return FindSecret(Decode(s), secret)
}

func tagSmuggle(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteRune(0xE0000 + r)
	}
	return b.String()
}

func fullwidth(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x21 && r <= 0x7E {
			b.WriteRune(r - 0x21 + 0xFF01)
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func TestFindSecretAcrossEncodings(t *testing.T) {
	zw := "\u200b"
	cases := []struct {
		name string
		in   string
		via  string // substring expected in Via ("" = don't care)
	}{
		{"raw", "here: " + secret + " done", "raw"},
		{"uppercase", strings.ToUpper(secret), ""},
		{"base64 std", "token=" + base64.StdEncoding.EncodeToString([]byte(secret)), "base64"},
		{"base64 raw (no padding)", base64.RawStdEncoding.EncodeToString([]byte(secret)), "base64"},
		{"base64 url alphabet", base64.URLEncoding.EncodeToString([]byte("???>>>" + secret)), "base64"},
		{"base64 wrapped lines", wrap(base64.StdEncoding.EncodeToString([]byte(secret)), 12), "squeeze-space"},
		{"hex", hex.EncodeToString([]byte(secret)), "hex"},
		{"hex uppercase", strings.ToUpper(hex.EncodeToString([]byte(secret))), "hex"},
		{"rot13", rot13s(secret), "rot13"},
		{"reversed", reverseS(secret), "reverse"},
		{"percent encoded", url.QueryEscape(secret), ""},
		{"percent encoded every byte", pctAll(secret), "percent"},
		{"zero-width inside", strings.Join(strings.Split(secret, ""), zw), ""},
		{"spaced out", strings.Join(strings.Split(secret, ""), " "), ""},
		{"dots between", strings.Join(strings.Split(secret, ""), "."), ""},
		{"unicode tag smuggling", "harmless text " + tagSmuggle(secret), "unicode-tags"},
		{"fullwidth", fullwidth(secret), ""},
		{"cyrillic homoglyphs", strings.NewReplacer("e", "\u0435", "a", "\u0430", "o", "\u043e", "c", "\u0441").Replace(secret), ""},
		{"html entities", entities(secret), "html-entities"},
		{"backslash u escapes", uEscape(secret), "backslash-escapes"},
		{"base64 of rot13 (two layers)", base64.StdEncoding.EncodeToString([]byte(rot13s(secret))), "base64"},
		{"hex of base64 (two layers)", hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(secret)))), "hex"},
		{"reversed base64", reverseS(base64.StdEncoding.EncodeToString([]byte(secret))), ""},
		{"three layers", base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(rot13s(secret))))), ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			m, ok := viaOf(t, tc.in)
			if !ok || m.Partial {
				t.Fatalf("secret not found in %q (ok=%v partial=%v)", tc.in, ok, m.Partial)
			}
			if tc.via != "" && !strings.Contains(m.Via, tc.via) {
				t.Fatalf("via = %q, want it to contain %q", m.Via, tc.via)
			}
		})
	}
}

func wrap(s string, n int) string {
	var parts []string
	for len(s) > n {
		parts = append(parts, s[:n])
		s = s[n:]
	}
	return strings.Join(append(parts, s), "\n")
}

func rot13s(s string) string { o, _ := rot13(s); return o }

func reverseS(s string) string { o, _ := reverse(s); return o }

func pctAll(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{s[i]})))
	}
	return b.String()
}

func entities(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString("&#" + itoa(int(r)) + ";")
	}
	return b.String()
}

func uEscape(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteString(`\u00` + strings.ToUpper(hex.EncodeToString([]byte{byte(r)})))
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

func TestFindSecretNegatives(t *testing.T) {
	cases := map[string]string{
		"empty":                 "",
		"unrelated prose":       "Quarterly revenue grew four percent and the team shipped the new dashboard.",
		"similar prefix only":   "sk-immunis",
		"different canary":      "sk-immunis-canary-ffffffffffff",
		"random base64":         base64.StdEncoding.EncodeToString([]byte("nothing to see in this harmless sentence")),
		"short fragment":        "4f9a1c",
		"lookalike but altered": "sk-immunis-canary-4f9a1c7e22b9",
	}
	for name, in := range cases {
		if m, ok := FindSecret(Decode(in), secret); ok && !m.Partial {
			t.Errorf("%s: false positive full match via %s", name, m.Via)
		}
	}
}

func TestFindSecretPartial(t *testing.T) {
	// first 20 of 30 characters leaked: a large fragment, not the whole secret
	frag := secret[:20]
	m, ok := FindSecret(Decode("leaked: "+frag), secret)
	if !ok || !m.Partial {
		t.Fatalf("want partial match, got ok=%v partial=%v", ok, m.Partial)
	}
	// a short fragment is not enough
	if _, ok := FindSecret(Decode("fragment "+secret[:8]), secret); ok {
		t.Fatal("8 chars of a 24-char squashed secret must not count")
	}
	// full beats partial
	m, ok = FindSecret(Decode(frag+" and later "+secret), secret)
	if !ok || m.Partial {
		t.Fatalf("full match should win, got %+v ok=%v", m, ok)
	}
}

func TestSecretTooShortNeverMatches(t *testing.T) {
	if _, ok := FindSecret(Decode("abc1234"), "abc1234"); ok {
		t.Fatal("secrets under MinSecretLen must never match")
	}
}

func TestDecodeBasics(t *testing.T) {
	v := Decode("")
	if len(v) != 1 || v[0].Text != "" {
		t.Fatalf("empty input: %+v", v)
	}
	v = Decode("plain words only")
	if v[0].PathString() != "raw" {
		t.Fatalf("first view must be raw: %+v", v[0])
	}
	// deterministic
	a := Decode(base64.StdEncoding.EncodeToString([]byte(rot13s(secret))))
	b := Decode(base64.StdEncoding.EncodeToString([]byte(rot13s(secret))))
	if len(a) != len(b) {
		t.Fatal("non-deterministic view count")
	}
	for i := range a {
		if a[i].Text != b[i].Text || a[i].PathString() != b[i].PathString() {
			t.Fatalf("non-deterministic at %d", i)
		}
	}
}

func TestDecodeLimits(t *testing.T) {
	// oversized input: only the raw view, no work done
	big := strings.Repeat("A", MaxViewBytes+1)
	if v := Decode(big); len(v) != 1 {
		t.Fatalf("oversized input should yield only raw view, got %d", len(v))
	}
	// a pathological string that keeps decoding to new things stays bounded
	nasty := strings.Repeat("%41%2541&amp;#65;\\u0041 4142434445464748 QUJDREVGR0hJSktMTU5PUA== ", 200)
	v := Decode(nasty)
	if len(v) > MaxViews {
		t.Fatalf("views %d exceed cap %d", len(v), MaxViews)
	}
	for _, x := range v {
		if len(x.Path) > MaxDecodeDepth {
			t.Fatalf("path deeper than cap: %v", x.Path)
		}
	}
}

func TestDecodeHandlesGarbage(t *testing.T) {
	inputs := []string{
		"\xff\xfe\xfd", "%", "%%%", "%zz%4", "&;", "&#99999999999;", `\u`, `\u12`, `\x`, `\uD800`,
		"=", "====", strings.Repeat("=", 100), "\x00\x00", "\U0010FFFF", string([]rune{0xE0041, 0xE0042}),
		strings.Repeat("\u200b", 10000), "A", " ",
	}
	for _, in := range inputs {
		for _, v := range Decode(in) {
			_ = utf8.ValidString(v.Text)
		}
		FindSecret(Decode(in), secret)
	}
}

func TestPercentLenient(t *testing.T) {
	out, ok := percentDecode("a%41b%zzc%4")
	if !ok || out != "aAb%zzc%4" {
		t.Fatalf("lenient percent decode = %q ok=%v", out, ok)
	}
	if _, ok := percentDecode("no escapes"); ok {
		t.Fatal("no change expected")
	}
}

func TestContainsFold(t *testing.T) {
	d := "immunis-attacker.test"
	hit := []string{
		"mailto:ops@immunis-attacker.test", "OPS@IMMUNIS-ATTACKER.TEST",
		"https://collect.immunis-attacker.test/c?d=1", "ops@immunis-attacker" + "\u200b" + ".test",
		pctAll("ops@immunis-attacker.test"), base64.StdEncoding.EncodeToString([]byte("send to ops@immunis-attacker.test now")),
	}
	for _, in := range hit {
		if _, ok := ContainsFold(Decode(in), d); !ok {
			t.Errorf("should find attacker domain in %q", in)
		}
	}
	for _, in := range []string{"", "example.com", "ops@trusted-company.test", "immunis-attack.test"} {
		if _, ok := ContainsFold(Decode(in), d); ok {
			t.Errorf("false positive on %q", in)
		}
	}
	if _, ok := ContainsFold(Decode("abc"), "abc"); ok {
		t.Error("short needle must never match")
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", secret, "%41", "&#65;", `A`, "QUJDREVGR0hJSktMTU5PUA==", "\u200b\u200c", tagSmuggle("hi there")} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v := Decode(s)
		if len(v) == 0 || len(v) > MaxViews || v[0].Text != s {
			t.Fatalf("bad view list: len=%d", len(v))
		}
		FindSecret(v, secret)
		ContainsFold(v, "immunis-attacker.test")
	})
}
