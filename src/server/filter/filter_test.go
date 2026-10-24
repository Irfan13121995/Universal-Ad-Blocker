package filter

import (
	"fmt"
	"strings"
	"testing"
)

const sample = `
# hosts style
127.0.0.1 localhost
0.0.0.0 0.0.0.0
0.0.0.0 doubleclick.net ads.example.org # trailing comment
::1 ip6-localhost
! adblock comment
[Adblock Plus 2.0]
||tracker.example.com^
||thirdparty.example^$third-party
||withpath.example.com/ads.js
||unsupported.example.com^$script
@@||allowed.tracker.example.com^
example.com##.banner
/regex.*/
plain-domain.net
*.telemetry.microsoft.com
`

func build(t *testing.T) *Engine {
	t.Helper()
	b := NewBuilder(16)
	b.SetListName(1, "test")
	st, err := Parse(strings.NewReader(sample), func(r Rule) { b.Add(1, r) })
	if err != nil {
		t.Fatal(err)
	}
	if st.Rules != 7 {
		t.Fatalf("expected 7 rules, got %d (%+v)", st.Rules, st)
	}
	e := NewEngine()
	e.SetLists(b.Build())
	return e
}

func TestMatch(t *testing.T) {
	e := build(t)
	cases := map[string]bool{
		"doubleclick.net":                 true,
		"sub.doubleclick.net":             false, // hosts entries are exact
		"ads.example.org":                 true,
		"tracker.example.com":             true,
		"a.b.tracker.example.com":         true,
		"allowed.tracker.example.com":     false, // exception rule
		"x.allowed.tracker.example.com":   false,
		"thirdparty.example":              true,
		"withpath.example.com":            false,
		"unsupported.example.com":         false,
		"plain-domain.net":                true,
		"telemetry.microsoft.com":         false, // *.x does not include x
		"vortex.telemetry.microsoft.com":  true,
		"example.com":                     false,
		"localhost":                       false,
		"com":                             false,
		"notdoubleclick.net":              false,
	}
	for name, want := range cases {
		if got := e.Match(name).Blocked; got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestCustomPrecedence(t *testing.T) {
	e := build(t)
	e.SetCustomRules([]CustomRule{
		{ID: 1, Domain: "doubleclick.net", Action: "allow"},
		{ID: 2, Domain: "example.com", Action: "block", Subdomains: true},
		{ID: 3, Domain: "good.example.com", Action: "allow"},
	})
	if e.Match("doubleclick.net").Blocked {
		t.Error("custom allow should override list block")
	}
	if r := e.Match("www.example.com"); !r.Blocked || r.Reason != ReasonCustomBlock {
		t.Errorf("custom block with subdomains failed: %+v", r)
	}
	if !e.Match("example.com").Blocked {
		t.Error("custom block should include apex")
	}
	if e.Match("good.example.com").Blocked {
		t.Error("custom allow should beat custom block")
	}
	e.SetCustomRules(nil)
	if !e.Match("doubleclick.net").Blocked {
		t.Error("removing custom allow should re-block immediately")
	}
}

func TestNormalizeDomain(t *testing.T) {
	good := []string{"Example.COM.", "a_b.example.com", "xn--bcher-kva.example"}
	bad := []string{"", "localhost", "1.2.3.4", "a..b", "-", "exa mple.com", strings.Repeat("a", 64) + ".com"}
	for _, g := range good {
		if _, ok := NormalizeDomain(g, true); !ok {
			t.Errorf("expected %q to be valid", g)
		}
	}
	for _, b := range bad {
		if _, ok := NormalizeDomain(b, true); ok {
			t.Errorf("expected %q to be invalid", b)
		}
	}
}

func BenchmarkMatch(b *testing.B) {
	bl := NewBuilder(300000)
	for i := 0; i < 300000; i++ {
		bl.Add(1, Rule{Domain: fmt.Sprintf("ad%d.tracker%d.com", i, i%1000), Kind: DomainAndSubdomains})
	}
	e := NewEngine()
	e.SetLists(bl.Build())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Match("a.very.deep.sub.domain.of.something.example.com")
	}
}
