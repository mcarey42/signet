package trace

import (
	"bytes"
	"strings"
	"testing"
)

// Inert until switched on: the closure must not even run.
//
// This is what lets trace calls sit in hot paths like the authorization
// decision. If building an event cost anything when tracing was off, they would
// have to be removed from exactly the places they are most needed.
func TestInertWhenOff(t *testing.T) {
	Stop()
	called := false
	Do(AreaAuthz, "should.not.emit", func(e *Event) {
		called = true
		e.Str("k", "v")
	})
	if called {
		t.Fatal("the event builder ran while tracing was off")
	}
	if On(AreaAuthz) {
		t.Fatal("an area reported as traced while tracing was off")
	}
}

// Only the selected areas are recorded.
func TestAreasAreSelective(t *testing.T) {
	var buf bytes.Buffer
	if err := Start(&buf, nil, AreaAuthz); err != nil {
		t.Fatal(err)
	}
	defer Stop()

	Do(AreaAuthz, "wanted", func(e *Event) { e.Str("k", "yes") })
	Do(AreaStore, "unwanted", func(e *Event) { e.Str("k", "no") })

	out := buf.String()
	if !strings.Contains(out, "wanted") {
		t.Fatalf("the selected area was not recorded: %s", out)
	}
	if strings.Contains(out, "unwanted") {
		t.Fatalf("an unselected area was recorded: %s", out)
	}
}

// A redacted value must never reach the file, and equal values must produce
// equal digests so one credential can be followed through a trace.
func TestRedactionHidesValuesButPreservesEquality(t *testing.T) {
	var buf bytes.Buffer
	if err := Start(&buf, nil, AreaAttest); err != nil {
		t.Fatal(err)
	}
	defer Stop()

	secret := []byte("signet.a-real-bearer-token-value")
	other := []byte("signet.a-different-token")
	Do(AreaAttest, "first", func(e *Event) { e.Redact("evidence", secret) })
	Do(AreaAttest, "second", func(e *Event) { e.Redact("evidence", secret) })
	Do(AreaAttest, "third", func(e *Event) { e.Redact("evidence", other) })

	out := buf.String()
	if strings.Contains(out, "a-real-bearer-token-value") || strings.Contains(out, "a-different-token") {
		t.Fatalf("a redacted value reached the trace: %s", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 events, got %d", len(lines))
	}
	d1, d2, d3 := digestIn(t, lines[0]), digestIn(t, lines[1]), digestIn(t, lines[2])
	if d1 != d2 {
		t.Fatal("the same value produced different digests; a credential cannot be followed")
	}
	if d1 == d3 {
		t.Fatal("different values produced the same digest")
	}
	if !strings.HasPrefix(d1, "r:") {
		t.Fatalf("a digest should be marked as redacted, got %q", d1)
	}
}

// The salt is per-process, so a digest means nothing outside its own trace —
// including against a guessed value.
func TestDigestsDoNotCorrelateAcrossTraces(t *testing.T) {
	secret := []byte("the same secret both times")

	var a, b bytes.Buffer
	if err := Start(&a, nil, AreaAttest); err != nil {
		t.Fatal(err)
	}
	Do(AreaAttest, "x", func(e *Event) { e.Redact("v", secret) })
	Stop()

	if err := Start(&b, nil, AreaAttest); err != nil {
		t.Fatal(err)
	}
	Do(AreaAttest, "x", func(e *Event) { e.Redact("v", secret) })
	Stop()

	if digestIn(t, strings.TrimSpace(a.String())) == digestIn(t, strings.TrimSpace(b.String())) {
		t.Fatal("digests correlate across traces; the salt is not per-process")
	}
}

// An unknown area name is refused rather than silently tracing less than was
// asked for — a trace that quietly omits the area you needed is worse than one
// that refuses to start.
func TestUnknownAreaIsRefused(t *testing.T) {
	if _, err := ParseAreas("authz,not-an-area"); err == nil {
		t.Fatal("an unknown area was accepted")
	}
	got, err := ParseAreas("all")
	if err != nil || len(got) != len(AllAreas) {
		t.Fatalf(`"all" should expand to every area: %v %v`, got, err)
	}
}

func digestIn(t *testing.T, line string) string {
	t.Helper()
	for _, part := range strings.Split(line, `"`) {
		if strings.HasPrefix(part, "r:") {
			return part
		}
	}
	t.Fatalf("no redacted digest in %q", line)
	return ""
}
