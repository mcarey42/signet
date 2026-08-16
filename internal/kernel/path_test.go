package kernel

import "testing"

func TestValidatePath(t *testing.T) {
	valid := []string{
		"/", "/people/mcarey", "/clusters/svc/apps/eso",
		"/secrets/cluster-svc/apps/litellm", "/a.b_c-d/e",
	}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}

	invalid := map[string]string{
		"":                   "empty",
		"people/mcarey":      "relative",
		"/people/":           "trailing slash",
		"/people//mcarey":    "empty segment",
		"/people/.":          "dot segment",
		"/people/../root":    "parent segment",
		"/People/Mcarey":     "uppercase (case-confusable)",
		"/people/andré":      "non-ascii (unicode-confusable)",
		"/people/has space":  "space",
		"/people/semi;colon": "punctuation outside the grammar",
		"/people/tab\tchar":  "control character",
		"/people/star*":      "wildcard character",
	}
	for p, why := range invalid {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) = nil, want rejection (%s)", p, why)
		}
	}
}

func TestScopeCoversIsComponentWise(t *testing.T) {
	cases := []struct {
		scope, path string
		want        bool
	}{
		{"/", "/anything/at/all", true},
		{"/", "/", true},
		{"/clusters/lab", "/clusters/lab", true},
		{"/clusters/lab", "/clusters/lab/apps/runner", true},
		// The bug this test exists for: substring prefixes are not scopes.
		{"/clusters/lab", "/clusters/lab-2", false},
		{"/clusters/lab", "/clusters/lab-2/apps/x", false},
		{"/clusters/lab", "/clusters", false},
		{"/clusters/lab/apps", "/clusters/lab", false},
		{"/secrets/a", "/secrets/ab", false},
	}
	for _, c := range cases {
		if got := ScopeCovers(c.scope, c.path); got != c.want {
			t.Errorf("ScopeCovers(%q, %q) = %v, want %v", c.scope, c.path, got, c.want)
		}
	}
}
