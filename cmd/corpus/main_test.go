package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	exAttacks = "../../corpus/testdata/example-attacks.jsonl"
	exBenign  = "../../corpus/testdata/example-benign.jsonl"
)

func do(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestUsageAndUnknown(t *testing.T) {
	if code, _, e := do(t); code != 2 || !strings.Contains(e, "usage") {
		t.Errorf("no args: %d %q", code, e)
	}
	if code, o, _ := do(t, "help"); code != 0 || !strings.Contains(o, "verify-holdout") {
		t.Errorf("help: %d %q", code, o)
	}
	if code, _, e := do(t, "frobnicate"); code != 2 || !strings.Contains(e, "unknown command") {
		t.Errorf("unknown: %d %q", code, e)
	}
}

func TestLintExample(t *testing.T) {
	code, out, _ := do(t, "lint", "-attacks", exAttacks, "-benign", exBenign)
	if code != 0 {
		t.Fatalf("example corpus has errors (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "0 error(s)") || !strings.Contains(out, "3 attacks, 3 benign twins") {
		t.Errorf("unexpected report:\n%s", out)
	}
	if code, _, _ := do(t, "lint", "-strict", "-attacks", exAttacks, "-benign", exBenign); code != 1 {
		t.Errorf("strict lint of a thin corpus must fail, got %d", code)
	}
	if code, _, _ := do(t, "lint", "-strict", "-min-attacks", "1", "-min-seeds", "0", "-min-twins", "1", "-attacks", exAttacks, "-benign", exBenign); code != 0 {
		t.Errorf("relaxed thresholds should pass strict, got %d", code)
	}
}

func TestLintInputErrors(t *testing.T) {
	if code, _, e := do(t, "lint"); code != 2 || !strings.Contains(e, "-attacks is required") {
		t.Errorf("%d %q", code, e)
	}
	if code, _, _ := do(t, "lint", "-attacks", "nope.jsonl"); code != 2 {
		t.Errorf("missing file: %d", code)
	}
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(bad, []byte("{broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, _ := do(t, "lint", "-attacks", bad); code != 1 || !strings.Contains(out, "bad.jsonl:1") {
		t.Errorf("bad record: %d %q", code, out)
	}
}

func TestTwins(t *testing.T) {
	// The example has every twin but fewer than fifteen overall.
	code, out, _ := do(t, "twins", "-attacks", exAttacks, "-benign", exBenign)
	if code != 1 || !strings.Contains(out, "3 seed attacks, 3 with a twin; 3 benign twins (need >= 15)") {
		t.Errorf("%d\n%s", code, out)
	}
	if code, _, _ := do(t, "twins", "-min-twins", "3", "-attacks", exAttacks, "-benign", exBenign); code != 0 {
		t.Errorf("want 0 with min-twins 3, got %d", code)
	}
	empty := filepath.Join(t.TempDir(), "b.jsonl")
	if err := os.WriteFile(empty, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = do(t, "twins", "-min-twins", "0", "-attacks", exAttacks, "-benign", empty)
	if code != 1 || strings.Count(out, "MISSING TWIN") != 3 {
		t.Errorf("want 3 missing twins:\n%s", out)
	}
}

func TestSplitAndVerifyEndToEnd(t *testing.T) {
	out := filepath.Join(t.TempDir(), "build")
	code, so, se := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-holdout", "social", "-out", out)
	if code != 0 {
		t.Fatalf("split: %d %s %s", code, so, se)
	}
	for _, want := range []string{`holdout family "social" locked`, "loop:      2 attacks,   2 benign", "holdout:   1 attacks,   1 benign"} {
		if !strings.Contains(so, want) {
			t.Errorf("split output missing %q:\n%s", want, so)
		}
	}
	lock := filepath.Join(out, "holdout.lock.json")
	loopA, loopB := filepath.Join(out, "loop-attacks.jsonl"), filepath.Join(out, "loop-benign.jsonl")
	if code, o, _ := do(t, "verify-holdout", "-lock", lock, "-attacks", loopA, "-benign", loopB); code != 0 || !strings.Contains(o, "no leaks") {
		t.Errorf("clean loop reported leaks: %d %s", code, o)
	}
	// Smuggling the held-out attack into the loop must be caught.
	if code, o, _ := do(t, "verify-holdout", "-lock", lock, "-attacks", loopA+","+filepath.Join(out, "holdout-attacks.jsonl")); code != 1 || !strings.Contains(o, "HOLDOUT LEAK") {
		t.Errorf("leak not caught: %d %s", code, o)
	}
	// Re-running under the same family is fine; a different family is refused.
	if code, o, _ := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-holdout", "social", "-out", out); code != 0 || !strings.Contains(o, "existing lock") {
		t.Errorf("idempotent re-split: %d %s", code, o)
	}
	if code, _, e := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-holdout", "exfiltration", "-out", out); code != 2 || !strings.Contains(e, "already locked") {
		t.Errorf("changing the holdout must be refused: %d %s", code, e)
	}
	// A tampered lock is rejected.
	b, _ := os.ReadFile(lock)
	if err := os.WriteFile(lock, bytes.Replace(b, []byte("social"), []byte("persistence"), 1), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, e := do(t, "verify-holdout", "-lock", lock, "-attacks", loopA); code != 2 || !strings.Contains(e, "digest mismatch") {
		t.Errorf("tampered lock: %d %s", code, e)
	}
}

func TestSplitRefusals(t *testing.T) {
	out := t.TempDir()
	if code, _, e := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-out", out); code != 2 || !strings.Contains(e, "required") {
		t.Errorf("missing -holdout: %d %s", code, e)
	}
	if code, _, e := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-holdout", "persistence", "-out", out); code != 2 || !strings.Contains(e, "nothing to hold out") {
		t.Errorf("empty family: %d %s", code, e)
	}
	if code, _, e := do(t, "split", "-attacks", exAttacks, "-benign", exBenign, "-holdout", "bogus", "-out", out); code != 2 || !strings.Contains(e, "six families") {
		t.Errorf("bogus family: %d %s", code, e)
	}
	bad := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(bad, []byte(`{"id":"x"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, e := do(t, "split", "-attacks", bad, "-benign", exBenign, "-holdout", "social", "-out", out); code != 2 || !strings.Contains(e, "corpus lint") {
		t.Errorf("invalid corpus must not be split: %d %s", code, e)
	}
	if code, _, _ := do(t, "verify-holdout"); code != 2 {
		t.Errorf("verify without -lock: %d", code)
	}
}
