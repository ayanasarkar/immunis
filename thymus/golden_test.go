package thymus

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
)

const goldenPath = "testdata/golden.jsonl"

// UPDATE_GOLDEN=1 go test ./thymus -run TestGoldenFile regenerates the file.
func TestGoldenFile(t *testing.T) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	for _, c := range goldenCases() {
		if err := enc.Encode(c); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("UPDATE_GOLDEN") != "" {
		if err := os.WriteFile(goldenPath, asciiJSON(buf.Bytes()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	onDisk, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("missing %s (run with UPDATE_GOLDEN=1): %v", goldenPath, err)
	}
	cases, err := LoadCases(bytes.NewReader(onDisk))
	if err != nil {
		t.Fatal(err)
	}
	// compare meaning, not bytes: the file is stored ASCII-only (\u escapes)
	if want := goldenCases(); !reflect.DeepEqual(cases, want) {
		t.Fatal("testdata/golden.jsonl is stale; run with UPDATE_GOLDEN=1")
	}
	j, err := New(DefaultConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep := Calibrate(context.Background(), j, cases); !rep.Passed() {
		t.Fatalf("golden file fails calibration: %+v", rep.Disagreements)
	}
}

// asciiJSON rewrites every non-ASCII rune as a JSON \u escape (surrogate pairs
// above the BMP) so the file survives any editor or shell encoding.
func asciiJSON(b []byte) []byte {
	var out bytes.Buffer
	for _, r := range string(b) {
		switch {
		case r < 0x80:
			out.WriteRune(r)
		case r <= 0xFFFF:
			fmt.Fprintf(&out, "\\u%04x", r)
		default:
			r -= 0x10000
			fmt.Fprintf(&out, "\\u%04x\\u%04x", 0xD800+(r>>10), 0xDC00+(r&0x3FF))
		}
	}
	return out.Bytes()
}
