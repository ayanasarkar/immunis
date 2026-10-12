package contract

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Record is anything MARROW stores.
type Record interface {
	Validate() error
	RecordID() string
}

// MaxLineBytes caps one JSONL line (8 MiB: episodes carry full transcripts).
const MaxLineBytes = 8 << 20

// DecodeStrict decodes exactly one JSON value, rejecting unknown fields and
// trailing data. Silent field drift is how contracts rot.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}

// ReadJSONL reads one record per line, strictly, validating each. Blank lines
// are skipped; CRLF line endings are fine. Errors carry the 1-based line number.
func ReadJSONL[T Record](r io.Reader) ([]T, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), MaxLineBytes)
	var out []T
	line := 0
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		var v T
		if err := DecodeStrict(text, &v); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if err := v.Validate(); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, v)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return out, nil
}

// CheckUniqueIDs fails on the first duplicate record id.
func CheckUniqueIDs[T Record](recs []T) error {
	seen := make(map[string]int, len(recs))
	for i, r := range recs {
		id := r.RecordID()
		if j, dup := seen[id]; dup {
			return fmt.Errorf("duplicate id %q at records %d and %d", id, j, i)
		}
		seen[id] = i
	}
	return nil
}

// WriteJSONL validates then writes one compact JSON object per line. HTML
// escaping is off so payloads stay human-readable on disk.
func WriteJSONL[T Record](w io.Writer, recs []T) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i, r := range recs {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("record %d: %w", i, err)
		}
	}
	return nil
}
