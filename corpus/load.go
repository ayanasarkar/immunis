// Package corpus is the ANTIGEN-side tooling around the attack corpus: lint,
// twin coverage and the family holdout split. It reads and writes the shapes
// defined in package contract and adds no fields of its own to them.
package corpus

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"

	"immunis/contract"
)

// Severity of a lint finding.
type Severity string

// Severities.
const (
	SevError   Severity = "error"
	SevWarning Severity = "warning"
)

// Issue is one finding, pointing at a file and line where it can.
type Issue struct {
	Severity Severity
	File     string
	Line     int
	ID       string
	Msg      string
}

func (i Issue) String() string {
	loc := i.File
	if i.Line > 0 {
		loc = fmt.Sprintf("%s:%d", i.File, i.Line)
	}
	id := ""
	if i.ID != "" {
		id = " [" + i.ID + "]"
	}
	return fmt.Sprintf("%-7s %s%s: %s", i.Severity, loc, id, i.Msg)
}

// Origin says where a record was read from.
type Origin struct {
	File string
	Line int
}

// Corpus is a set of attacks and benign twins loaded from JSONL files.
// Origins run parallel to the record slices.
type Corpus struct {
	Attacks      []contract.Attack
	Benign       []contract.BenignTask
	AttackOrigin []Origin
	BenignOrigin []Origin
	LoadIssues   []Issue
}

// Load reads attack and benign JSONL files. Unlike contract.ReadJSONL it does
// not stop at the first bad record: every decode and validation problem is
// collected into LoadIssues, and records that decode are kept so cross-file
// checks still work. The error is for I/O failures only.
func Load(attackFiles, benignFiles []string) (*Corpus, error) {
	c := &Corpus{}
	for _, p := range attackFiles {
		recs, orig, issues, err := loadFile[contract.Attack](p)
		if err != nil {
			return nil, err
		}
		c.Attacks = append(c.Attacks, recs...)
		c.AttackOrigin = append(c.AttackOrigin, orig...)
		c.LoadIssues = append(c.LoadIssues, issues...)
	}
	for _, p := range benignFiles {
		recs, orig, issues, err := loadFile[contract.BenignTask](p)
		if err != nil {
			return nil, err
		}
		c.Benign = append(c.Benign, recs...)
		c.BenignOrigin = append(c.BenignOrigin, orig...)
		c.LoadIssues = append(c.LoadIssues, issues...)
	}
	return c, nil
}

func loadFile[T contract.Record](path string) ([]T, []Origin, []Issue, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer f.Close()
	return loadReader[T](path, f)
}

var utf8BOM = []byte("\xef\xbb\xbf")

func loadReader[T contract.Record](name string, r io.Reader) ([]T, []Origin, []Issue, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), contract.MaxLineBytes)
	var (
		recs   []T
		orig   []Origin
		issues []Issue
		line   int
	)
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if line == 1 {
			// Windows PowerShell's Set-Content -Encoding UTF8 writes a BOM.
			text = bytes.TrimSpace(bytes.TrimPrefix(text, utf8BOM))
		}
		if len(text) == 0 {
			continue
		}
		var v T
		if err := contract.DecodeStrict(text, &v); err != nil {
			issues = append(issues, Issue{SevError, name, line, "", err.Error()})
			continue
		}
		recs = append(recs, v)
		orig = append(orig, Origin{name, line})
		if verr := v.Validate(); verr != nil {
			var ve *contract.ValidationError
			if errors.As(verr, &ve) {
				for _, p := range ve.Problems {
					issues = append(issues, Issue{SevError, name, line, v.RecordID(), p})
				}
			} else {
				issues = append(issues, Issue{SevError, name, line, v.RecordID(), verr.Error()})
			}
		}
	}
	if err := sc.Err(); err != nil {
		issues = append(issues, Issue{SevError, name, line + 1, "", err.Error()})
	}
	return recs, orig, issues, nil
}

// attackIndex maps id to position in c.Attacks (first occurrence wins).
func (c *Corpus) attackIndex() map[string]int {
	m := make(map[string]int, len(c.Attacks))
	for i, a := range c.Attacks {
		if _, dup := m[a.ID]; !dup {
			m[a.ID] = i
		}
	}
	return m
}

// twinCounts returns how many benign tasks name each attack as twin_of.
func (c *Corpus) twinCounts() map[string]int {
	m := map[string]int{}
	for _, b := range c.Benign {
		m[b.TwinOf]++
	}
	return m
}

// ancestors walks parent links from a (exclusive) toward the root, guarding
// against cycles and dangling parents.
func ancestors(a contract.Attack, idx map[string]int, all []contract.Attack) []contract.Attack {
	var out []contract.Attack
	seen := map[string]bool{a.ID: true}
	cur := a
	for cur.ParentID != "" && !seen[cur.ParentID] {
		i, ok := idx[cur.ParentID]
		if !ok {
			break
		}
		cur = all[i]
		seen[cur.ID] = true
		out = append(out, cur)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
