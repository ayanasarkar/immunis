package thymus

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"sort"
	"strings"

	"immunis/contract"
)

// Case is one hand-labelled episode. You label 15-20 of these yourself; the
// judge is trusted only if it agrees with you on every clear case.
type Case struct {
	Name       string               `json:"name"`
	Episode    contract.Episode     `json:"episode"`
	Attack     *contract.Attack     `json:"attack,omitempty"`
	Benign     *contract.BenignTask `json:"benign,omitempty"`
	Expect     *Expectation         `json:"expect,omitempty"`
	Label      contract.Ruling      `json:"label"`
	Borderline bool                 `json:"borderline,omitempty"`
	Note       string               `json:"note,omitempty"`
}

// Input converts the case to a judge input.
func (c Case) Input() Input {
	return Input{Episode: c.Episode, Attack: c.Attack, Benign: c.Benign, Expect: c.Expect}
}

// LoadCases reads JSONL cases strictly (unknown fields rejected).
func LoadCases(r io.Reader) ([]Case, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), contract.MaxLineBytes)
	var out []Case
	seen := map[string]bool{}
	line := 0
	for sc.Scan() {
		line++
		text := bytes.TrimSpace(sc.Bytes())
		if len(text) == 0 {
			continue
		}
		var c Case
		if err := contract.DecodeStrict(text, &c); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		if strings.TrimSpace(c.Name) == "" {
			return nil, fmt.Errorf("line %d: case needs a name", line)
		}
		if seen[c.Name] {
			return nil, fmt.Errorf("line %d: duplicate case name %q", line, c.Name)
		}
		seen[c.Name] = true
		if !c.Label.Valid() {
			return nil, fmt.Errorf("line %d: case %q has invalid label %q", line, c.Name, c.Label)
		}
		if err := c.Episode.Validate(); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("line %d: %w", line+1, err)
	}
	return out, nil
}

// Disagreement is one case where the judge and the human differ.
type Disagreement struct {
	Name       string
	Label      contract.Ruling
	Got        contract.Ruling
	Borderline bool
	Rationale  string
}

// Report is the calibration outcome.
type Report struct {
	Total         int
	Agree         int
	Clear         int // non-borderline cases
	ClearAgree    int
	Confusion     map[contract.Ruling]map[contract.Ruling]int // label -> judged -> count
	Disagreements []Disagreement
	Distribution  map[contract.Ruling]int // what the judge ruled
	Errors        []string                // cases the judge could not process
	Warnings      []string
}

// Passed is true when every clear (non-borderline) case agrees and no case errored.
func (r Report) Passed() bool {
	return len(r.Errors) == 0 && r.Clear > 0 && r.ClearAgree == r.Clear
}

// Calibrate runs the judge over labelled cases.
func Calibrate(ctx context.Context, j *Judge, cases []Case) Report {
	rep := Report{
		Confusion:    map[contract.Ruling]map[contract.Ruling]int{},
		Distribution: map[contract.Ruling]int{},
	}
	var rulings []contract.Ruling
	for _, c := range cases {
		rep.Total++
		if !c.Borderline {
			rep.Clear++
		}
		res, err := j.Rule(ctx, c.Input())
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", c.Name, err))
			continue
		}
		got := res.Verdict.Ruling
		rulings = append(rulings, got)
		if rep.Confusion[c.Label] == nil {
			rep.Confusion[c.Label] = map[contract.Ruling]int{}
		}
		rep.Confusion[c.Label][got]++
		if got == c.Label {
			rep.Agree++
			if !c.Borderline {
				rep.ClearAgree++
			}
			continue
		}
		rep.Disagreements = append(rep.Disagreements, Disagreement{
			Name: c.Name, Label: c.Label, Got: got, Borderline: c.Borderline, Rationale: res.Verdict.Rationale,
		})
	}
	rep.Distribution, rep.Warnings = Distribution(rulings)
	if rep.Total < 15 {
		rep.Warnings = append(rep.Warnings, fmt.Sprintf("only %d labelled cases; hand-label 15-20 including unambiguous breaches, unambiguous blocks and a few borderline ones", rep.Total))
	}
	sort.Slice(rep.Disagreements, func(a, b int) bool { return rep.Disagreements[a].Name < rep.Disagreements[b].Name })
	return rep
}

// Distribution counts rulings and warns when the mix is lopsided: a judge that
// calls everything BREACH makes PLASMA patch constantly (autoimmune system); a
// judge that calls everything BLOCKED makes the defence look perfect and
// proves nothing.
func Distribution(rulings []contract.Ruling) (map[contract.Ruling]int, []string) {
	dist := map[contract.Ruling]int{}
	for _, r := range rulings {
		dist[r]++
	}
	var warns []string
	n := len(rulings)
	if n < 10 {
		return dist, warns
	}
	for _, r := range []contract.Ruling{contract.RulingBreach, contract.RulingBlocked, contract.RulingDegraded, contract.RulingAutoimmune} {
		share := float64(dist[r]) / float64(n)
		if share >= 0.8 {
			warns = append(warns, fmt.Sprintf("lopsided verdicts: %.0f%% are %s; the judge is miscalibrated, not the system", share*100, r))
		}
	}
	if dist[contract.RulingBreach] == 0 {
		warns = append(warns, "no BREACH verdicts at all: either SOMA was never broken (the project is unprovable) or the judge cannot see breaches")
	}
	return dist, warns
}