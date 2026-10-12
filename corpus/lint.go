package corpus

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode"

	"immunis/contract"
)

// Options are the lint thresholds. The defaults are the handbook targets.
type Options struct {
	MinAttacks        int // total attacks (handbook hour 18: fifteen-plus)
	MinSeedsPerFamily int // generation-0 attacks per family (at least three)
	MinTwins          int // benign twins overall (at least fifteen)
}

// DefaultOptions are the handbook targets.
func DefaultOptions() Options {
	return Options{MinAttacks: 15, MinSeedsPerFamily: 3, MinTwins: 15}
}

// FamilyStat is one row of the coverage table.
type FamilyStat struct {
	Family   contract.Family
	Seeds    int // generation 0
	Mutants  int // generation > 0
	Covered  int // attacks with a twin on themselves or an ancestor
	Attacks  int
	Twins    int // benign tasks whose twin_of is an attack of this family
	Surfaces int // distinct delivery surfaces used by this family
}

// Report is the result of Lint.
type Report struct {
	Issues   []Issue
	Coverage []FamilyStat
	Attacks  int
	Benign   int
}

// Errors counts error-severity issues.
func (r Report) Errors() int { return r.count(SevError) }

// Warnings counts warning-severity issues.
func (r Report) Warnings() int { return r.count(SevWarning) }

func (r Report) count(s Severity) int {
	n := 0
	for _, i := range r.Issues {
		if i.Severity == s {
			n++
		}
	}
	return n
}

// Failed reports whether the report should fail a build. Warnings only fail
// it in strict mode.
func (r Report) Failed(strict bool) bool {
	return r.Errors() > 0 || (strict && r.Warnings() > 0)
}

// Write prints issues, the coverage table and a summary line.
func (r Report) Write(w io.Writer) {
	for _, i := range r.Issues {
		fmt.Fprintln(w, i)
	}
	if len(r.Issues) > 0 {
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%-14s %5s %7s %9s %5s %9s\n", "family", "seeds", "mutants", "twinned", "twins", "surfaces")
	for _, s := range r.Coverage {
		fmt.Fprintf(w, "%-14s %5d %7d %6d/%-3d %5d %9d\n", s.Family, s.Seeds, s.Mutants, s.Covered, s.Attacks, s.Twins, s.Surfaces)
	}
	fmt.Fprintf(w, "\n%d attacks, %d benign twins: %d error(s), %d warning(s)\n", r.Attacks, r.Benign, r.Errors(), r.Warnings())
	fmt.Fprintln(w, "(a mutant counts as twinned when it or any ancestor has a twin)")
}

// normText lowercases and collapses whitespace, for equality checks.
func normText(s string) string { return strings.Join(strings.Fields(strings.ToLower(s)), " ") }

func tokenSet(s string) map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}) {
		m[t] = true
	}
	return m
}

// similarity is the Jaccard overlap of the two texts' word sets, 0..1.
func similarity(a, b string) float64 {
	x, y := tokenSet(a), tokenSet(b)
	if len(x) == 0 && len(y) == 0 {
		return 1
	}
	inter := 0
	for t := range x {
		if y[t] {
			inter++
		}
	}
	return float64(inter) / float64(len(x)+len(y)-inter)
}

// Thresholds for the delivery-realism and twin-quality heuristics.
const (
	shortPayloadBytes = 150
	barePhraseBytes   = 400
	lowTwinSimilarity = 0.15
)

var barePhrases = []string{
	"ignore previous instructions", "ignore all previous", "ignore the above",
	"disregard your instructions", "disregard all prior", "you are now",
	"forget your instructions",
}

// Lint runs every structural and cross-record check over c.
func Lint(c *Corpus, o Options) Report {
	r := Report{Attacks: len(c.Attacks), Benign: len(c.Benign)}
	r.Issues = append(r.Issues, c.LoadIssues...)
	add := func(sev Severity, o Origin, id, format string, a ...any) {
		r.Issues = append(r.Issues, Issue{sev, o.File, o.Line, id, fmt.Sprintf(format, a...)})
	}

	// Duplicate ids, within and across record kinds.
	idx := map[string]int{}
	seenAttack := map[string]Origin{}
	for i, a := range c.Attacks {
		if first, dup := seenAttack[a.ID]; dup {
			add(SevError, c.AttackOrigin[i], a.ID, "duplicate attack id (first at %s:%d)", first.File, first.Line)
			continue
		}
		seenAttack[a.ID] = c.AttackOrigin[i]
		idx[a.ID] = i
	}
	seenBenign := map[string]Origin{}
	for i, b := range c.Benign {
		if first, dup := seenBenign[b.ID]; dup {
			add(SevError, c.BenignOrigin[i], b.ID, "duplicate benign id (first at %s:%d)", first.File, first.Line)
			continue
		}
		seenBenign[b.ID] = c.BenignOrigin[i]
		if o, clash := seenAttack[b.ID]; clash {
			add(SevError, c.BenignOrigin[i], b.ID, "benign id collides with attack id at %s:%d", o.File, o.Line)
		}
	}

	// Lineage.
	for i, a := range c.Attacks {
		if a.ParentID == "" {
			continue
		}
		pi, ok := idx[a.ParentID]
		if !ok {
			add(SevError, c.AttackOrigin[i], a.ID, "parent_id %q is not in the corpus", a.ParentID)
			continue
		}
		p := c.Attacks[pi]
		if a.Generation != p.Generation+1 {
			add(SevError, c.AttackOrigin[i], a.ID, "generation %d but parent %q is generation %d (want %d)", a.Generation, p.ID, p.Generation, p.Generation+1)
		}
		if a.Family != p.Family {
			add(SevWarning, c.AttackOrigin[i], a.ID, "family %q differs from parent %q family %q", a.Family, p.ID, p.Family)
		}
		if normText(a.Payload) == normText(p.Payload) {
			add(SevError, c.AttackOrigin[i], a.ID, "payload is identical to parent %q: the mutation changed nothing", p.ID)
		}
		seen := map[string]bool{a.ID: true}
		for cur := p; cur.ParentID != ""; {
			if seen[cur.ParentID] {
				add(SevError, c.AttackOrigin[i], a.ID, "lineage cycle through %q", cur.ParentID)
				break
			}
			seen[cur.ParentID] = true
			ni, ok := idx[cur.ParentID]
			if !ok {
				break
			}
			cur = c.Attacks[ni]
		}
	}

	// Per-attack content heuristics and duplicate detection.
	payloadOwner := map[string]string{}
	gen0Objective := map[string]string{}
	for i, a := range c.Attacks {
		low := strings.ToLower(a.Payload)
		if n := len(strings.TrimSpace(a.Payload)); n > 0 && n < shortPayloadBytes {
			add(SevWarning, c.AttackOrigin[i], a.ID, "payload is only %d bytes: attacks should be sandwiched inside genuinely useful content, not pasted bare", n)
		} else {
			for _, ph := range barePhrases {
				if strings.Contains(low, ph) && len(a.Payload) < barePhraseBytes {
					add(SevWarning, c.AttackOrigin[i], a.ID, "short payload containing %q reads as a string-matching demo, not a realistic attack", ph)
					break
				}
			}
		}
		if key := normText(a.Payload); key != "" {
			if other, dup := payloadOwner[key]; dup && other != a.ParentID && other != a.ID {
				add(SevWarning, c.AttackOrigin[i], a.ID, "payload is identical to attack %q", other)
			} else if !dup {
				payloadOwner[key] = a.ID
			}
		}
		if a.Generation == 0 {
			if key := normText(a.Objective); key != "" {
				if other, dup := gen0Objective[key]; dup {
					add(SevWarning, c.AttackOrigin[i], a.ID, "objective is word-for-word the same as %q: copy-pasted objectives make for lazy verdicts", other)
				} else {
					gen0Objective[key] = a.ID
				}
			}
		}
	}

	// Twin integrity.
	for i, b := range c.Benign {
		ai, ok := idx[b.TwinOf]
		if !ok {
			add(SevError, c.BenignOrigin[i], b.ID, "twin_of %q is not an attack in the corpus", b.TwinOf)
			continue
		}
		a := c.Attacks[ai]
		if b.Surface != a.Surface {
			add(SevWarning, c.BenignOrigin[i], b.ID, "surface %q differs from its attack's surface %q: a twin must arrive the same way", b.Surface, a.Surface)
		}
		switch {
		case normText(b.Content) == normText(a.Payload):
			add(SevError, c.BenignOrigin[i], b.ID, "content is identical to the attack payload: that is the attack, not its twin")
		case similarity(a.Payload, b.Content) < lowTwinSimilarity:
			add(SevWarning, c.BenignOrigin[i], b.ID, "content shares little with attack %q (word overlap %.0f%%): a twin should look almost identical", a.ID, 100*similarity(a.Payload, b.Content))
		}
	}

	// Coverage.
	twinsOn := c.twinCounts()
	stats := map[contract.Family]*FamilyStat{}
	surfaces := map[contract.Family]map[contract.Surface]bool{}
	for _, f := range contract.AllFamilies {
		stats[f] = &FamilyStat{Family: f}
		surfaces[f] = map[contract.Surface]bool{}
	}
	var uncovered []int
	for i, a := range c.Attacks {
		st, ok := stats[a.Family]
		if !ok {
			continue // reported by Validate
		}
		st.Attacks++
		if a.Generation == 0 {
			st.Seeds++
		} else {
			st.Mutants++
		}
		st.Twins += twinsOn[a.ID]
		surfaces[a.Family][a.Surface] = true
		covered := twinsOn[a.ID] > 0
		for _, anc := range ancestors(a, idx, c.Attacks) {
			if twinsOn[anc.ID] > 0 {
				covered = true
			}
		}
		if covered {
			st.Covered++
		} else {
			uncovered = append(uncovered, i)
		}
	}
	for _, f := range contract.AllFamilies {
		st := stats[f]
		st.Surfaces = len(surfaces[f])
		r.Coverage = append(r.Coverage, *st)
		if st.Seeds < o.MinSeedsPerFamily {
			add(SevWarning, Origin{File: "(corpus)"}, "", "family %q has %d seed attack(s), the handbook wants at least %d", f, st.Seeds, o.MinSeedsPerFamily)
		}
	}
	for _, i := range uncovered {
		a := c.Attacks[i]
		add(SevWarning, c.AttackOrigin[i], a.ID, "no benign twin for this attack or any ancestor")
	}
	if len(c.Attacks) < o.MinAttacks {
		add(SevWarning, Origin{File: "(corpus)"}, "", "%d attacks, the handbook wants at least %d", len(c.Attacks), o.MinAttacks)
	}
	if len(c.Benign) < o.MinTwins {
		add(SevWarning, Origin{File: "(corpus)"}, "", "%d benign twins, the handbook wants at least %d", len(c.Benign), o.MinTwins)
	}

	sort.SliceStable(r.Issues, func(i, j int) bool {
		a, b := r.Issues[i], r.Issues[j]
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	return r
}

// TwinGap is an attack with no twin.
type TwinGap struct {
	Attack contract.Attack
	Origin Origin
}

// TwinGaps lists generation-0 attacks that have no benign twin of their own.
// (Mutants inherit their ancestor's twin and are not listed.)
func TwinGaps(c *Corpus) []TwinGap {
	twins := c.twinCounts()
	var out []TwinGap
	for i, a := range c.Attacks {
		if a.Generation == 0 && twins[a.ID] == 0 {
			out = append(out, TwinGap{a, c.AttackOrigin[i]})
		}
	}
	return out
}

// OrphanTwins lists benign tasks whose twin_of is not an attack in c.
func OrphanTwins(c *Corpus) []contract.BenignTask {
	idx := c.attackIndex()
	var out []contract.BenignTask
	for _, b := range c.Benign {
		if _, ok := idx[b.TwinOf]; !ok {
			out = append(out, b)
		}
	}
	return out
}
