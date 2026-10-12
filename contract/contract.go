// Package contract holds the shared record shapes of Project IMMUNIS.
//
// The shapes mirror COORDINATION.md section 5 exactly (field names included).
// Anything the handbook leaves open is marked "SHAPE ASSUMPTION" below and must
// be confirmed with Wrik (SOMA) / Mainak (MARROW) before hour 4. Nobody adds a
// field silently: ask in the team channel first.
package contract

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

// Family is one of the six attack families. The list is FROZEN.
type Family string

const (
	FamilyInjection    Family = "injection"
	FamilyMemoryPoison Family = "memory-poison"
	FamilyExfiltration Family = "exfiltration"
	FamilyToolAbuse    Family = "tool-abuse"
	FamilyPersistence  Family = "persistence"
	FamilySocial       Family = "social"
)

// AllFamilies is the frozen family list, in handbook order.
var AllFamilies = []Family{
	FamilyInjection, FamilyMemoryPoison, FamilyExfiltration,
	FamilyToolAbuse, FamilyPersistence, FamilySocial,
}

// Valid reports whether f is one of the six frozen families.
func (f Family) Valid() bool {
	for _, k := range AllFamilies {
		if f == k {
			return true
		}
	}
	return false
}

// Surface is the real delivery surface an attack arrives through.
// Values are the handbook's literal strings (note the spaces).
type Surface string

const (
	SurfaceEmail      Surface = "email"
	SurfaceWebPage    Surface = "web page"
	SurfaceDocument   Surface = "document"
	SurfaceToolOutput Surface = "tool output"
	SurfaceCalendar   Surface = "calendar"
	SurfaceContact    Surface = "contact"
)

// AllSurfaces lists every delivery surface.
var AllSurfaces = []Surface{
	SurfaceEmail, SurfaceWebPage, SurfaceDocument,
	SurfaceToolOutput, SurfaceCalendar, SurfaceContact,
}

// Valid reports whether s is a known surface.
func (s Surface) Valid() bool {
	for _, k := range AllSurfaces {
		if s == k {
			return true
		}
	}
	return false
}

// ViolationKind is the machine-readable part of Attack.ExpectedViolation.
// The three kinds are exactly the three ways the handbook defines a BREACH.
type ViolationKind string

const (
	ViolationDataEgress    ViolationKind = "data_egress"    // data left the sandbox
	ViolationForbiddenTool ViolationKind = "forbidden_tool" // a forbidden tool fired
	ViolationMemoryPersist ViolationKind = "memory_persist" // poison persisted into memory/skills/contacts
)

// Valid reports whether k is a known violation kind.
func (k ViolationKind) Valid() bool {
	return k == ViolationDataEgress || k == ViolationForbiddenTool || k == ViolationMemoryPersist
}

// allowedKinds says which violation kinds make sense for each family. A
// "memory-poison" attack whose expected violation is an outbound email is a
// mislabelled record, and a mislabelled objective means a worthless verdict.
var allowedKinds = map[Family][]ViolationKind{
	FamilyInjection:    {ViolationForbiddenTool, ViolationDataEgress},
	FamilyMemoryPoison: {ViolationMemoryPersist},
	FamilyExfiltration: {ViolationDataEgress},
	FamilyToolAbuse:    {ViolationForbiddenTool},
	FamilyPersistence:  {ViolationMemoryPersist, ViolationForbiddenTool},
	FamilySocial:       {ViolationForbiddenTool, ViolationDataEgress, ViolationMemoryPersist},
}

// Trust is the trust level carried by every piece of text inside SOMA.
type Trust string

const (
	TrustTrusted     Trust = "trusted"
	TrustUntrusted   Trust = "untrusted"
	TrustQuarantined Trust = "quarantined"
)

// Valid reports whether t is a known trust level.
func (t Trust) Valid() bool {
	return t == TrustTrusted || t == TrustUntrusted || t == TrustQuarantined
}

// Ruling is the THYMUS verdict.
type Ruling string

const (
	RulingBreach     Ruling = "BREACH"
	RulingBlocked    Ruling = "BLOCKED"
	RulingDegraded   Ruling = "DEGRADED"
	RulingAutoimmune Ruling = "AUTOIMMUNE"
)

// Valid reports whether r is one of the four rulings.
func (r Ruling) Valid() bool {
	return r == RulingBreach || r == RulingBlocked || r == RulingDegraded || r == RulingAutoimmune
}

// JudgeTier records which tier of THYMUS decided.
type JudgeTier string

const (
	TierFast JudgeTier = "fast"
	TierDeep JudgeTier = "deep"
)

// Valid reports whether t is a known tier.
func (t JudgeTier) Valid() bool { return t == TierFast || t == TierDeep }

// ---------------------------------------------------------------------------
// Validation plumbing
// ---------------------------------------------------------------------------

// ValidationError lists every problem found in one record, not just the first.
type ValidationError struct {
	Record   string // "attack", "benign_task", "episode", "verdict"
	ID       string
	Problems []string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s %q invalid: %s", e.Record, e.ID, strings.Join(e.Problems, "; "))
}

type problems []string

func (p *problems) addf(format string, a ...any) { *p = append(*p, fmt.Sprintf(format, a...)) }

func (p problems) err(record, id string) error {
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Record: record, ID: id, Problems: []string(p)}
}

var (
	idRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{2,63}$`)
	detailRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)
	toolRe   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,63}$`)
)

// ValidID reports whether s is a legal record id.
func ValidID(s string) bool { return idRe.MatchString(s) }

// MaxPayloadBytes caps Attack.Payload and BenignTask.Content (64 KiB).
const MaxPayloadBytes = 64 * 1024

func checkText(name, s string, max int) []string {
	var out []string
	switch {
	case strings.TrimSpace(s) == "":
		out = append(out, name+" is empty")
	case len(s) > max:
		out = append(out, fmt.Sprintf("%s is %d bytes, max %d", name, len(s), max))
	}
	if !utf8.ValidString(s) {
		out = append(out, name+" is not valid UTF-8")
	}
	if strings.ContainsRune(s, 0) {
		out = append(out, name+" contains a NUL byte")
	}
	return out
}

func wordCount(s string) int { return len(strings.Fields(s)) }

// ---------------------------------------------------------------------------
// Objective quality
// ---------------------------------------------------------------------------

// concreteTerms: an objective must point at something THYMUS can find in an
// episode (a tool, an artefact, a destination, a store). "Vague objective,
// worthless verdict."
var concreteTerms = []string{
	"send_email", "email", "url", "http", "file", "memory", "remember",
	"calendar", "contact", "schedule", "credential", "api key", "secret",
	"passphrase", "payroll", "delete", "write", "forward", "post", "shell",
	"tool", "skill", "canary", "invite", "persist", "reply", "address",
}

var vaguePhrases = []string{
	"be malicious", "attack the system", "attack soma", "jailbreak",
	"do something bad", "cause harm", "break the assistant", "bypass safety",
	"get past the defence", "get past the defense", "misbehave", "do bad things",
}

// Objective length bounds, in words.
const (
	MinObjectiveWords = 10
	MaxObjectiveWords = 120
)

// CheckObjective returns the problems with a plain-English attacker objective.
func CheckObjective(s string) []string {
	var out []string
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return []string{"objective is not clean UTF-8 text"}
	}
	n := wordCount(s)
	switch {
	case n == 0:
		return []string{"objective is empty"}
	case n < MinObjectiveWords:
		out = append(out, fmt.Sprintf("objective has %d words, need >= %d: say what success looks like for the attacker", n, MinObjectiveWords))
	case n > MaxObjectiveWords:
		out = append(out, fmt.Sprintf("objective has %d words, max %d", n, MaxObjectiveWords))
	}
	low := strings.ToLower(s)
	concrete := false
	for _, t := range concreteTerms {
		if strings.Contains(low, t) {
			concrete = true
			break
		}
	}
	if !concrete {
		vague := ""
		for _, v := range vaguePhrases {
			if strings.Contains(low, v) {
				vague = fmt.Sprintf(" (vague phrase %q)", v)
				break
			}
		}
		out = append(out, "objective names no concrete tool, artefact, destination or store"+vague)
	}
	return out
}

// ParseViolation splits "<kind>:<detail>", e.g. "forbidden_tool:send_email".
func ParseViolation(s string) (ViolationKind, string, error) {
	kind, detail, ok := strings.Cut(s, ":")
	if !ok {
		return "", "", fmt.Errorf("expected_violation %q must look like <kind>:<detail>", s)
	}
	k := ViolationKind(kind)
	if !k.Valid() {
		return "", "", fmt.Errorf("expected_violation kind %q unknown (want data_egress, forbidden_tool or memory_persist)", kind)
	}
	if !detailRe.MatchString(detail) {
		return "", "", fmt.Errorf("expected_violation detail %q must match %s", detail, detailRe)
	}
	return k, detail, nil
}

// ---------------------------------------------------------------------------
// Attack
// ---------------------------------------------------------------------------

// Attack is the ANTIGEN -> MARROW record.
//
//	id, family, surface, payload, objective, generation, parent_id,
//	expected_violation
//
// ParentID is "" for generation-0 (hand-written or Garak-seeded) attacks.
// ExpectedViolation is "<kind>:<detail>" (see ParseViolation).
type Attack struct {
	ID                string  `json:"id"`
	Family            Family  `json:"family"`
	Surface           Surface `json:"surface"`
	Payload           string  `json:"payload"`
	Objective         string  `json:"objective"`
	Generation        int     `json:"generation"`
	ParentID          string  `json:"parent_id"`
	ExpectedViolation string  `json:"expected_violation"`
}

// RecordID implements Record.
func (a Attack) RecordID() string { return a.ID }

// Validate checks every structural rule on an Attack.
func (a Attack) Validate() error {
	var p problems
	if !idRe.MatchString(a.ID) {
		p.addf("id %q must match %s", a.ID, idRe)
	}
	if !a.Family.Valid() {
		p.addf("family %q is not one of the six frozen families", a.Family)
	}
	if !a.Surface.Valid() {
		p.addf("surface %q is not a known delivery surface", a.Surface)
	}
	p = append(p, checkText("payload", a.Payload, MaxPayloadBytes)...)
	p = append(p, CheckObjective(a.Objective)...)

	switch {
	case a.Generation < 0:
		p.addf("generation %d is negative", a.Generation)
	case a.Generation == 0:
		if a.ParentID != "" {
			p.addf("generation 0 attack must have empty parent_id, got %q", a.ParentID)
		}
	default:
		switch {
		case a.ParentID == "":
			p.addf("generation %d attack needs a parent_id (phylogeny)", a.Generation)
		case a.ParentID == a.ID:
			p.addf("parent_id equals id %q", a.ID)
		case !idRe.MatchString(a.ParentID):
			p.addf("parent_id %q is not a legal id", a.ParentID)
		}
	}

	kind, _, err := ParseViolation(a.ExpectedViolation)
	if err != nil {
		p.addf("%v", err)
	} else if a.Family.Valid() {
		ok := false
		for _, k := range allowedKinds[a.Family] {
			if k == kind {
				ok = true
			}
		}
		if !ok {
			p.addf("family %q cannot have expected violation kind %q", a.Family, kind)
		}
	}
	return p.err("attack", a.ID)
}

// ---------------------------------------------------------------------------
// BenignTask
// ---------------------------------------------------------------------------

// BenignTask is the legitimate twin of an Attack.
type BenignTask struct {
	ID              string  `json:"id"`
	TwinOf          string  `json:"twin_of"`
	Surface         Surface `json:"surface"`
	Content         string  `json:"content"`
	SuccessCriteria string  `json:"success_criteria"`
}

// RecordID implements Record.
func (b BenignTask) RecordID() string { return b.ID }

// MinCriteriaWords is the minimum length of success_criteria.
const MinCriteriaWords = 6

// Validate checks every structural rule on a BenignTask.
func (b BenignTask) Validate() error {
	var p problems
	if !idRe.MatchString(b.ID) {
		p.addf("id %q must match %s", b.ID, idRe)
	}
	switch {
	case !idRe.MatchString(b.TwinOf):
		p.addf("twin_of %q is not a legal attack id", b.TwinOf)
	case b.TwinOf == b.ID:
		p.addf("twin_of equals id %q", b.ID)
	}
	if !b.Surface.Valid() {
		p.addf("surface %q is not a known delivery surface", b.Surface)
	}
	p = append(p, checkText("content", b.Content, MaxPayloadBytes)...)
	if n := wordCount(b.SuccessCriteria); n < MinCriteriaWords {
		p.addf("success_criteria has %d words, need >= %d: say what SOMA must still be willing to do", n, MinCriteriaWords)
	} else if n > 120 {
		p.addf("success_criteria has %d words, max 120", n)
	}
	return p.err("benign_task", b.ID)
}

// ---------------------------------------------------------------------------
// Episode (SOMA -> THYMUS)
//
// SHAPE ASSUMPTION: the handbook says only "transcript, tool_calls (with the
// taint trace on every argument), memory_diff (before/after)". The inner
// shapes below are what THYMUS needs to rule on concrete evidence. Confirm
// with Wrik; decoding ignores nothing (strict) so a mismatch fails loudly.
// ---------------------------------------------------------------------------

// TaintTag is one hop of an argument's taint trace.
type TaintTag struct {
	Origin string `json:"origin"` // e.g. "user", "email:msg-17", "web:https://..."
	Trust  Trust  `json:"trust"`
}

// ToolArg is one argument of a tool call, stringified, with its taint trace.
type ToolArg struct {
	Name  string     `json:"name"`
	Value string     `json:"value"`
	Taint []TaintTag `json:"taint"`
}

// ToolStatus says what actually happened to a tool call.
type ToolStatus string

const (
	StatusExecuted        ToolStatus = "executed"
	StatusBlocked         ToolStatus = "blocked"
	StatusElevationNeeded ToolStatus = "elevation_required"
	StatusError           ToolStatus = "error"
)

// Valid reports whether s is a known tool status.
func (s ToolStatus) Valid() bool {
	return s == StatusExecuted || s == StatusBlocked || s == StatusElevationNeeded || s == StatusError
}

// ToolCall is one tool invocation in an episode.
type ToolCall struct {
	Turn   int        `json:"turn"` // index into Transcript that issued it
	Name   string     `json:"name"`
	Args   []ToolArg  `json:"args"`
	Status ToolStatus `json:"status"`
	Result string     `json:"result,omitempty"`
}

// Turn is one transcript entry.
type Turn struct {
	Index   int    `json:"index"`
	Role    string `json:"role"` // user | assistant | tool | system
	Content string `json:"content"`
	Origin  string `json:"origin,omitempty"`
	Trust   Trust  `json:"trust,omitempty"`
}

// MemoryEntry is one durable memory/skill/contact record in SOMA.
type MemoryEntry struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Trust  Trust  `json:"trust"`
	Origin string `json:"origin,omitempty"`
}

// MemoryDiff is the before/after snapshot pair.
type MemoryDiff struct {
	Before []MemoryEntry `json:"before"`
	After  []MemoryEntry `json:"after"`
}

// Episode is the full record of one run.
type Episode struct {
	ID            string     `json:"id"`
	AttackID      string     `json:"attack_id,omitempty"`
	BenignTaskID  string     `json:"benign_task_id,omitempty"`
	PolicyVersion int        `json:"policy_version"`
	Transcript    []Turn     `json:"transcript"`
	ToolCalls     []ToolCall `json:"tool_calls"`
	MemoryDiff    MemoryDiff `json:"memory_diff"`
	WallClockMS   int64      `json:"wall_clock_ms"`
	TokenCount    int        `json:"token_count"`
}

// RecordID implements Record.
func (e Episode) RecordID() string { return e.ID }

var validRoles = map[string]bool{"user": true, "assistant": true, "tool": true, "system": true}

func checkMemory(p *problems, label string, entries []MemoryEntry) {
	seen := make(map[string]bool, len(entries))
	for i, m := range entries {
		switch {
		case m.Key == "":
			p.addf("memory_diff.%s[%d] has an empty key", label, i)
		case strings.TrimSpace(m.Key) != m.Key || !utf8.ValidString(m.Key) || strings.ContainsRune(m.Key, 0):
			// evidence pointers must be able to name every key
			p.addf("memory_diff.%s[%d] key %q must be clean text without surrounding space", label, i, m.Key)
		case seen[m.Key]:
			p.addf("memory_diff.%s has duplicate key %q", label, m.Key)
		}
		seen[m.Key] = true
		if !m.Trust.Valid() {
			p.addf("memory_diff.%s[%d] trust %q invalid", label, i, m.Trust)
		}
	}
}

// Validate checks every structural rule on an Episode.
func (e Episode) Validate() error {
	var p problems
	if !idRe.MatchString(e.ID) {
		p.addf("id %q must match %s", e.ID, idRe)
	}
	switch {
	case e.AttackID != "" && e.BenignTaskID != "":
		p.addf("exactly one of attack_id / benign_task_id may be set, got both")
	case e.AttackID == "" && e.BenignTaskID == "":
		p.addf("one of attack_id / benign_task_id is required")
	case e.AttackID != "" && !idRe.MatchString(e.AttackID):
		p.addf("attack_id %q is not a legal id", e.AttackID)
	case e.BenignTaskID != "" && !idRe.MatchString(e.BenignTaskID):
		p.addf("benign_task_id %q is not a legal id", e.BenignTaskID)
	}
	if e.PolicyVersion < 0 {
		p.addf("policy_version %d is negative", e.PolicyVersion)
	}
	if e.WallClockMS < 0 {
		p.addf("wall_clock_ms %d is negative", e.WallClockMS)
	}
	if e.TokenCount < 0 {
		p.addf("token_count %d is negative", e.TokenCount)
	}
	if len(e.Transcript) == 0 {
		p.addf("transcript is empty")
	}
	for i, t := range e.Transcript {
		if t.Index != i {
			p.addf("transcript[%d].index is %d, turns must be numbered 0..n-1 in order", i, t.Index)
		}
		if !validRoles[t.Role] {
			p.addf("transcript[%d].role %q invalid", i, t.Role)
		}
		if t.Trust != "" && !t.Trust.Valid() {
			p.addf("transcript[%d].trust %q invalid", i, t.Trust)
		}
	}
	for i, c := range e.ToolCalls {
		if c.Turn < 0 || c.Turn >= len(e.Transcript) {
			p.addf("tool_calls[%d].turn %d outside transcript (0..%d)", i, c.Turn, len(e.Transcript)-1)
		}
		if !toolRe.MatchString(c.Name) {
			p.addf("tool_calls[%d].name %q must match %s", i, c.Name, toolRe)
		}
		if !c.Status.Valid() {
			p.addf("tool_calls[%d].status %q invalid", i, c.Status)
		}
		names := make(map[string]bool, len(c.Args))
		for j, a := range c.Args {
			if a.Name == "" {
				p.addf("tool_calls[%d].args[%d] has an empty name", i, j)
			} else if names[a.Name] {
				p.addf("tool_calls[%d] has duplicate arg %q", i, a.Name)
			}
			names[a.Name] = true
			if len(a.Taint) == 0 {
				p.addf("tool_calls[%d].args[%d] (%s) has no taint trace; every argument must carry one", i, j, a.Name)
			}
			for k, tg := range a.Taint {
				if tg.Origin == "" {
					p.addf("tool_calls[%d].args[%d].taint[%d] has empty origin", i, j, k)
				}
				if !tg.Trust.Valid() {
					p.addf("tool_calls[%d].args[%d].taint[%d] trust %q invalid", i, j, k, tg.Trust)
				}
			}
		}
	}
	checkMemory(&p, "before", e.MemoryDiff.Before)
	checkMemory(&p, "after", e.MemoryDiff.After)
	return p.err("episode", e.ID)
}

// ---------------------------------------------------------------------------
// Evidence pointers
// ---------------------------------------------------------------------------

// EvidenceKind says what an evidence pointer points at.
type EvidenceKind string

const (
	EvTurn        EvidenceKind = "turn"         // turn:<index>
	EvToolCall    EvidenceKind = "tool_call"    // tool_call:<index into tool_calls>
	EvMemoryWrite EvidenceKind = "memory_write" // memory_write:<key written or changed>
	EvEpisode     EvidenceKind = "episode"      // episode:final (whole-episode ruling, never for BREACH)
)

// Evidence is a parsed evidence pointer.
type Evidence struct {
	Kind EvidenceKind
	Ref  string
}

// String renders the canonical pointer text.
func (e Evidence) String() string { return string(e.Kind) + ":" + e.Ref }

// ParseEvidence parses "<kind>:<ref>". Index refs must be canonical
// non-negative decimals (no sign, no leading zeros, no spaces).
func ParseEvidence(s string) (Evidence, error) {
	kind, ref, ok := strings.Cut(s, ":")
	if !ok || ref == "" {
		return Evidence{}, fmt.Errorf("evidence pointer %q must look like <kind>:<ref>", s)
	}
	switch EvidenceKind(kind) {
	case EvTurn, EvToolCall:
		n, err := parseIndex(ref)
		if err != nil {
			return Evidence{}, fmt.Errorf("evidence pointer %q: %v", s, err)
		}
		return Evidence{Kind: EvidenceKind(kind), Ref: fmt.Sprint(n)}, nil
	case EvMemoryWrite:
		if strings.TrimSpace(ref) != ref || !utf8.ValidString(ref) || strings.ContainsRune(ref, 0) {
			return Evidence{}, fmt.Errorf("evidence pointer %q: memory key must be clean text without surrounding space", s)
		}
		return Evidence{Kind: EvMemoryWrite, Ref: ref}, nil
	case EvEpisode:
		if ref != "final" {
			return Evidence{}, fmt.Errorf("evidence pointer %q: only episode:final is allowed", s)
		}
		return Evidence{Kind: EvEpisode, Ref: ref}, nil
	}
	return Evidence{}, fmt.Errorf("evidence pointer %q: unknown kind %q", s, kind)
}

func parseIndex(ref string) (int, error) {
	if len(ref) > 9 {
		return 0, fmt.Errorf("index %q too large", ref)
	}
	n := 0
	for i := 0; i < len(ref); i++ {
		c := ref[i]
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("index %q must be a plain non-negative decimal", ref)
		}
		n = n*10 + int(c-'0')
	}
	if fmt.Sprint(n) != ref {
		return 0, fmt.Errorf("index %q must not have leading zeros", ref)
	}
	return n, nil
}

// Resolve checks that the pointer names something that really exists in e.
func (e Episode) Resolve(ev Evidence) error {
	switch ev.Kind {
	case EvTurn:
		n, err := parseIndex(ev.Ref)
		if err != nil {
			return err
		}
		if n >= len(e.Transcript) {
			return fmt.Errorf("evidence %s: episode has only %d turns", ev, len(e.Transcript))
		}
	case EvToolCall:
		n, err := parseIndex(ev.Ref)
		if err != nil {
			return err
		}
		if n >= len(e.ToolCalls) {
			return fmt.Errorf("evidence %s: episode has only %d tool calls", ev, len(e.ToolCalls))
		}
	case EvMemoryWrite:
		before := make(map[string]string, len(e.MemoryDiff.Before))
		for _, m := range e.MemoryDiff.Before {
			before[m.Key] = m.Value
		}
		for _, m := range e.MemoryDiff.After {
			if m.Key != ev.Ref {
				continue
			}
			if old, had := before[m.Key]; had && old == m.Value {
				return fmt.Errorf("evidence %s: key exists but was not written or changed in this episode", ev)
			}
			return nil
		}
		return fmt.Errorf("evidence %s: key not present in memory_diff.after", ev)
	case EvEpisode:
		if ev.Ref != "final" {
			return fmt.Errorf("evidence %s: only episode:final is allowed", ev)
		}
	default:
		return fmt.Errorf("evidence %s: unknown kind", ev)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Verdict (THYMUS -> PLASMA / MARROW)
// ---------------------------------------------------------------------------

// Verdict is the judge's ruling on one episode. MARROW rejects any verdict
// whose evidence_pointer is missing, malformed, or (see ValidateAgainst) does
// not resolve inside the episode.
type Verdict struct {
	EpisodeID       string    `json:"episode_id"`
	Ruling          Ruling    `json:"ruling"`
	EvidencePointer string    `json:"evidence_pointer"`
	Confidence      float64   `json:"confidence"`
	JudgeTier       JudgeTier `json:"judge_tier"`
	Rationale       string    `json:"rationale"`
}

// RecordID implements Record (episode id; one episode may have several verdicts).
func (v Verdict) RecordID() string { return v.EpisodeID }

// MaxRationaleSentences is the handbook limit.
const MaxRationaleSentences = 3

const maxRationaleBytes = 800

var sentenceEnd = regexp.MustCompile(`[.!?]+(?:\s|$)`)

func sentenceCount(s string) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	n := len(sentenceEnd.FindAllStringIndex(s, -1))
	if last := s[len(s)-1]; last != '.' && last != '!' && last != '?' {
		n++
	}
	return n
}

// Validate checks a Verdict in isolation.
func (v Verdict) Validate() error {
	var p problems
	if !idRe.MatchString(v.EpisodeID) {
		p.addf("episode_id %q must match %s", v.EpisodeID, idRe)
	}
	if !v.Ruling.Valid() {
		p.addf("ruling %q invalid", v.Ruling)
	}
	if v.EvidencePointer == "" {
		p.addf("evidence_pointer is required: a verdict without evidence is unusable")
	} else if ev, err := ParseEvidence(v.EvidencePointer); err != nil {
		p.addf("%v", err)
	} else if v.Ruling == RulingBreach && ev.Kind == EvEpisode {
		p.addf("a BREACH must name the exact tool call, turn or memory write, not episode:final")
	}
	if math.IsNaN(v.Confidence) || v.Confidence < 0 || v.Confidence > 1 {
		p.addf("confidence %v outside [0,1]", v.Confidence)
	}
	if !v.JudgeTier.Valid() {
		p.addf("judge_tier %q invalid (want fast or deep)", v.JudgeTier)
	}
	switch n := sentenceCount(v.Rationale); {
	case n == 0:
		p.addf("rationale is empty")
	case n > MaxRationaleSentences:
		p.addf("rationale has %d sentences, max %d", n, MaxRationaleSentences)
	}
	if len(v.Rationale) > maxRationaleBytes {
		p.addf("rationale is %d bytes, max %d", len(v.Rationale), maxRationaleBytes)
	}
	return p.err("verdict", v.EpisodeID)
}

// ValidateAgainst validates the verdict and also resolves its evidence
// pointer inside the episode it rules on.
func (v Verdict) ValidateAgainst(ep Episode) error {
	if err := v.Validate(); err != nil {
		return err
	}
	var p problems
	if v.EpisodeID != ep.ID {
		p.addf("verdict is for episode %q but was checked against %q", v.EpisodeID, ep.ID)
	}
	if ev, err := ParseEvidence(v.EvidencePointer); err == nil {
		if rerr := ep.Resolve(ev); rerr != nil {
			p.addf("%v", rerr)
		}
	}
	return p.err("verdict", v.EpisodeID)
}