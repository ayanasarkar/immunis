package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"immunis/contract"
)

// LockVersion is the lock file format version.
const LockVersion = 1

// Lock is holdout.lock.json. It records which records were held out of the
// patch loop so that leakage can be detected later. It stores SHA-256 hashes
// of the held-out payloads, not the payloads, so the lock can sit in a shared
// repo without handing the loop the held-out text.
type Lock struct {
	Version       int             `json:"version"`
	HoldoutFamily contract.Family `json:"holdout_family"`
	AttackIDs     []string        `json:"attack_ids"`
	BenignIDs     []string        `json:"benign_ids"`
	PayloadSHA256 []string        `json:"payload_sha256"`
	Digest        string          `json:"digest"`
}

func payloadHash(s string) string {
	sum := sha256.Sum256([]byte(normText(s)))
	return hex.EncodeToString(sum[:])
}

func (l Lock) computeDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "v%d\n%s\n", l.Version, l.HoldoutFamily)
	for _, group := range [][]string{l.AttackIDs, l.BenignIDs, l.PayloadSHA256} {
		h.Write([]byte(strings.Join(group, ",")))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Check verifies the lock is well formed and has not been edited by hand.
func (l Lock) Check() error {
	switch {
	case l.Version != LockVersion:
		return fmt.Errorf("lock version %d, this tool reads version %d", l.Version, LockVersion)
	case !l.HoldoutFamily.Valid():
		return fmt.Errorf("lock holdout_family %q is not one of the six families", l.HoldoutFamily)
	case len(l.AttackIDs) == 0:
		return fmt.Errorf("lock holds out no attacks")
	case l.Digest != l.computeDigest():
		return fmt.Errorf("lock digest mismatch: the file was edited by hand or corrupted")
	}
	return nil
}

// ReadLock loads and checks a lock file.
func ReadLock(path string) (Lock, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	var l Lock
	if err := contract.DecodeStrict(bytes.TrimPrefix(b, utf8BOM), &l); err != nil {
		return Lock{}, fmt.Errorf("%s: %w", path, err)
	}
	if err := l.Check(); err != nil {
		return Lock{}, fmt.Errorf("%s: %w", path, err)
	}
	return l, nil
}

// Split divides c into the corpus the patch loop may see and the held-out
// corpus. An attack is held out when its family is the holdout family, or
// when any ancestor's family is (a mutant never launders a held-out seed back
// into the loop). Benign twins follow their attack: a twin is near-identical
// to the attack, so leaving it in the loop's benign suite would leak the
// held-out family's shape.
//
// prior is the existing lock, if any. The holdout cannot change once set: the
// family must match and every previously locked record must still be held out.
func Split(c *Corpus, family contract.Family, prior *Lock) (loop, holdout *Corpus, lock Lock, err error) {
	if !family.Valid() {
		return nil, nil, Lock{}, fmt.Errorf("%q is not one of the six families", family)
	}
	if prior != nil && prior.HoldoutFamily != family {
		return nil, nil, Lock{}, fmt.Errorf("holdout is already locked to family %q; changing it now would leak the old holdout into the loop", prior.HoldoutFamily)
	}
	idx := c.attackIndex()
	loop, holdout = &Corpus{}, &Corpus{}
	held := map[string]bool{}
	for i, a := range c.Attacks {
		isHeld := a.Family == family
		for _, anc := range ancestors(a, idx, c.Attacks) {
			if anc.Family == family {
				isHeld = true
			}
		}
		if isHeld {
			held[a.ID] = true
			holdout.Attacks = append(holdout.Attacks, a)
			holdout.AttackOrigin = append(holdout.AttackOrigin, c.AttackOrigin[i])
		} else {
			loop.Attacks = append(loop.Attacks, a)
			loop.AttackOrigin = append(loop.AttackOrigin, c.AttackOrigin[i])
		}
	}
	if len(holdout.Attacks) == 0 {
		return nil, nil, Lock{}, fmt.Errorf("no attacks in family %q: nothing to hold out", family)
	}
	heldBenign := map[string]bool{}
	for i, b := range c.Benign {
		if held[b.TwinOf] {
			heldBenign[b.ID] = true
			holdout.Benign = append(holdout.Benign, b)
			holdout.BenignOrigin = append(holdout.BenignOrigin, c.BenignOrigin[i])
		} else {
			loop.Benign = append(loop.Benign, b)
			loop.BenignOrigin = append(loop.BenignOrigin, c.BenignOrigin[i])
		}
	}
	if prior != nil {
		for _, id := range prior.AttackIDs {
			if !held[id] {
				return nil, nil, Lock{}, fmt.Errorf("locked holdout attack %q is missing from the corpus or no longer held out", id)
			}
		}
		for _, id := range prior.BenignIDs {
			if !heldBenign[id] {
				return nil, nil, Lock{}, fmt.Errorf("locked holdout benign twin %q is missing from the corpus or no longer held out", id)
			}
		}
	}
	hashes := map[string]bool{}
	for _, a := range holdout.Attacks {
		hashes[payloadHash(a.Payload)] = true
	}
	lock = Lock{
		Version:       LockVersion,
		HoldoutFamily: family,
		AttackIDs:     sortedKeys(held),
		BenignIDs:     sortedKeys(heldBenign),
		PayloadSHA256: sortedKeys(hashes),
	}
	if lock.BenignIDs == nil {
		lock.BenignIDs = []string{}
	}
	lock.Digest = lock.computeDigest()
	return loop, holdout, lock, nil
}

// Output file names written by WriteSplit.
const (
	LoopAttacksFile    = "loop-attacks.jsonl"
	LoopBenignFile     = "loop-benign.jsonl"
	HoldoutAttacksFile = "holdout-attacks.jsonl"
	HoldoutBenignFile  = "holdout-benign.jsonl"
	LockFile           = "holdout.lock.json"
)

// WriteSplit validates and writes the four JSONL files and the lock into dir.
func WriteSplit(dir string, loop, holdout *Corpus, lock Lock) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	type job struct {
		name string
		data func(*bytes.Buffer) error
	}
	attacks := func(c *Corpus) func(*bytes.Buffer) error {
		return func(b *bytes.Buffer) error { return contract.WriteJSONL(b, c.Attacks) }
	}
	benign := func(c *Corpus) func(*bytes.Buffer) error {
		return func(b *bytes.Buffer) error { return contract.WriteJSONL(b, c.Benign) }
	}
	jobs := []job{
		{LoopAttacksFile, attacks(loop)}, {LoopBenignFile, benign(loop)},
		{HoldoutAttacksFile, attacks(holdout)}, {HoldoutBenignFile, benign(holdout)},
	}
	// Render everything first so a validation failure leaves no half-written split.
	rendered := make([][]byte, len(jobs))
	for i, j := range jobs {
		var b bytes.Buffer
		if err := j.data(&b); err != nil {
			return fmt.Errorf("%s: %w", j.name, err)
		}
		rendered[i] = b.Bytes()
	}
	lb, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return err
	}
	for i, j := range jobs {
		if err := os.WriteFile(filepath.Join(dir, j.name), rendered[i], 0o644); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, LockFile), append(lb, '\n'), 0o644)
}

// VerifyHoldout checks that the loop-side files contain nothing the lock held
// out. Every finding is an error: a leak invalidates the transfer result.
func VerifyHoldout(l Lock, loop *Corpus) []Issue {
	var out []Issue
	if err := l.Check(); err != nil {
		return []Issue{{SevError, LockFile, 0, "", err.Error()}}
	}
	lockedA := map[string]bool{}
	for _, id := range l.AttackIDs {
		lockedA[id] = true
	}
	lockedB := map[string]bool{}
	for _, id := range l.BenignIDs {
		lockedB[id] = true
	}
	lockedHash := map[string]bool{}
	for _, h := range l.PayloadSHA256 {
		lockedHash[h] = true
	}
	flag := func(o Origin, id, format string, a ...any) {
		out = append(out, Issue{SevError, o.File, o.Line, id, "HOLDOUT LEAK: " + fmt.Sprintf(format, a...)})
	}
	idx := loop.attackIndex()
	for i, a := range loop.Attacks {
		o := loop.AttackOrigin[i]
		switch {
		case lockedA[a.ID]:
			flag(o, a.ID, "attack is locked in the holdout")
		case a.Family == l.HoldoutFamily:
			flag(o, a.ID, "attack belongs to the held-out family %q", l.HoldoutFamily)
		case lockedA[a.ParentID]:
			flag(o, a.ID, "mutant of held-out attack %q", a.ParentID)
		case lockedHash[payloadHash(a.Payload)]:
			flag(o, a.ID, "payload is identical to a held-out attack")
		default:
			for _, anc := range ancestors(a, idx, loop.Attacks) {
				if anc.Family == l.HoldoutFamily {
					flag(o, a.ID, "descends from %q of the held-out family", anc.ID)
					break
				}
			}
		}
	}
	for i, b := range loop.Benign {
		o := loop.BenignOrigin[i]
		switch {
		case lockedB[b.ID]:
			flag(o, b.ID, "benign twin is locked in the holdout")
		case lockedA[b.TwinOf]:
			flag(o, b.ID, "twin of held-out attack %q", b.TwinOf)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}
