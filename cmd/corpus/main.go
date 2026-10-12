// Command corpus is the ANTIGEN corpus tooling.
//
//	corpus lint           -attacks A[,B..] [-benign C[,D..]] [-strict] [-min-attacks N] [-min-seeds N] [-min-twins N]
//	corpus twins          -attacks A[,B..]  -benign C[,D..]  [-min-twins N]
//	corpus split          -attacks A[,B..]  -benign C[,D..]  -holdout FAMILY -out DIR
//	corpus verify-holdout -lock holdout.lock.json -attacks A[,B..] [-benign C[,D..]]
//
// Exit codes: 0 ok, 1 findings that fail the check, 2 usage or I/O error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"immunis/contract"
	"immunis/corpus"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `usage:
  corpus lint           -attacks A[,B..] [-benign C[,D..]] [-strict] [-min-attacks N] [-min-seeds N] [-min-twins N]
  corpus twins          -attacks A[,B..]  -benign C[,D..]  [-min-twins N]
  corpus split          -attacks A[,B..]  -benign C[,D..]  -holdout FAMILY -out DIR
  corpus verify-holdout -lock holdout.lock.json -attacks A[,B..] [-benign C[,D..]]
`

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "lint":
		return cmdLint(args[1:], stdout, stderr)
	case "twins":
		return cmdTwins(args[1:], stdout, stderr)
	case "split":
		return cmdSplit(args[1:], stdout, stderr)
	case "verify-holdout":
		return cmdVerify(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
	return 2
}

func paths(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func load(attacks, benign string, needBenign bool, stderr io.Writer) (*corpus.Corpus, bool) {
	a, b := paths(attacks), paths(benign)
	if len(a) == 0 {
		fmt.Fprintln(stderr, "-attacks is required")
		return nil, false
	}
	if needBenign && len(b) == 0 {
		fmt.Fprintln(stderr, "-benign is required")
		return nil, false
	}
	c, err := corpus.Load(a, b)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return nil, false
	}
	return c, true
}

func cmdLint(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(stderr)
	d := corpus.DefaultOptions()
	attacks := fs.String("attacks", "", "attack JSONL file(s), comma separated")
	benign := fs.String("benign", "", "benign twin JSONL file(s), comma separated")
	strict := fs.Bool("strict", false, "fail on warnings too")
	minAttacks := fs.Int("min-attacks", d.MinAttacks, "minimum total attacks")
	minSeeds := fs.Int("min-seeds", d.MinSeedsPerFamily, "minimum generation-0 attacks per family")
	minTwins := fs.Int("min-twins", d.MinTwins, "minimum benign twins overall")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, ok := load(*attacks, *benign, false, stderr)
	if !ok {
		return 2
	}
	rep := corpus.Lint(c, corpus.Options{MinAttacks: *minAttacks, MinSeedsPerFamily: *minSeeds, MinTwins: *minTwins})
	rep.Write(stdout)
	if rep.Failed(*strict) {
		return 1
	}
	return 0
}

func cmdTwins(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("twins", flag.ContinueOnError)
	fs.SetOutput(stderr)
	attacks := fs.String("attacks", "", "attack JSONL file(s), comma separated")
	benign := fs.String("benign", "", "benign twin JSONL file(s), comma separated")
	minTwins := fs.Int("min-twins", corpus.DefaultOptions().MinTwins, "minimum benign twins overall")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, ok := load(*attacks, *benign, true, stderr)
	if !ok {
		return 2
	}
	gaps := corpus.TwinGaps(c)
	orphans := corpus.OrphanTwins(c)
	for _, g := range gaps {
		fmt.Fprintf(stdout, "MISSING TWIN  %-28s %-14s %-12s %s:%d\n", g.Attack.ID, g.Attack.Family, g.Attack.Surface, g.Origin.File, g.Origin.Line)
	}
	for _, b := range orphans {
		fmt.Fprintf(stdout, "ORPHAN TWIN   %-28s twin_of=%q is not an attack\n", b.ID, b.TwinOf)
	}
	seeds := 0
	for _, a := range c.Attacks {
		if a.Generation == 0 {
			seeds++
		}
	}
	fmt.Fprintf(stdout, "%d seed attacks, %d with a twin; %d benign twins (need >= %d)\n", seeds, seeds-len(gaps), len(c.Benign), *minTwins)
	if len(gaps) > 0 || len(orphans) > 0 || len(c.Benign) < *minTwins {
		return 1
	}
	return 0
}

func cmdSplit(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("split", flag.ContinueOnError)
	fs.SetOutput(stderr)
	attacks := fs.String("attacks", "", "attack JSONL file(s), comma separated")
	benign := fs.String("benign", "", "benign twin JSONL file(s), comma separated")
	holdout := fs.String("holdout", "", "family to hold out of the patch loop")
	out := fs.String("out", "", "output directory")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *holdout == "" || *out == "" {
		fmt.Fprintln(stderr, "-holdout and -out are required")
		return 2
	}
	c, ok := load(*attacks, *benign, true, stderr)
	if !ok {
		return 2
	}
	if len(c.LoadIssues) > 0 {
		for _, i := range c.LoadIssues {
			fmt.Fprintln(stderr, i)
		}
		fmt.Fprintln(stderr, "refusing to split a corpus that does not validate: run `corpus lint` and fix the errors first")
		return 2
	}
	var prior *corpus.Lock
	lockPath := filepath.Join(*out, corpus.LockFile)
	if l, err := corpus.ReadLock(lockPath); err == nil {
		prior = &l
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, err)
		return 2
	}
	loop, held, lock, err := corpus.Split(c, contract.Family(*holdout), prior)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	// The loop side must be clean by construction; verify it anyway.
	if leaks := corpus.VerifyHoldout(lock, loop); len(leaks) > 0 {
		for _, i := range leaks {
			fmt.Fprintln(stderr, i)
		}
		return 2
	}
	if err := corpus.WriteSplit(*out, loop, held, lock); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	verb := "locked"
	if prior != nil {
		verb = "re-split under the existing lock"
	}
	fmt.Fprintf(stdout, "holdout family %q %s\n", lock.HoldoutFamily, verb)
	fmt.Fprintf(stdout, "  loop:    %3d attacks, %3d benign twins  -> %s, %s\n", len(loop.Attacks), len(loop.Benign), corpus.LoopAttacksFile, corpus.LoopBenignFile)
	fmt.Fprintf(stdout, "  holdout: %3d attacks, %3d benign twins  -> %s, %s\n", len(held.Attacks), len(held.Benign), corpus.HoldoutAttacksFile, corpus.HoldoutBenignFile)
	fmt.Fprintf(stdout, "  lock:    %s (digest %s)\n", corpus.LockFile, lock.Digest[:12])
	fmt.Fprintln(stdout, "Only the loop-* files may feed MARROW, PLASMA and the patch loop.")
	return 0
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-holdout", flag.ContinueOnError)
	fs.SetOutput(stderr)
	lockPath := fs.String("lock", "", "holdout.lock.json")
	attacks := fs.String("attacks", "", "loop-side attack JSONL file(s), comma separated")
	benign := fs.String("benign", "", "loop-side benign JSONL file(s), comma separated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *lockPath == "" {
		fmt.Fprintln(stderr, "-lock is required")
		return 2
	}
	lock, err := corpus.ReadLock(*lockPath)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	c, ok := load(*attacks, *benign, false, stderr)
	if !ok {
		return 2
	}
	issues := corpus.VerifyHoldout(lock, c)
	for _, i := range c.LoadIssues {
		fmt.Fprintln(stdout, i)
	}
	for _, i := range issues {
		fmt.Fprintln(stdout, i)
	}
	if len(issues) > 0 || len(c.LoadIssues) > 0 {
		fmt.Fprintf(stdout, "FAIL: %d leak(s), %d load error(s)\n", len(issues), len(c.LoadIssues))
		return 1
	}
	fmt.Fprintf(stdout, "OK: %d attacks and %d benign twins checked against holdout %q, no leaks\n", len(c.Attacks), len(c.Benign), lock.HoldoutFamily)
	return 0
}
