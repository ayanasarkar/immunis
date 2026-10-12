// Command thymus is the THYMUS judge CLI.
//
//	thymus decode    [-secret S] [-domain D] <text | ->     show every decoded view and any hidden secret
//	thymus calibrate -cases cases.jsonl                      compare the judge with your hand labels
//	thymus judge     -cases cases.jsonl [-json]              rule on each case, print verdicts
//
// Exit codes: 0 ok, 1 calibration failed, 2 usage or input error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"immunis/contract"
	"immunis/thymus"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

const usage = `usage:
  thymus decode    [-secret S] [-domain D] <text | ->
  thymus calibrate -cases cases.jsonl
  thymus judge     -cases cases.jsonl [-json]
`

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "decode":
		return cmdDecode(args[1:], stdin, stdout, stderr)
	case "calibrate":
		return cmdCalibrate(args[1:], stdout, stderr)
	case "judge":
		return cmdJudge(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "unknown command %q\n%s", args[0], usage)
	return 2
}

func cmdDecode(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decode", flag.ContinueOnError)
	fs.SetOutput(stderr)
	secretFlag := fs.String("secret", "", "secret to look for (default: every configured canary)")
	domain := fs.String("domain", "", "domain to look for (default: configured attacker domains)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "decode needs exactly one argument: the text, or - to read stdin")
		return 2
	}
	text := fs.Arg(0)
	if text == "-" {
		b, err := io.ReadAll(io.LimitReader(stdin, thymus.MaxViewBytes+1))
		if err != nil {
			fmt.Fprintln(stderr, "read stdin:", err)
			return 2
		}
		text = string(b)
	}
	views := thymus.Decode(text)
	fmt.Fprintf(stdout, "%d view(s):\n", len(views))
	for i, v := range views {
		shown := strings.NewReplacer("\n", "\\n", "\r", "\\r").Replace(v.Text)
		if len(shown) > 100 {
			shown = shown[:100] + "..."
		}
		fmt.Fprintf(stdout, "  %2d. [%s] %q\n", i, v.PathString(), shown)
	}
	cfg := thymus.DefaultConfig()
	secrets := cfg.Canaries
	if *secretFlag != "" {
		secrets = map[string]string{"given": *secretFlag}
	}
	names := make([]string, 0, len(secrets))
	for n := range secrets {
		names = append(names, n)
	}
	sort.Strings(names)
	found := false
	for _, n := range names {
		if m, ok := thymus.FindSecret(views, secrets[n]); ok {
			kind := "FULL"
			if m.Partial {
				kind = "PARTIAL"
			}
			fmt.Fprintf(stdout, "FOUND %s secret %q via %s\n", kind, n, m.Via)
			found = true
		}
	}
	domains := cfg.AttackerDomains
	if *domain != "" {
		domains = []string{*domain}
	}
	for _, d := range domains {
		if via, ok := thymus.ContainsFold(views, d); ok {
			fmt.Fprintf(stdout, "FOUND domain %q via %s\n", d, via)
			found = true
		}
	}
	if !found {
		fmt.Fprintln(stdout, "nothing found")
	}
	return 0
}

func loadCases(path string) ([]thymus.Case, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return thymus.LoadCases(f)
}

func casesFlag(name string, args []string, stderr io.Writer) (*flag.FlagSet, *string, bool) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("cases", "", "JSONL file of hand-labelled cases")
	return fs, path, true
}

func cmdCalibrate(args []string, stdout, stderr io.Writer) int {
	fs, path, _ := casesFlag("calibrate", args, stderr)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "calibrate needs -cases <file.jsonl>")
		return 2
	}
	cases, err := loadCases(*path)
	if err != nil {
		fmt.Fprintln(stderr, "load cases:", err)
		return 2
	}
	j, err := thymus.New(thymus.DefaultConfig(), nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	rep := thymus.Calibrate(context.Background(), j, cases)
	fmt.Fprintf(stdout, "cases: %d   agree: %d   clear: %d   clear-agree: %d\n", rep.Total, rep.Agree, rep.Clear, rep.ClearAgree)
	fmt.Fprintln(stdout, "judge distribution:")
	for _, r := range []contract.Ruling{contract.RulingBreach, contract.RulingBlocked, contract.RulingDegraded, contract.RulingAutoimmune} {
		fmt.Fprintf(stdout, "  %-10s %d\n", r, rep.Distribution[r])
	}
	for _, d := range rep.Disagreements {
		tag := "CLEAR"
		if d.Borderline {
			tag = "borderline"
		}
		fmt.Fprintf(stdout, "DISAGREE [%s] %s: you=%s judge=%s\n    %s\n", tag, d.Name, d.Label, d.Got, d.Rationale)
	}
	for _, e := range rep.Errors {
		fmt.Fprintln(stdout, "ERROR", e)
	}
	for _, w := range rep.Warnings {
		fmt.Fprintln(stdout, "WARNING", w)
	}
	if rep.Passed() {
		fmt.Fprintln(stdout, "RESULT: PASS (judge agrees with you on every clear case)")
		return 0
	}
	fmt.Fprintln(stdout, "RESULT: FAIL")
	return 1
}

func cmdJudge(args []string, stdout, stderr io.Writer) int {
	fs, path, _ := casesFlag("judge", args, stderr)
	asJSON := fs.Bool("json", false, "emit one verdict JSON object per line")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *path == "" {
		fmt.Fprintln(stderr, "judge needs -cases <file.jsonl>")
		return 2
	}
	cases, err := loadCases(*path)
	if err != nil {
		fmt.Fprintln(stderr, "load cases:", err)
		return 2
	}
	j, err := thymus.New(thymus.DefaultConfig(), nil)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	status := 0
	for _, c := range cases {
		res, err := j.Rule(context.Background(), c.Input())
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", c.Name, err)
			status = 2
			continue
		}
		if *asJSON {
			if err := enc.Encode(res.Verdict); err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
			continue
		}
		v := res.Verdict
		fmt.Fprintf(stdout, "%-34s %-10s %-24s conf=%.2f score=%.2f esc=%s\n", c.Name, v.Ruling, v.EvidencePointer, v.Confidence, res.Score, orDash(res.EscalationReason))
	}
	return status
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}