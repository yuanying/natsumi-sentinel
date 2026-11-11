package github_test

import (
	"fmt"
	"strings"
	"testing"
)

const (
	zero = "0000000000000000000000000000000000000000"
	oidA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	oidB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	oidC = "cccccccccccccccccccccccccccccccccccccccc"
)

// pkt writes one pkt-line.
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// push is a receive-pack request: the commands, a flush, and a pack.
func push(commands ...string) string {
	var b strings.Builder
	for i, c := range commands {
		if i == 0 {
			c += "\x00report-status side-band-64k agent=git/2.50"
		}
		b.WriteString(pkt(c + "\n"))
	}
	b.WriteString("0000")
	b.WriteString("PACK\x00\x00\x00\x02binary pack data")
	return b.String()
}

func TestAFetchOrACloneGoesThroughAsARead(t *testing.T) {
	w := newWorld(t)
	for _, tc := range []struct{ method, path string }{
		{"GET", "/o/r.git/info/refs"},
		{"POST", "/o/r.git/git-upload-pack"},
		{"POST", "/o/r/git-upload-pack"},
	} {
		res, err := w.read("git.example.com", tc.method, tc.path, "0000")
		if err != nil || !res.Read {
			t.Errorf("%s %s: %+v, %v", tc.method, tc.path, res, err)
		}
	}
}

func TestEachRefOfAPushIsAnOperationNamedByItsKindAndRef(t *testing.T) {
	w := newWorld(t)
	body := push(
		zero+" "+oidA+" refs/heads/feature/x",
		oidB+" "+zero+" refs/heads/old",
	)
	res := w.must("git.example.com", "POST", "/Example/R.git/git-receive-pack", body)
	if len(res.Operations) != 2 {
		t.Fatalf("operations = %+v", res.Operations)
	}
	create, del := res.Operations[0], res.Operations[1]
	if create.Name != "git.branch.push" || params(create.Params) != "owner=example repo=r ref=refs/heads/feature/x branch=feature/x sha="+oidA || strings.Join(create.Target, " ") != "owner repo ref" {
		t.Errorf("create = %+v", create)
	}
	if params(create.Facts) != "kind=create" {
		t.Errorf("create's facts = %s", params(create.Facts))
	}
	if del.Name != "git.branch.delete" || params(del.Params) != "owner=example repo=r ref=refs/heads/old" || params(del.Facts) != "kind=delete old="+oidB {
		t.Errorf("delete = %+v", del)
	}
	if create.Fingerprint == "" || create.Fingerprint == del.Fingerprint {
		t.Errorf("fingerprints = %q, %q; want one of each ref's own", create.Fingerprint, del.Fingerprint)
	}
	if res.Request == nil || res.Request.Text != zero+" "+oidA+" refs/heads/feature/x\n"+oidB+" "+zero+" refs/heads/old\n" || res.Request.Binary {
		t.Errorf("kept = %+v; want the commands only", res.Request)
	}
	if len(w.gh.requests()) != 0 {
		t.Error("the gate asked upstream about a create and a delete")
	}
}

func TestAnUpdateIsAForcePushWhenUpstreamSaysTheNewCommitDoesNotFollowTheOld(t *testing.T) {
	w := newWorld(t)
	w.gh.compare[oidA+"..."+oidB] = "ahead"
	w.gh.compare[oidA+"..."+oidC] = "diverged"
	w.gh.compare[oidB+"..."+oidA] = "behind"
	for _, tc := range []struct{ old, new, kind, op string }{
		{oidA, oidB, "update", "git.branch.push"},
		{oidA, oidC, "force", "git.branch.force"},
		{oidB, oidA, "force", "git.branch.force"},
		{oidC, oidA, "update", "git.branch.push"},
	} {
		res := w.must("git.example.com", "POST", "/o/r.git/git-receive-pack", push(tc.old+" "+tc.new+" refs/heads/main"))
		op := res.Operations[0]
		if op.Name != tc.op || !strings.HasPrefix(params(op.Facts), "kind="+tc.kind) {
			t.Errorf("%s...%s: %s %s; want %s", tc.old[:1], tc.new[:1], op.Name, params(op.Facts), tc.op)
		}
	}
	for _, r := range w.gh.requests() {
		if r.Header.Get("Authorization") != surrogate || !strings.HasPrefix(r.URL.Path, "/repos/o/r/compare/") {
			t.Errorf("asked %s with %q", r.URL.Path, r.Header.Get("Authorization"))
		}
	}
}

func TestAnUpdateUpstreamCannotCompareIsNotRefusedButSaysSo(t *testing.T) {
	w := newWorld(t)
	res := w.must("git.example.com", "POST", "/o/r.git/git-receive-pack", push(oidC+" "+oidA+" refs/heads/main"))
	if got := params(res.Operations[0].Facts); got != "kind=update old="+oidC+" fastForward=unknown" {
		t.Errorf("facts = %s", got)
	}
	w.gh.fail = true
	if _, err := w.read("git.example.com", "POST", "/o/r.git/git-receive-pack", push(oidA+" "+oidB+" refs/heads/main")); err == nil {
		t.Error("an upstream that does not answer was taken")
	}
}

func TestATagPushedShowsItsCommitAndWhetherItIsOnTheDefaultBranch(t *testing.T) {
	w := newWorld(t)
	w.gh.repos["o/r"] = "main"
	w.gh.compare["main..."+oidA] = "behind"
	res := w.must("git.example.com", "POST", "/o/r.git/git-receive-pack", push(zero+" "+oidA+" refs/tags/v1.0.0"))
	op := res.Operations[0]
	if op.Name != "git.tag.create" || params(op.Params) != "owner=o repo=r ref=refs/tags/v1.0.0 tag=v1.0.0 sha="+oidA {
		t.Errorf("operation = %+v", op)
	}
	if params(op.Facts) != "kind=create commit="+oidA+" defaultBranch=main onDefaultBranch=true" {
		t.Errorf("facts = %s", params(op.Facts))
	}
}

func TestARefNoPushRuleNamesIsARawOperation(t *testing.T) {
	w := newWorld(t)
	res := w.must("git.example.com", "POST", "/o/r.git/git-receive-pack", push(zero+" "+oidA+" refs/notes/commits"))
	if op := res.Operations[0]; op.Name != "" || params(op.Params) != "owner=o repo=r ref=refs/notes/commits sha="+oidA {
		t.Errorf("operation = %+v", op)
	}
}

func TestShallowLinesBeforeTheCommandsAreSkipped(t *testing.T) {
	w := newWorld(t)
	body := pkt("shallow "+oidC+"\n") + push(zero+" "+oidA+" refs/heads/x")
	res := w.must("git.example.com", "POST", "/o/r.git/git-receive-pack", body)
	if len(res.Operations) != 1 || res.Operations[0].Name != "git.branch.push" {
		t.Errorf("operations = %+v", res.Operations)
	}
}

func TestAPushWhoseCommandsCannotBeReadIsRefused(t *testing.T) {
	w := newWorld(t)
	for name, body := range map[string]string{
		"no flush":            pkt(zero + " " + oidA + " refs/heads/x\x00caps\n"),
		"not pkt-lines":       "hello",
		"a bad length":        "00zz",
		"no command":          "0000PACK",
		"a short object id":   push(zero[:39] + " " + oidA + " refs/heads/x"),
		"not a ref":           push(zero + " " + oidA + " HEAD"),
		"a space in the ref":  push(zero + " " + oidA + " refs/heads/a b"),
		"a push certificate":  pkt("push-cert\x00caps\n") + "0000",
		"the same ref twice":  push(zero+" "+oidA+" refs/heads/x", zero+" "+oidB+" refs/heads/x"),
		"nothing to change":   push(zero + " " + zero + " refs/heads/x"),
		"a line after flush?": pkt(zero+" "+oidA+" refs/heads/x\x00caps\n") + pkt("garbage"),
	} {
		res, err := w.read("git.example.com", "POST", "/o/r.git/git-receive-pack", body)
		if err != nil || res.Refusal == "" {
			t.Errorf("%s: %+v, %v", name, res, err)
		}
	}
	req := w.request("git.example.com", "POST", "/o/r.git/git-receive-pack", push(zero+" "+oidA+" refs/heads/x"))
	req.Header.Set("Content-Encoding", "gzip")
	if res, _ := w.c.Read(t.Context(), req); !strings.Contains(res.Refusal, "Content-Encoding") {
		t.Errorf("a compressed push: %+v", res)
	}
	if res, _ := w.read("git.example.com", "POST", "/o/git-receive-pack", push(zero+" "+oidA+" refs/heads/x")); res.Refusal == "" {
		t.Errorf("a push to no repository: %+v", res)
	}
}

func TestAPushCutOffAfterItsCommandsIsReadFromWhatWasRead(t *testing.T) {
	w := newWorld(t)
	body := push(zero + " " + oidA + " refs/heads/x")
	req := w.request("git.example.com", "POST", "/o/r.git/git-receive-pack", body[:strings.Index(body, "PACK")+2])
	req.BodyComplete = false
	res, err := w.c.Read(t.Context(), req)
	if err != nil || len(res.Operations) != 1 {
		t.Errorf("Read = %+v, %v", res, err)
	}
}
