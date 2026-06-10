package run

import (
	"context"
	"errors"
	"testing"
)

func TestFakeReturnsScriptedResponseAndRecordsCalls(t *testing.T) {
	f := &Fake{Responses: map[string]FakeResponse{
		"npm view pkg@1.0.0 version --json": {Out: []byte(`"1.0.0"`)},
	}}
	out, err := f.Run(context.Background(), "npm", "view", "pkg@1.0.0", "version", "--json")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if string(out) != `"1.0.0"` {
		t.Fatalf("out = %q", out)
	}
	if len(f.Calls) != 1 || f.Calls[0] != "npm view pkg@1.0.0 version --json" {
		t.Fatalf("Calls = %v", f.Calls)
	}
}

func TestFakeErrorsOnUnscriptedCall(t *testing.T) {
	f := &Fake{}
	if _, err := f.Run(context.Background(), "git", "status"); err == nil {
		t.Fatal("expected error for unscripted call")
	}
}

func TestFakePropagatesScriptedError(t *testing.T) {
	want := errors.New("boom")
	f := &Fake{Responses: map[string]FakeResponse{"x": {Err: want}}}
	if _, err := f.Run(context.Background(), "x"); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
