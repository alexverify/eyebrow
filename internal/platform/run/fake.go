package run

import (
	"context"
	"fmt"
	"strings"
)

// FakeResponse is a scripted result for one command invocation.
type FakeResponse struct {
	Out []byte
	Err error
}

// Fake is a scripted Runner for tests. Responses are keyed by the full command
// line ("name arg1 arg2 ..."). It records every call in Calls.
type Fake struct {
	Responses map[string]FakeResponse
	Calls     []string
}

// Run satisfies Runner.
func (f *Fake) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	f.Calls = append(f.Calls, key)
	r, ok := f.Responses[key]
	if !ok {
		return nil, fmt.Errorf("fake runner: no scripted response for %q", key)
	}
	return r.Out, r.Err
}
