// Package auditlog appends audit events as JSONL, one file per UTC day.
//
// Writes are single O_APPEND calls so several concurrent shims (one per
// wrapped server) interleave whole lines without locking. Files are 0600 —
// the log reveals which tools ran when, which is nobody else's business.
package auditlog

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/alexverify/eyebrow/internal/domain/audit"
)

// Sink writes events under a directory, satisfying ports.AuditSink.
type Sink struct {
	dir string
}

// New returns a Sink rooted at dir (created on first emit).
func New(dir string) *Sink { return &Sink{dir: dir} }

// Emit appends one event to the day file matching e.At (UTC).
func (s *Sink) Emit(_ context.Context, e audit.Event) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, e.At.UTC().Format("2006-01-02")+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}
