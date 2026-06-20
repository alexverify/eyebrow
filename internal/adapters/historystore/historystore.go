// Package historystore appends and reads counts-only posture snapshots to a
// local JSONL file (~/.eyebrow/history.jsonl), the data behind the posture trend.
// It never stores artifact content — only the aggregate verdict counts.
package historystore

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexverify/eyebrow/internal/domain/posture"
)

// Append adds one snapshot as a JSON line, creating the file and its parent
// directory as needed. Append-only keeps writes cheap and the history immutable.
func Append(path string, p posture.Posture) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

// Read loads every snapshot, oldest first. A missing file yields no snapshots
// and no error; an unparseable line is skipped so one bad write never hides the
// rest of the trend.
func Read(path string) ([]posture.Posture, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []posture.Posture
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var p posture.Posture
		if json.Unmarshal([]byte(line), &p) == nil {
			out = append(out, p)
		}
	}
	return out, nil
}
