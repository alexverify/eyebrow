// Package repstore loads an opt-in community reputation corpus (theme H3) from a
// local JSON file: a content-hash → Signal map the user chose to trust. Keeping
// it a local file makes the privacy model structural — a reputation query is a
// map lookup, so no hash ever leaves the machine. A missing file is a silent
// no-op (empty corpus, no error), exactly like the advisory feed offline.
package repstore

import (
	"encoding/json"
	"os"

	"github.com/alexverify/eyebrow/internal/domain/reputation"
)

// Load reads the reputation corpus at path. A missing or empty path yields an
// empty corpus and no error, so the signal is strictly opt-in and degrades
// silently when not configured.
func Load(path string) (reputation.Source, error) {
	if path == "" {
		return reputation.Source{}, nil
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return reputation.Source{}, nil
	}
	if err != nil {
		return nil, err
	}
	var src reputation.Source
	if err := json.Unmarshal(b, &src); err != nil {
		return nil, err
	}
	if src == nil {
		src = reputation.Source{}
	}
	return src, nil
}
