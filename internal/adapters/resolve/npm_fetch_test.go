package resolve

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alexverify/assay/internal/platform/run"
)

func TestPackFetcherDownloadsAndExtracts(t *testing.T) {
	tmp := t.TempDir()
	// A real tarball npm would have produced.
	makeTarGzAt(t, tmp, "some-mcp-1.4.2.tgz", map[string]string{
		"package.json":  `{"name":"some-mcp","version":"1.4.2"}`,
		"dist/index.js": "module.exports = {}",
	})

	runner := &run.Fake{Responses: map[string]run.FakeResponse{
		"npm pack some-mcp@1.4.2 --pack-destination " + tmp + " --json": {
			Out: []byte(`[{"filename":"some-mcp-1.4.2.tgz"}]`),
		},
	}}
	pf := packFetcher{runner: runner}

	dir, err := pf.fetchInto(context.Background(), "some-mcp@1.4.2", tmp)
	if err != nil {
		t.Fatalf("fetchInto: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "dist", "index.js"))
	if err != nil || string(got) != "module.exports = {}" {
		t.Fatalf("extracted code wrong: %q err=%v", got, err)
	}
}
