package auditlog

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/alexverify/assay/internal/domain/audit"
)

// Filter narrows which events Read returns. Zero-value fields don't filter.
type Filter struct {
	Server string
	Tool   string
	Status string
	Kind   audit.Kind
	Since  time.Time
}

func (f Filter) match(e audit.Event) bool {
	if f.Server != "" && e.Server != f.Server {
		return false
	}
	if f.Tool != "" && e.Tool != f.Tool {
		return false
	}
	if f.Status != "" && e.Status != f.Status {
		return false
	}
	if f.Kind != "" && e.Kind != f.Kind {
		return false
	}
	if !f.Since.IsZero() && e.At.Before(f.Since) {
		return false
	}
	return true
}

// Read loads matching events from every day file under dir, sorted ascending
// by time. A missing directory yields no events and no error. Unparseable
// lines are skipped so one corrupt line never hides the rest of the log.
func Read(dir string, f Filter) ([]audit.Event, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []audit.Event
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".jsonl") {
			continue
		}
		evs, err := readFile(filepath.Join(dir, ent.Name()), f)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].At.Before(out[j].At) })
	return out, nil
}

func readFile(path string, f Filter) ([]audit.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var out []audit.Event
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // tool results can be large
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e audit.Event
		if json.Unmarshal(line, &e) != nil {
			continue // skip a corrupt line, keep the rest
		}
		if f.match(e) {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

// Summary aggregates a set of events for a quick overview.
type Summary struct {
	Total       int            `json:"total"`
	Sessions    int            `json:"sessions"`
	ToolCalls   int            `json:"toolCalls"`
	Activations int            `json:"activations"`
	Denied      int            `json:"denied"`
	Egress      int            `json:"egress"`
	Redactions  int            `json:"redactions"`
	ByServer    map[string]int `json:"byServer"`
	ByTool      map[string]int `json:"byTool"`
}

// Summarize rolls up events into counts.
func Summarize(evs []audit.Event) Summary {
	s := Summary{ByServer: map[string]int{}, ByTool: map[string]int{}}
	sessions := map[string]bool{}
	for _, e := range evs {
		s.Total++
		s.ByServer[e.Server]++
		if e.Session != "" {
			sessions[e.Session] = true
		}
		switch e.Kind {
		case audit.KindToolCall:
			s.ToolCalls++
			if e.Tool != "" {
				s.ByTool[e.Tool]++
			}
		case audit.KindActivation:
			s.Activations++
		case audit.KindEgress:
			s.Egress++
			s.Redactions += e.Redactions
		}
		if e.Status == audit.StatusDenied {
			s.Denied++
		}
	}
	s.Sessions = len(sessions)
	return s
}
