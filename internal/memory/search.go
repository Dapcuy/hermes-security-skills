package memory

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// Scored hasil pencarian: entry + skor frekuensi kata kunci.
type Scored struct {
	Entry *Entry
	Score int
}

// Index adalah inverted index sederhana in-memory (§41 full-text retrieval):
// token → (entryID → frekuensi kemunculan). MVP sesuai ROADMAP §30
// ("Markdown/YAML/JSONL, lalu SQLite + FTS5 jika diperlukan") — tanpa
// database, dibangun ulang dari file setiap kali dipanggil.
type Index struct {
	postings map[string]map[string]int // token -> id -> freq
	entries  map[string]*Entry
}

// BuildIndex membangun index atas semua entry di store (knowledge + case
// memory). Sumber token: id + title + category + body.
func (s *Store) BuildIndex() (*Index, error) {
	all, err := s.List(Filter{})
	if err != nil {
		return nil, err
	}
	idx := &Index{
		postings: make(map[string]map[string]int),
		entries:  make(map[string]*Entry, len(all)),
	}
	for _, e := range all {
		idx.Add(e)
	}
	return idx, nil
}

// Add menambahkan satu entry ke index.
func (ix *Index) Add(e *Entry) {
	if e == nil {
		return
	}
	ix.entries[e.ID] = e
	text := strings.Join([]string{e.ID, e.Title, e.Category, e.Body}, " ")
	counts := map[string]int{}
	for _, tok := range tokenize(text) {
		counts[tok]++
	}
	for tok, freq := range counts {
		if ix.postings[tok] == nil {
			ix.postings[tok] = make(map[string]int)
		}
		ix.postings[tok][e.ID] += freq
	}
}

// Size jumlah entry yang ter-index.
func (ix *Index) Size() int { return len(ix.entries) }

// Search menjalankan query multi-kata: skor entry = jumlah frekuensi semua
// token query yang muncul (entry tanpa kecocokan dihilangkan). Hasil diurut
// skor menurun, tie-break by id menaik (deterministik).
func (ix *Index) Search(query string) ([]Scored, error) {
	tokens := tokenize(query)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("memory: query kosong")
	}
	scores := map[string]int{}
	for _, tok := range tokens {
		for id, freq := range ix.postings[tok] {
			scores[id] += freq
		}
	}
	out := make([]Scored, 0, len(scores))
	for id, score := range scores {
		out = append(out, Scored{Entry: ix.entries[id], Score: score})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Entry.ID < out[j].Entry.ID
	})
	return out, nil
}

// Search adalah convenience: bangun index lalu jalankan query satu kali.
func (s *Store) Search(query string) ([]Scored, error) {
	ix, err := s.BuildIndex()
	if err != nil {
		return nil, err
	}
	return ix.Search(query)
}

// tokenize memecah teks menjadi token lowercase (huruf/digit unicode);
// token kosong dihilangkan. MVP tanpa stemming/stopword — sengaja sederhana.
func tokenize(s string) []string {
	var toks []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return toks
}
