// Package yamlmini adalah parser YAML subset untuk control plane
// Hermes Security Skills (stdlib only, tanpa dependency eksternal).
//
// Didukung (cukup untuk capabilities/registry.yaml dan policy/*.yaml):
//   - mapping (key: value) dan sequence (- item), indentasi spasi (2 per level)
//   - scalar: string (plain, 'single', "double"), int, bool, null (kosong)
//   - flow sequence satu baris: [a, b, c]
//   - komentar '#' (baris penuh, atau trailing untuk plain scalar)
//   - seq-of-map ("key: value" setelah dash, kelanjutan align dengan dash+2)
//
// TIDAK didukung (fail-closed = error): anchor/alias, tag, dokumen ganda,
// flow mapping '{...}', multiline scalar (| atau >), indentasi tab.
package yamlmini

import (
	"fmt"
	"strconv"
	"strings"
)

type line struct {
	indent  int
	content string
	num     int // nomor baris asli (1-based) untuk pesan error
}

type parser struct {
	lines []line
	pos   int
}

// Parse mem-parse data YAML subset dan mengembalikan dokumen top-level
// sebagai map. Fail-closed: input tidak valid selalu mengembalikan error.
func Parse(data []byte) (map[string]any, error) {
	p, err := newParser(string(data))
	if err != nil {
		return nil, err
	}
	if len(p.lines) == 0 {
		return map[string]any{}, nil
	}
	v, err := p.parseBlock(p.lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		return nil, fmt.Errorf("yamlmini: baris %d: konten tidak terduga %q", p.lines[p.pos].num, p.lines[p.pos].content)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("yamlmini: dokumen top-level harus mapping")
	}
	return m, nil
}

func newParser(src string) (*parser, error) {
	raw := strings.Split(src, "\n")
	p := &parser{}
	started := false
	for i, r := range raw {
		r = strings.TrimRight(r, "\r") // toleransi CRLF (Windows)
		// Indentasi = run karakter spasi/tab di awal baris.
		j := 0
		for j < len(r) && (r[j] == ' ' || r[j] == '\t') {
			j++
		}
		if strings.Contains(r[:j], "\t") {
			return nil, fmt.Errorf("yamlmini: baris %d: indentasi tab tidak didukung", i+1)
		}
		indentStr := r[:j]
		trimmed := strings.TrimSpace(r)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "---") || strings.HasPrefix(trimmed, "...") {
			// Document separator hanya boleh sebelum konten apapun.
			if started {
				return nil, fmt.Errorf("yamlmini: baris %d: dokumen ganda tidak didukung", i+1)
			}
			continue
		}
		started = true
		p.lines = append(p.lines, line{indent: len(indentStr), content: trimmed, num: i + 1})
	}
	return p, nil
}

func isSeqItem(content string) bool {
	return content == "-" || strings.HasPrefix(content, "- ")
}

// parseBlock mem-parse node pada indentasi minimal `indent`.
func (p *parser) parseBlock(indent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	cur := p.lines[p.pos]
	if cur.indent < indent {
		return nil, nil
	}
	if isSeqItem(cur.content) {
		return p.parseSeq(cur.indent)
	}
	return p.parseMap(cur.indent)
}

func (p *parser) parseSeq(indent int) (any, error) {
	seq := []any{}
	for p.pos < len(p.lines) {
		cur := p.lines[p.pos]
		if cur.indent != indent || !isSeqItem(cur.content) {
			break
		}
		p.pos++
		rest := ""
		if len(cur.content) > 1 {
			rest = strings.TrimSpace(cur.content[2:]) // lewati "- "
		}
		if rest == "" {
			// Item berupa block nested pada baris berikutnya.
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				v, err := p.parseBlock(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				seq = append(seq, v)
			} else {
				seq = append(seq, nil)
			}
			continue
		}
		// Item inline: scalar, flow seq, atau awal mapping ("key: value").
		if key, kv, ok := splitKey(rest); ok {
			// Seq of map: tulis-ulang baris dash sebagai baris map pertama
			// pada indent+2 lalu parse sebagai mapping biasa.
			p.lines[p.pos-1] = line{indent: indent + 2, content: key + ": " + kv, num: cur.num}
			p.pos--
			v, err := p.parseMap(indent + 2)
			if err != nil {
				return nil, err
			}
			seq = append(seq, v)
			continue
		}
		v, err := parseInlineValue(rest, cur.num)
		if err != nil {
			return nil, err
		}
		seq = append(seq, v)
	}
	return seq, nil
}

func (p *parser) parseMap(indent int) (any, error) {
	m := map[string]any{}
	for p.pos < len(p.lines) {
		cur := p.lines[p.pos]
		if cur.indent < indent {
			break
		}
		if cur.indent > indent {
			return nil, fmt.Errorf("yamlmini: baris %d: indentasi tidak konsisten", cur.num)
		}
		if isSeqItem(cur.content) {
			break // mapping dan sequence bercampur pada indent sama = invalid
		}
		key, rest, ok := splitKey(cur.content)
		if !ok {
			return nil, fmt.Errorf("yamlmini: baris %d: baris mapping tidak valid %q", cur.num, cur.content)
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("yamlmini: baris %d: key duplikat %q", cur.num, key)
		}
		p.pos++
		if rest == "" {
			// Nilai nested block (lebih dalam), seq compact (indent sama),
			// atau null.
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				v, err := p.parseBlock(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			} else if p.pos < len(p.lines) && p.lines[p.pos].indent == indent && isSeqItem(p.lines[p.pos].content) {
				v, err := p.parseSeq(indent)
				if err != nil {
					return nil, err
				}
				m[key] = v
			} else {
				m[key] = nil
			}
			continue
		}
		v, err := parseInlineValue(rest, cur.num)
		if err != nil {
			return nil, err
		}
		m[key] = v
	}
	return m, nil
}

// splitKey memisah "key: value" / "key:". Colon harus diikuti spasi atau
// akhir baris agar nilai seperti "http://x" tidak salah dianggap mapping.
func splitKey(s string) (key, rest string, ok bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' && (i+1 == len(s) || s[i+1] == ' ') {
			k := strings.TrimSpace(s[:i])
			if k == "" {
				return "", "", false
			}
			return k, strings.TrimSpace(s[i+1:]), true
		}
	}
	return "", "", false
}

func parseInlineValue(s string, num int) (any, error) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return nil, nil // "key:   # komentar" -> null
	}
	if strings.HasPrefix(s, "[") {
		return parseFlowSeq(s, num)
	}
	if strings.HasPrefix(s, "{") {
		return nil, fmt.Errorf("yamlmini: baris %d: flow mapping '{...}' tidak didukung", num)
	}
	return parseScalar(s, num)
}

func parseFlowSeq(s string, num int) (any, error) {
	if !strings.HasSuffix(s, "]") {
		return nil, fmt.Errorf("yamlmini: baris %d: flow sequence tidak ditutup", num)
	}
	inner := strings.TrimSpace(s[1 : len(s)-1])
	out := []any{}
	if inner == "" {
		return out, nil
	}
	for _, part := range splitFlowParts(inner) {
		v, err := parseScalar(strings.TrimSpace(part), num)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}

// splitFlowParts memecah isi flow sequence pada koma di luar kutipan.
func splitFlowParts(s string) []string {
	var parts []string
	var sb strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
			sb.WriteByte(c)
		case c == '"' && !inSingle:
			inDouble = !inDouble
			sb.WriteByte(c)
		case c == ',' && !inSingle && !inDouble:
			parts = append(parts, sb.String())
			sb.Reset()
		default:
			sb.WriteByte(c)
		}
	}
	parts = append(parts, sb.String())
	return parts
}

// parseScalar mengonversi scalar: quoted string, bool, int, null, atau
// plain string (trailing comment " #..." dipotong).
func parseScalar(s string, num int) (any, error) {
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') {
		quote := s[0]
		end := -1
		for i := 1; i < len(s); i++ {
			if quote == '"' && s[i] == '\\' {
				i++ // lewati karakter hasil escape
				continue
			}
			if s[i] == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++ // '' di dalam single-quoted = literal '
					continue
				}
				end = i
				break
			}
		}
		if end < 0 {
			return nil, fmt.Errorf("yamlmini: baris %d: string tidak ditutup", num)
		}
		rest := strings.TrimSpace(s[end+1:])
		if rest != "" && !strings.HasPrefix(rest, "#") {
			return nil, fmt.Errorf("yamlmini: baris %d: konten tidak terduga setelah string %q", num, rest)
		}
		body := s[1:end]
		if quote == '\'' {
			return strings.ReplaceAll(body, "''", "'"), nil
		}
		return unescapeDouble(body, num)
	}
	// Plain scalar: potong trailing comment.
	if idx := strings.Index(s, " #"); idx >= 0 {
		s = s[:idx]
	}
	s = strings.TrimSpace(s)
	switch s {
	case "":
		return nil, nil
	case "true":
		return true, nil
	case "false":
		return false, nil
	case "~", "null":
		return nil, nil
	}
	if isInt(s) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("yamlmini: baris %d: int tidak valid %q", num, s)
		}
		return n, nil
	}
	return s, nil
}

func isInt(s string) bool {
	body := strings.TrimPrefix(s, "-")
	if body == "" {
		return false
	}
	for i := 0; i < len(body); i++ {
		if body[i] < '0' || body[i] > '9' {
			return false
		}
	}
	return true
}

func unescapeDouble(s string, num int) (string, error) {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' {
			sb.WriteByte(c)
			continue
		}
		i++
		if i >= len(s) {
			return "", fmt.Errorf("yamlmini: baris %d: escape tidak lengkap", num)
		}
		switch s[i] {
		case 'n':
			sb.WriteByte('\n')
		case 't':
			sb.WriteByte('\t')
		case 'r':
			sb.WriteByte('\r')
		case '"':
			sb.WriteByte('"')
		case '\\':
			sb.WriteByte('\\')
		default:
			return "", fmt.Errorf("yamlmini: baris %d: escape \\%c tidak didukung", num, s[i])
		}
	}
	return sb.String(), nil
}
