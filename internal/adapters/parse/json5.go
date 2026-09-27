package parse

import "encoding/json"

// JSON5 parses the JSON5 subset OpenClaw writes: JSONC plus bare identifier
// keys and single-quoted strings. It rewrites those into plain JSON — quoting
// bare words other than true/false/null, re-quoting '...' strings — and hands
// the result to encoding/json. Hex numbers, Infinity and NaN are out of scope;
// a bare Infinity becomes the string "Infinity" and fails typed decoding.
func JSON5(b []byte, v any) error {
	return json.Unmarshal(stripTrailingCommas(json5ToJSON(stripComments5(b))), v)
}

// stripComments5 is stripComments aware of single-quoted strings, so a // or
// /* inside '...' survives.
func stripComments5(b []byte) []byte {
	out := make([]byte, 0, len(b))
	var quote byte
	escaped := false
	for i := 0; i < len(b); i++ {
		c := b[i]
		if quote != 0 {
			out = append(out, c)
			switch {
			case escaped:
				escaped = false
			case c == '\\':
				escaped = true
			case c == quote:
				quote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			out = append(out, c)
			continue
		}
		if c == '/' && i+1 < len(b) {
			if b[i+1] == '/' {
				i += 2
				for i < len(b) && b[i] != '\n' {
					i++
				}
				if i < len(b) {
					out = append(out, '\n')
				}
				continue
			}
			if b[i+1] == '*' {
				i += 2
				for i+1 < len(b) && !(b[i] == '*' && b[i+1] == '/') {
					i++
				}
				i++
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func isIdentStart(c byte) bool {
	return c == '_' || c == '$' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func isNumberPart(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-'
}

// json5ToJSON quotes bare identifiers and converts '...' strings to "...".
func json5ToJSON(b []byte) []byte {
	out := make([]byte, 0, len(b)+len(b)/8)
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case c == '"':
			j := i + 1
			for j < len(b) && b[j] != '"' {
				if b[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(b) {
				return append(out, b[i:]...) // unterminated: let encoding/json report it
			}
			out = append(out, b[i:j+1]...)
			i = j
		case c == '\'':
			out = append(out, '"')
			j := i + 1
			for ; j < len(b) && b[j] != '\''; j++ {
				switch {
				case b[j] == '\\' && j+1 < len(b) && b[j+1] == '\'':
					out = append(out, '\'')
					j++
				case b[j] == '\\' && j+1 < len(b):
					out = append(out, b[j], b[j+1])
					j++
				case b[j] == '"':
					out = append(out, '\\', '"')
				default:
					out = append(out, b[j])
				}
			}
			if j >= len(b) {
				return out // unterminated: encoding/json reports it
			}
			out = append(out, '"')
			i = j
		case c == '-' || (c >= '0' && c <= '9'):
			j := i
			for j < len(b) && isNumberPart(b[j]) {
				j++
			}
			out = append(out, b[i:j]...)
			i = j - 1
		case isIdentStart(c):
			j := i
			for j < len(b) && isIdentPart(b[j]) {
				j++
			}
			word := string(b[i:j])
			if word == "true" || word == "false" || word == "null" {
				out = append(out, word...)
			} else {
				out = append(out, '"')
				out = append(out, word...)
				out = append(out, '"')
			}
			i = j - 1
		default:
			out = append(out, c)
		}
	}
	return out
}
