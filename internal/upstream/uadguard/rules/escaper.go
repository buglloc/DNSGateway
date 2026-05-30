package rules

import "strings"

func EscapeString(in string) string {
	var out strings.Builder
	for _, c := range in {
		if isEscapedRune(c) {
			_, _ = out.WriteRune('\\')
		}
		out.WriteRune(c)
	}
	return out.String()
}

func UnescapeString(in string) string {
	var out strings.Builder
	escaped := false
	for _, c := range in {
		if escaped {
			if !isEscapedRune(c) {
				_, _ = out.WriteRune('\\')
			}
			_, _ = out.WriteRune(c)
			escaped = false
			continue
		}

		if c == '\\' {
			escaped = true
			continue
		}

		out.WriteRune(c)
	}
	if escaped {
		_, _ = out.WriteRune('\\')
	}
	return out.String()
}

func isEscapedRune(c rune) bool {
	switch c {
	case '\\', '\'', '"', ',', '|', '/', '$':
		return true
	default:
		return false
	}
}
