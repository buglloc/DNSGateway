package rules

import "strings"

func EscapeString(in string) string {
	var out strings.Builder
	for _, c := range in {
		switch c {
		case '\'', '"', ',', '|', '/', '$':
			_, _ = out.WriteRune('\\')
		}
		out.WriteRune(c)
	}
	return out.String()
}

func UnescapeString(in string) string {
	var out strings.Builder
	for _, c := range in {
		if c == '\\' {
			continue
		}

		out.WriteRune(c)
	}
	return out.String()
}
