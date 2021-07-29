package util

import "strings"

func NAIfEmptyStr(str string) string {
	if str == "" {
		return "na"
	}
	return str
}

func NAIfNilOrEmptyStr(str *string) string {
	if str == nil || *str == "" {
		return "na"
	}
	return *str
}

func IsNAOrEmpty(in string) bool {
	return in == "" || strings.ToLower(strings.TrimSpace(in)) == "na"
}
