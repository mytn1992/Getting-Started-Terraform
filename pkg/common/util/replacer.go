package util

import "strings"

func SvcProviderAccIDReplacer(tmpl, svcProvider, accID string) string {
	return strings.NewReplacer("{SERVICE_PROVIDER}", svcProvider, "{ACC_ID}", accID).Replace(tmpl)
}
