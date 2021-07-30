package subdomainNSTakeover

import (
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"

	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/module/tfinv"
)

type config struct {
	LogLevel string        `mapstructure:"log_level" toml:"log_level"`
	Common   common.Config `mapstructure:"common" toml:"common"`
	TFInv    tfinv.Config  `mapstructure:"tfinv" toml:"tfinv"`
	Brahma   brahma.Config `mapstructure:"brahma" toml:"brahma"`
}

type DNSRecord struct {
	Source     string `mapstructure:"source" csv:"source"`
	Type       string `mapstructure:"type" csv:"type"`
	Target     string `mapstructure:"target" csv:"target"`
	Provider   string `mapstructure:"provider" csv:"provider"`
	AccountId  string `mapstructure:"accountId" csv:"account_id"`
	TechFamily string `mapstructure:"tech_family" csv:"tech_family"`
}

type Service struct {
	Name    string `mapstructure:"name" json:"name"`
	Message string `mapstructure:"message" json:"message"`
}
