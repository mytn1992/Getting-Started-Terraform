package subdomainNSTakeover

import (
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/azureconfig"
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/brahma"

	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/module/tfinv"
)

type config struct {
	LogLevel string             `mapstructure:"log_level" toml:"log_level"`
	Common   common.Config      `mapstructure:"common" toml:"common"`
	TFInv    tfinv.Config       `mapstructure:"tfinv" toml:"tfinv"`
	Brahma   brahma.Config      `mapstructure:"brahma" toml:"brahma"`
	Azure    azureconfig.Config `mapstructure:"azure" toml:"azure"`
}

type Service struct {
	Name    string `mapstructure:"name" json:"name"`
	Message string `mapstructure:"message" json:"message"`
}
type IP struct {
	IP            string `mapstructure:"ip" json:"ip"`
	AssociationId string `mapstructure:"association_id" json:"association_id"`
	AllocationId  string `mapstructure:"allocation_id" json:"allocation_id"`
}
