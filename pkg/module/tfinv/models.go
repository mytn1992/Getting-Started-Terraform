package tfinv

import (
	"gitlab.myteksi.net/dev-sec-ops/subdomainNSTakeover/pkg/common/gsheetw"
)

type wrapper struct {
	config  Config
	gsheetw *gsheetw.Wrapper
}

type Config struct {
	CredentialsFilePath  string `mapstructure:"credentials_file_path"`
	SpreadsheetID        string `mapstructure:"spreadsheet_id"`
	MappingWorksheetName string `mapstructure:"mapping_worksheet_name"`
}

type TechFamily struct {
	Name              string
	Entity            string
	CostFamilyCenters []string
	Handlers          []string
}
