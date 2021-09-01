package common

type Config struct {
	Env              string
	ReportFolderTmpl string `mapstructure:"report_folder_tmpl"`
	WorkerCount      int    `mapstructure:"worker_count"`
}

type DNSRecord struct {
	Source     string `mapstructure:"source" csv:"source"`
	Type       string `mapstructure:"type" csv:"type"`
	Target     string `mapstructure:"target" csv:"target"`
	Provider   string `mapstructure:"provider" csv:"provider"`
	AccountId  string `mapstructure:"accountId" csv:"account_id"`
	TechFamily string `mapstructure:"tech_family" csv:"tech_family"`
}
