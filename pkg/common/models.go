package common

type Config struct {
	Env              string
	ReportFolderTmpl string `mapstructure:"report_folder_tmpl"`
	WorkerCount      int    `mapstructure:"worker_count"`
}
