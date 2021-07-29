package subdomainNSTakeover

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func loadConfig() *config {
	viper.AddConfigPath(".")
	viper.AddConfigPath("./config/")
	viper.SetConfigType("toml")
	env := strings.ToLower(os.Getenv("ENV"))
	if env == "" {
		env = "dev"
	}
	viper.SetConfigName(env)
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal("unable to load config", err)
	}
	conf := &config{}
	err = viper.Unmarshal(conf)
	if err != nil {
		log.Fatal("unable to unmarshal config", err)
	}

	conf.Common.Env = env
	return conf
}
