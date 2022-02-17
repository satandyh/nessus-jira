// got from
// https://github.com/RobinUS2/indispenso/blob/master/conf.go

package config

import (
  "os"
  "fmt"
  "github.com/spf13/pflag"
  "github.com/spf13/viper"
)

type Conf struct {
  JiraUrl string
  JiraUser string
  JiraPass string

  confFlags *pflag.FlagSet
}

func NewConfig() *Conf {
  c := new(Conf)

  viper.SetConfigName("config.yaml")
  // all env will look like NJ_SOMETHING
  viper.SetEnvPrefix("nj")

  // Defaults
  viper.SetDefault("JiraPass", "")
  viper.SetDefault("JiraUser", "test")
  viper.SetDefault("JiraUrl", "test")

  //Flags
  c.confFlags = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
  configFile := c.confFlags.StringP("config", "c", "", "Config file location default is /opt/scripts/nessus-jira/config.{json,toml,yaml,yml}")
  c.confFlags.BoolP("verbose", "v", false, "Logging verbosity level")
  c.confFlags.BoolP("help", "h", false, "Print help message")


  c.confFlags.Parse(os.Args[1:])
  if len(*configFile) > 2 {
    viper.SetConfigFile(*configFile)
  } else {
    legacyConfigFile := "/opt/scripts/nessus-jira/config.yaml"
    if _, err := os.Stat(legacyConfigFile); err == nil {
      viper.SetConfigFile(legacyConfigFile)
      viper.SetConfigType("yaml")
    }
  }
  // bind flags from pflags
  viper.BindPFlags(c.confFlags)
  // try to get values from env
  viper.AutomaticEnv()
  // get values from config
  viper.ReadInConfig()

  return c
}
