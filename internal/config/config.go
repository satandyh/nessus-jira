// got from
// https://github.com/RobinUS2/indispenso/blob/master/conf.go

package config

import (
  "os"
  "fmt"
  "github.com/spf13/pflag"
  "github.com/spf13/viper"
  "github.com/satandyh/nessus-jira/internal/logger"
)

type NessusScan struct {
  Project string
  Watchers []string
  TaskName []string
}

type NessusConn struct {
  User string
  Pass string
  Url string
  TokenAccess string
  TokenSecret string
  CertPub string
  CertPriv string
  CertCA string
}

type Conf struct {
  Jira struct {
    Url string
    User string
    Pass string
  }
  Data struct {
    Dir string
    Log string
  }
  Smtp struct {
    Url string
    User string
    Pass string
    Fromaddr string
    Toaddr []string
    Recipients []string
  }
  Imap struct {
    Url string
    User string
    Pass string
  }
  Nessus struct {
    Conn NessusConn
    Scans []NessusScan
  }
  Csv struct {
    Header []string
  }
  confFlags *pflag.FlagSet
}

// logger
var logConfig = logging.LogConfig{
  ConsoleLoggingEnabled: true,
  EncodeLogsAsJson: true,
  FileLoggingEnabled: false,
  Directory: ".",
  Filename: "log.log",
  MaxSize: 10,
  MaxBackups: 1,
  MaxAge: 1,
  LogLevel: 6,
}

var log = logging.Configure(logConfig)

func NewConfig() Conf {
  var c Conf

  // all env will look like NJ_SOMETHING
  // for embedded use NJ_LEV1.VALUE
  viper.SetEnvPrefix("nj")

  // Defaults
  viper.SetDefault("Jira.User", "jira")
  viper.SetDefault("Jira.Pass", "no")
  viper.SetDefault("Jira.Url", "https://atlassian.com")

  //Flags
  c.confFlags = pflag.NewFlagSet(os.Args[0], pflag.ExitOnError)
  configFile := c.confFlags.StringP("config", "c", "", "Config file location. Supported formats {json,toml,yaml}. Default {'$HOME/.nessus-jira','.','./config','/opt/scripts/nessus-jira'}/config.yml")
  //c.confFlags.StringP("verbose", "v", "6", "Logging verbosity level. Default 6 level (Info)")
  help := c.confFlags.BoolP("help", "h", false, "Print help message")

  //parse flags
  arg_err := c.confFlags.Parse(os.Args[1:])
  if arg_err != nil {
    log.Fatal().
      Err(arg_err).
      Str("module", "config").
      Msg("")
  }
  if *help {
      fmt.Println("Usage of nessus-jira:")
      c.confFlags.PrintDefaults()
      os.Exit(0)
  }

  if len(*configFile) > 2 {
    viper.SetConfigFile(*configFile)
  } else {
    viper.SetConfigName("config.yml") // name of config file (without extension)
    viper.SetConfigType("yaml") // REQUIRED if the config file does not have the extension in the name
    viper.AddConfigPath("/opt/scripts/nessus-jira")   // path to look for the config file in
    viper.AddConfigPath("$HOME/.nessus-jira")  // call multiple times to add many search paths
    viper.AddConfigPath("./config")
    viper.AddConfigPath(".")

  }
  // bind flags from pflags
  arg_bind_err := viper.BindPFlags(c.confFlags)
  if arg_bind_err != nil {
    log.Fatal().
      Err(arg_bind_err).
      Str("module", "config").
      Msg("")
  }

  // try to get values from env
  viper.AutomaticEnv()

  // get values from config
  file_read_err := viper.ReadInConfig()
  if file_read_err != nil {
    log.Fatal().
      Err(file_read_err).
      Str("module", "config").
      Msg("")
    //os.Exit(0)
  }

  // do all above and get our values
  dec_err := viper.Unmarshal(&c)
  if dec_err != nil {
    log.Fatal().
      Err(dec_err).
      Str("module", "config").
      Msg("")
  }

  return c
}
