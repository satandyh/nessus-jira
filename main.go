package main

import (
  "os"
  "time"
  "fmt"
  //"github.com/rs/zerolog"
  //"github.com/rs/zerolog/log"
  //jira "github.com/andygrunwald/go-jira"
  //"github.com/spf13/viper"
  "github.com/satandyh/nessus-jira/internal"
)

var conf *Conf


func main() {
  /*
  1. STEP LOGGING
  */
  //unix time everywhere
  zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

  //colors for cli
  log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339})

  log.Info().Str("foo", "bar").Msg("Hello world")
  zerolog.SetGlobalLevel(zerolog.InfoLevel)



  log.Info().
    Str("Scale", "833 cents").
    Float64("Interval", 833.09).
    Msg("Fibonacci is everywhere")
  fmt.Println("hello world")
  //fmt.Printf("%s: %+v\n", issue.Key, issue.Fields.Summary)


  /*
  2. STEP CONFIG
  */
  //
  conf = config.newConfig()


}