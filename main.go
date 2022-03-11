package main

import (
  "os"
  "os/signal"
  //"sync"
  //"time"
  "path/filepath"
  "fmt"
  "github.com/satandyh/nessus-jira/internal/logger"
  "github.com/satandyh/nessus-jira/internal/config"
  //"github.com/satandyh/nessus-jira/internal/tls"

  //jira "github.com/andygrunwald/go-jira"
)

var logConfig = logging.LogConfig{
  ConsoleLoggingEnabled: true,
  EncodeLogsAsJson: true,
  FileLoggingEnabled: true,
  Directory: "./config",
  Filename: "nessus-jira.log",
  MaxSize: 10,
  MaxBackups: 7,
  MaxAge: 7,
  LogLevel: 6,
}

var logger = logging.Configure(logConfig)

func main() {
  /*
  1. STEP LOGGING
  */

  //logger.Warn().
  //  Str("module", "main").
  //  Msg("warn shit")

  /*
  2. STEP CONFIG
  */
  conf := config.NewConfig()

  /*
  3. STEP GET SCAN STATUS
  3.1 get scan id from nessus by task name
  3.2 get scan status
  3.2.1 skip if scan status 'running'
  3.2.2 if scan status 'completed' and read='false'
  3.2.3 if lock_task_id present -> skip all - cause other nessus-jira is working now
  3.2.4 if lock_task_id not present -> create it and go to 4 step
  */

  // 3.1
  scans := GetScans(conf.Nessus.Conn)
  // 3.2.1 - 3.2.3
  actualScans := CheckStatus(conf, scans)
  // 3.2.4 used goroutine and signals to create lockfile
  // TODO - add check file created date if more than 24H ago - delete it
  exitsig := make(chan os.Signal, 1)
  signal.Notify(exitsig)
  var (
      lockstate bool = false
  )
  if _, err := os.Stat(filepath.Join(conf.Data.Dir, "nj.lock")); err == nil {
    logger.Info().
      Str("module", "main").
      Msg("Another instance already work.")
    return
  } else if os.IsNotExist(err) {
    var file, err = os.Create(filepath.Join(conf.Data.Dir, "nj.lock"))
    if err != nil {
      logger.Error().
        Str("module", "main").
        Err(err).
        Msg("")
      return
    }
    file.Close()
    lockstate = true
  }
  go func() {
    <-exitsig
    if lockstate {
      var err = os.Remove(filepath.Join(conf.Data.Dir, "nj.lock"))
      if err != nil {
        logger.Error().
          Str("module", "main").
          Err(err).
          Msg("No any new completed scans.")
      }
    }
    os.Exit(0)
  }()

  /* 4. STEP GET REPORS
  4.1 create scan report
  4.2 download scan report to tmp dir
  4.2.1 start timer for get results = 1200sec
  4.2.2 wait 10 sec
  4.2.3 check report status
  4.2.4 download report archive to dir if it ready and make read='true', if no -> go to 4.2.5
  4.2.5 check timer, if not finished -> go to 4.2.2
  4.2.6 if timer finished -> cancel task to get results for this scan and delete lock_task_id - try antoher one time to start nessus-jira
  */

  
  for k := range actualScans {
    ps := &actualScans[k]
    CreateScanReport(conf.Nessus.Conn, ps)
    //ps.Token, ps.File = CreateScanReport(ps.Id, ps.Name)
    fmt.Println(ps)
    //task.Token = token
    //task.File = file
  //  for _, sc := range scans.Scans {
  //    if task == sc.Name {
  //      CreateScanReport(sc.Id)
  //    }
  //  }
  }
  fmt.Println(actualScans[0])


  /*
  5. STEP PARSE reports and analyze results
  5.1 unarchive file to tmp
  5.2 get only interesting results (look for fields) from file
  5.3 save new csv to tmp
  5.xxx if something goes wrong -> cancel task to get results for this scan and delete lock_task_id - try antoher one time to start nessus-jira
  */

  /*
  6. CREATE JIRA TASKS
  6.1 create task for each separate scan result in necessary project
  */

  /*
  7. STEP FINISH WORK
  6.1 make scan read status to 'true'
  6.2 delete lock_task_id
  6.2 delete scan reports and archives from tmp - all formats csv zip json
  6.3 
  */

  



  //fmt.Println(conf)
  //fmt.Println(scans)
  fmt.Println(actualScans)
  //remove lockfile
  close(exitsig)

}