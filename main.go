package main

import (
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	config "github.com/satandyh/nessus-jira/internal/config"
	logging "github.com/satandyh/nessus-jira/internal/logger"
)

// Global vars for logs
var logConfig = logging.LogConfig{
	ConsoleLoggingEnabled: true,
	EncodeLogsAsJson:      true,
	FileLoggingEnabled:    true,
	Directory:             "./data",
	Filename:              "nessus-jira.log",
	MaxSize:               10,
	MaxBackups:            7,
	MaxAge:                7,
	LogLevel:              6,
}

var logger = logging.Configure(logConfig)

// Properly close - cause we use lock file
var Exitsig = make(chan os.Signal, 1)

func main() {
	/*
	  1. STEP LOGGING
	  Realised in global namespace
	*/
	/*
	  2. STEP CONFIG
	  get config with package conf
	*/
	/*
	  3. STEP GET SCAN STATUS
	  3.1 get scan id from nessus by task name
	  3.2 get scan status
	  3.2.1 skip if scan status 'running'
	  3.2.2 if scan status 'completed' and read='false'
	  3.2.3 if lock_task_id present -> skip all - cause other nessus-jira is working now
	  3.2.4 if lock_task_id not present -> create it and go to 4 step
	*/
	/*
		4. STEP GET REPORS
		4.1 create scan report
		4.2 download scan report to tmp dir
		4.2.1 start timer for get results = 1800sec
		4.2.2 wait 10sec
		4.2.3 check report status
		4.2.4 download report archive to dir if it ready and make read=='true', if no -> go to 4.2.5
		4.2.5 check timer, if not finished -> go to 4.2.2
		4.2.6 if timer finished -> cancel task to get results for this scan and delete lock_task_id - try antoher one time to start nessus-jira
	*/
	/*
	  5. STEP PARSE reports and analyze results
	  5.1 get only interesting results (look for fields) from file
	  5.2 save new csv to parsed csv
	*/
	/*
	  6. CREATE JIRA TASKS
	  6.1 create task for each separate scan result in necessary project
	*/
	/*
	  7. STEP FINISH WORK
	  7.1 make scan read status to 'true'
	  7.2 delete lock_task_id
	  7.2 delete scan reports and archives from tmp - all formats csv zip json
	  7.3
	*/

	// 2
	conf := config.NewConfig()

	//!!!test only!!!
	JiraTest(conf.Jira)
	// 3.1
	scans := GetScans(conf.Nessus.Conn)
	// 3.2.1 - 3.2.3
	actualScans := CheckStatus(conf, scans)
	// 3.2.4 used goroutine and signals to create lockfile
	// also we check file mtime -> if it more than 24H ago - delete lock file
	signal.Notify(Exitsig,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		os.Interrupt)
	var (
		lockstate bool = false
	)
	var waitToClose sync.WaitGroup
	waitToClose.Add(1)
	if f_stat, err := os.Stat(filepath.Join(conf.Data.Dir, "nj.lock")); err == nil {
		check_time := time.Now().Add(-24 * time.Hour)
		// true if check_time before f_stat
		if check_time.Before(f_stat.ModTime()) {
			logger.Info().
				Str("module", "main").
				Msg("Another instance already work.")
			return
		} else {
			logger.Info().
				Str("module", "main").
				Msg("Seems process hung. Lockfile mtime " + f_stat.ModTime().String())
			var err = os.Chtimes(filepath.Join(conf.Data.Dir, "nj.lock"), time.Now(), time.Now())
			if err != nil {
				logger.Error().
					Str("module", "main").
					Err(err).
					Msg("Cannot change lockfile mtime")
			}
			logger.Info().
				Str("module", "main").
				Msg("Lockfile mtime/ctime changed to " + time.Now().String() + ". Continue.")
		}
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
		defer waitToClose.Done()
		s := <-Exitsig
		if lockstate {
			var err = os.Remove(filepath.Join(conf.Data.Dir, "nj.lock"))
			if err != nil {
				logger.Error().
					Str("module", "main").
					Err(err).
					Msg("No any new completed scans.")
			}
		}
		logger.Info().
			Str("module", "main").
			Msg("Caught next signal - " + s.String())
		os.Exit(0)
	}()

	// 4
	// because we have several task let's make them through goroutines
	var waitAllReports sync.WaitGroup
	for k := range actualScans {
		// make pointer to main structure to work with it
		ps := &actualScans[k]
		//add another one counter to sync
		waitAllReports.Add(1)
		// add gouroutine
		go func() {
			// make aware of concurency all our inner gouroutine tasks
			// so send done to WaitGroup at end of goroutine
			defer waitAllReports.Done()
			// 4.1
			// make random lag before start
			rand.Seed(time.Now().UnixNano())
			rd := time.Duration(rand.Intn(5))
			time.Sleep(rd * time.Second)
			ps.ScanExport = CreateScanReport(conf.Nessus.Conn, ps)
			logger.Info().
				Str("module", "main").
				Msg("Created report for " + ps.Name)
			// 4.2.1
			//glob_timer := 0
			var reportStatus string
			for j := 0; j < 180; j++ {
				//glob_timer = j
				// 4.2.2
				time.Sleep(10 * time.Second)
				// 4.2.3
				reportStatus = CheckReportStatus(conf.Nessus.Conn, ps)
				logger.Info().
					Str("module", "main").
					Msg(ps.Name + " has status " + reportStatus)
				if reportStatus == "ready" {
					// 4.2.4
					ps.FileName = GetReport(conf.Nessus.Conn, conf.Data, ps)
					logger.Info().
						Str("module", "main").
						Msg("For " + ps.Name + " get file " + ps.FileName)
					ChangeScanStatus(conf.Nessus.Conn, ps)
					logger.Info().
						Str("module", "main").
						Msg(ps.Name + " status changed to read")
						// 4.2.5
					break
				}
			}
			// 4.2.6
			if reportStatus != "ready" {
				logger.Error().
					Str("module", "main").
					Msg("Cannot get report for " + ps.Name + ". Report creating time expired.")
			}
			// 5.1 - 5.2
			ParseCsv(ps, conf.Csv)
		}()
	}
	waitAllReports.Wait()

	logger.Info().
		Str("module", "main").
		Msg("All tasks completed.")
	// properly exit
	Exitsig <- syscall.SIGTERM
	waitToClose.Wait()
}
