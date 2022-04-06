package main

import (
	"encoding/csv"
	"io"
	"math"
	"os"
	"strconv"
	"syscall"

	"github.com/satandyh/nessus-jira/internal/config"
)

func ParseCsv(task *CompletedScan, c config.ConfCsv) {
	// open full file to read
	full_file, f_err := os.Open(task.FileName)
	if f_err != nil {
		logger.Error().
			Err(f_err).
			Str("module", "report").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer full_file.Close()

	// open new file to write
	new_file, nf_err := os.Create(task.FileName + "_parsed")
	if nf_err != nil {
		logger.Error().
			Err(nf_err).
			Str("module", "report").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer new_file.Close()
	// create csv writer
	w := csv.NewWriter(new_file)
	w.Comma = ';'
	defer w.Flush()
	// write header
	if head_err := w.Write(c.Header); head_err != nil {
		logger.Error().
			Err(head_err).
			Str("module", "report").
			Msg("Error writing record to file")
		Exitsig <- syscall.SIGHUP
	}

	// read and parse
	reader := csv.NewReader(full_file)
	var header []string
	var index []int
	// filter variables
	var risk int
	var cvss2 int
	var cvss3 int
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			logger.Error().
				Err(nf_err).
				Str("module", "report").
				Msg("")
			Exitsig <- syscall.SIGHUP
		}
		// get header from old file
		if header == nil {
			header = rec
			// get sequence of indexes in header, which represent match between two csv files
			for new_key, new_val := range c.Header {
				for old_key, old_val := range header {
					if new_val == old_val {
						index = append(index, old_key)
						// get index for our filter
						switch old_val {
						case "CVSS v2.0 Base Score":
							cvss2 = new_key
						case "CVSS v3.0 Base Score":
							cvss3 = new_key
						case "Risk":
							risk = new_key
						}
						break
					}
				}
			}
			// if header present parse our records
		} else {
			// get only necessary columns
			var new_rec []string
			for _, v := range index {
				new_rec = append(new_rec, rec[v])
			}
			// filter column
			tmp_cvss3, _ := strconv.ParseFloat(new_rec[cvss3], 64)
			tmp_cvss2, _ := strconv.ParseFloat(new_rec[cvss2], 64)
			if (!math.IsNaN(tmp_cvss3) && tmp_cvss3 >= c.Score.MinCVSS3) || (!math.IsNaN(tmp_cvss2) && tmp_cvss2 >= c.Score.MinCVSS2) || (len(c.Score.Risk) > 0 && c.Score.Risk == new_rec[risk]) {
				// write to file
				if col_err := w.Write(new_rec); col_err != nil {
					logger.Error().
						Err(col_err).
						Str("module", "report").
						Msg("Error writing record to file")
					Exitsig <- syscall.SIGHUP
				}
				// add 1 to counter only we have match our filter
				task.c_res++
			}
		}
		// also can do something
	}
}
