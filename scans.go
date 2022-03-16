package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/satandyh/nessus-jira/internal/config"
)

type Scans struct {
	Folders []struct {
		Custom       int    `json:"custom"`
		Default_tag  int    `json:"default_tag"`
		Id           int    `json:"id"`
		Name         string `json:"name"`
		Type         string `json:"type"`
		Unread_count *int   `json:"unread_count"`
	} `json:"folders"`
	Scans []struct {
		Control                bool   `json:"control"`
		Creation_date          int    `json:"creation_date"`
		Enabled                bool   `json:"enabled"`
		Folder_id              int    `json:"folder_id"`
		Id                     int    `json:"id"`
		Last_modification_date int    `json:"last_modification_date"`
		Live_results           *int   `json:"live_results"`
		Name                   string `json:"name"`
		Owner                  string `json:"owner"`
		Read                   bool   `json:"read"`
		Rrules                 string `json:"rrules"`
		Shared                 bool   `json:"shared"`
		Starttime              string `json:"starttime"`
		Status                 string `json:"status"`
		Timezone               string `json:"timezone"`
		Type                   string `json:"type"`
		User_permissions       int    `json:"user_permissions"`
		Uuid                   string `json:"uuid"`
	} `json:"scans"`
	Timestamp int `json:"timestamp"`
}

type ScanExport struct {
	Token string `json:"token"`
	File  int    `json:"file"`
}

type CompletedScan struct {
	Name       string
	Id         int
	ScanExport ScanExport
	FileName   string
}

// get scan results
func GetScans(conn config.NessusConn) Scans {
	// create connection with our options
	caCert, cacert_err := ioutil.ReadFile(conn.CertCA)
	if cacert_err != nil {
		logger.Error().
			Err(cacert_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	// load CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	// load certs
	clCert, clCert_err := tls.LoadX509KeyPair(conn.CertPub, conn.CertPriv)
	if clCert_err != nil {
		logger.Error().
			Err(clCert_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	// create tls conf
	tlsConfig := tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}
	// create transport layer
	tr := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	// create client
	cl := http.Client{
		Transport: &tr,
	}
	// make request to nessus
	req, req_err := http.NewRequest("GET", conn.Url+"scans", nil)
	if req_err != nil {
		logger.Error().
			Err(req_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	req.Header = http.Header{
		"X-ApiKeys":    []string{"accessKey=" + conn.TokenAccess + "; secretKey=" + conn.TokenSecret},
		"Content-Type": []string{"application/json"},
	}

	resp, resp_err := cl.Do(req)
	if resp_err != nil {
		logger.Error().
			Err(resp_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	defer resp.Body.Close()
	// TODO checks for response code != 2xx
	body, read_err := ioutil.ReadAll(resp.Body)
	if read_err != nil {
		logger.Error().
			Err(read_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	// parse and return results
	var data Scans
	json_err := json.Unmarshal(body, &data)
	if json_err != nil {
		logger.Error().
			Err(json_err).
			Str("module", "scan").
			Msg("")
		os.Exit(1)
	}
	return data
}

func CheckStatus(c config.Conf, s Scans) []CompletedScan {
	//var filtered []string
	var filter []CompletedScan
	for _, t := range c.Nessus.Scans {
		for _, task := range t.TaskName {
			for _, scan := range s.Scans {
				if scan.Status == "completed" && !scan.Read {
					if task == scan.Name {
						//filtered = append(filtered, task)
						item := CompletedScan{Name: task, Id: scan.Id}
						filter = append(filter, item)
					}
				}
			}
		}
	}
	if len(filter) == 0 {
		logger.Info().
			Str("module", "scan").
			Msg("No any new completed scans.")
		os.Exit(0)
	}
	return filter
}

func CreateScanReport(conn config.NessusConn, task *CompletedScan) ScanExport {
	// create connection with our options
	caCert, cacert_err := ioutil.ReadFile(conn.CertCA)
	if cacert_err != nil {
		logger.Error().
			Err(cacert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// load CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	// load certs
	clCert, clCert_err := tls.LoadX509KeyPair(conn.CertPub, conn.CertPriv)
	if clCert_err != nil {
		logger.Error().
			Err(clCert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// create tls conf
	tlsConfig := tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}
	// create transport layer
	tr := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	// create client
	cl := http.Client{
		Transport: &tr,
	}

	// make request to nessus
	var reqBody = []byte(`{"format":"csv","template_id":"","reportContents":{"csvColumns":{"id":true,"cve":true,"cvss":true,"risk":true,"hostname":true,"protocol":true,"port":true,"plugin_name":true,"synopsis":true,"description":true,"solution":true,"see_also":true,"plugin_output":true,"stig_severity":true,"cvss3_base_score":true,"cvss_temporal_score":true,"cvss3_temporal_score":true,"risk_factor":true,"references":true,"plugin_information":true,"exploitable_with":true}},"extraFilters":{"host_ids":[],"plugin_ids":[]}}`)
	req, req_err := http.NewRequest("POST", conn.Url+"scans/"+strconv.Itoa(task.Id)+"/export", bytes.NewBuffer(reqBody))
	if req_err != nil {
		logger.Error().
			Err(req_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	req.Header = http.Header{
		"X-ApiKeys":    []string{"accessKey=" + conn.TokenAccess + "; secretKey=" + conn.TokenSecret},
		"Content-Type": []string{"application/json"},
	}

	resp, resp_err := cl.Do(req)
	if resp_err != nil {
		logger.Error().
			Err(resp_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer resp.Body.Close()
	// TODO checks for response code != 2xx
	// parse and return results
	if resp.StatusCode != 200 {
		logger.Error().
			Str("module", "scan").
			Msg("Something dark happens with Your server")
		Exitsig <- syscall.SIGHUP
	}
	body, read_err := ioutil.ReadAll(resp.Body)
	if read_err != nil {
		logger.Error().
			Err(read_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	var data ScanExport
	json_err := json.Unmarshal(body, &data)
	if json_err != nil {
		logger.Error().
			Err(json_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	return data
}

func CheckReportStatus(conn config.NessusConn, task *CompletedScan) string {
	// create connection with our options
	caCert, cacert_err := ioutil.ReadFile(conn.CertCA)
	if cacert_err != nil {
		logger.Error().
			Err(cacert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// load CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	// load certs
	clCert, clCert_err := tls.LoadX509KeyPair(conn.CertPub, conn.CertPriv)
	if clCert_err != nil {
		logger.Error().
			Err(clCert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// create tls conf
	tlsConfig := tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}
	// create transport layer
	tr := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	// create client
	cl := http.Client{
		Transport: &tr,
	}
	// make request to nessus
	req, req_err := http.NewRequest("GET", conn.Url+"scans/"+strconv.Itoa(task.Id)+"/export/"+strconv.Itoa(task.ScanExport.File)+"/status", nil)
	if req_err != nil {
		logger.Error().
			Err(req_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	req.Header = http.Header{
		"X-ApiKeys":    []string{"accessKey=" + conn.TokenAccess + "; secretKey=" + conn.TokenSecret},
		"Content-Type": []string{"application/json"},
	}
	resp, resp_err := cl.Do(req)
	if resp_err != nil {
		logger.Error().
			Err(resp_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer resp.Body.Close()
	// TODO checks for response code != 2xx
	body, read_err := ioutil.ReadAll(resp.Body)
	if read_err != nil {
		logger.Error().
			Err(read_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// parse and return results
	var data map[string]interface{}
	d_err := json.Unmarshal(body, &data)
	if d_err != nil {
		logger.Error().
			Err(d_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	return data["status"].(string)
}

func GetReport(conn config.NessusConn, dir config.ConfData, task *CompletedScan) string {
	// create connection with our options
	caCert, cacert_err := ioutil.ReadFile(conn.CertCA)
	if cacert_err != nil {
		logger.Error().
			Err(cacert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// load CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	// load certs
	clCert, clCert_err := tls.LoadX509KeyPair(conn.CertPub, conn.CertPriv)
	if clCert_err != nil {
		logger.Error().
			Err(clCert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// create tls conf
	tlsConfig := tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}
	// create transport layer
	tr := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	// create client
	cl := http.Client{
		Transport: &tr,
	}

	// make request to nessus
	req, req_err := http.NewRequest("GET", conn.Url+"scans/"+strconv.Itoa(task.Id)+"/export/"+strconv.Itoa(task.ScanExport.File)+"/download", nil)
	if req_err != nil {
		logger.Error().
			Err(req_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	req.Header = http.Header{
		"X-ApiKeys":    []string{"accessKey=" + conn.TokenAccess + "; secretKey=" + conn.TokenSecret},
		"Content-Type": []string{"application/json"},
	}

	resp, resp_err := cl.Do(req)
	if resp_err != nil {
		logger.Error().
			Err(resp_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer resp.Body.Close()
	// TODO checks for response code != 2xx
	// parse and return results
	if resp.StatusCode != 200 {
		logger.Error().
			Str("module", "scan").
			Msg("Something dark happens with Your server")
		Exitsig <- syscall.SIGHUP
	}

	outfile, outfile_err := os.Create(filepath.Join(dir.Dir, task.Name+".csv"))
	//  ioutil.ReadAll(resp.Body)
	if outfile_err != nil {
		logger.Error().
			Err(outfile_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer outfile.Close()
	_, cp_err := io.Copy(outfile, resp.Body)
	if cp_err != nil {
		logger.Error().
			Err(cp_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}

	return filepath.Join(dir.Dir, task.Name+".csv")
}

func ChangeScanStatus(conn config.NessusConn, task *CompletedScan) {
	// create connection with our options
	caCert, cacert_err := ioutil.ReadFile(conn.CertCA)
	if cacert_err != nil {
		logger.Error().
			Err(cacert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// load CA
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caCert)
	// load certs
	clCert, clCert_err := tls.LoadX509KeyPair(conn.CertPub, conn.CertPriv)
	if clCert_err != nil {
		logger.Error().
			Err(clCert_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	// create tls conf
	tlsConfig := tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{clCert},
		InsecureSkipVerify: true,
	}
	// create transport layer
	tr := http.Transport{
		TLSClientConfig: &tlsConfig,
	}
	// create client
	cl := http.Client{
		Transport: &tr,
	}

	// make request to nessus
	var reqBody = []byte(`{"read":true}`)
	req, req_err := http.NewRequest("PUT", conn.Url+"scans/"+strconv.Itoa(task.Id)+"/status", bytes.NewBuffer(reqBody))
	if req_err != nil {
		logger.Error().
			Err(req_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	req.Header = http.Header{
		"X-ApiKeys":    []string{"accessKey=" + conn.TokenAccess + "; secretKey=" + conn.TokenSecret},
		"Content-Type": []string{"application/json"},
	}

	resp, resp_err := cl.Do(req)
	if resp_err != nil {
		logger.Error().
			Err(resp_err).
			Str("module", "scan").
			Msg("")
		Exitsig <- syscall.SIGHUP
	}
	defer resp.Body.Close()
	// parse and return results
	if resp.StatusCode != 200 {
		logger.Error().
			Str("module", "scan").
			Msg("Something dark happens with Your server")
		Exitsig <- syscall.SIGHUP
	}
}
