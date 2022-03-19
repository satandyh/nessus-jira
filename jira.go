package main

import (
	"fmt"

	"github.com/andygrunwald/go-jira"
	"github.com/satandyh/nessus-jira/internal/config"
)

func JiraTest(c config.ConfJira) {
	tp := jira.BasicAuthTransport{
		Username: c.User,
		Password: c.Pass,
	}

	jiraClient, cl_err := jira.NewClient(tp.Client(), c.Url)
	if cl_err != nil {
		logger.Error().
			Str("module", "jira").
			Err(cl_err).
			Msg("")
	}
	issue, resp, issue_err := jiraClient.Issue.Get("XXXX", nil)
	if issue_err != nil {
		logger.Error().
			Str("module", "jira").
			Err(issue_err).
			Msg("")
	}
	if resp.Response.StatusCode != 200 {
		logger.Error().
			Str("module", "jira").
			Msg(resp.Response.Status)
	}

	fmt.Printf("%s: %+v\n", issue.Key, issue.Fields.Summary)
	fmt.Printf("Type: %s\n", issue.Fields.Type.Name)
	fmt.Printf("Priority: %s\n", issue.Fields.Priority.Name)

}

/*
func JiraCreateTask(c config.ConfJira, scans config.Conf, tasks []CompletedScan) {
	//jiraClient, _ := jira.NewClient(nil, "https://issues.apache.org/jira/")
	tp := jira.BasicAuthTransport{
		Username: "username",
		Password: "token",
	}
	jiraClient, _ := jira.NewClient(tp.Client(), c.Url)
	issue, _, _ := jiraClient.Issue.Get("MESOS-3325", nil)

	fmt.Printf("%s: %+v\n", issue.Key, issue.Fields.Summary)
	fmt.Printf("Type: %s\n", issue.Fields.Type.Name)
	fmt.Printf("Priority: %s\n", issue.Fields.Priority.Name)

	// MESOS-3325: Running mesos-slave@0.23 in a container causes slave to be lost after a restart
	// Type: Bug
	// Priority: Critical
}
*/
