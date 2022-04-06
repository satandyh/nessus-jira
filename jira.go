package main

import (
	"io"
	"os"

	"github.com/andygrunwald/go-jira"
	"github.com/satandyh/nessus-jira/internal/config"
)

func JiraCreateTask(c config.ConfJira, scans config.Conf, tasks []CompletedScan) {
	//jiraClient, _ := jira.NewClient(nil, "https://issues.apache.org/jira/")
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
	// cycle thru all projects
	for _, proj := range scans.Nessus.Scans {
		// cycle thru all task in projects
		for _, newTask := range proj.TaskName {
			//read attachment file
			var r io.Reader
			for _, task := range tasks {
				// create task only if
				// - name task the same like in our results
				// - there are some results
				if newTask == task.Name && task.c_res != 0 {
					f, f_err := os.Open(task.FileName + "_parsed")
					if f_err != nil {
						logger.Error().
							Str("module", "jira").
							Err(f_err).
							Msg("")
					}
					defer f.Close()
					r = f
					i := jira.Issue{
						Fields: &jira.IssueFields{
							Description: proj.Description,
							Type: jira.IssueType{
								Name: proj.Type,
							},
							Project: jira.Project{
								Key: proj.Project,
							},
							Summary: proj.IssueName + " " + newTask,
						},
					}
					if len(proj.Component) > 0 {
						i.Fields.Components = append(i.Fields.Components, &jira.Component{Name: proj.Component})
					}
					// create task
					issue, resp, is_err := jiraClient.Issue.Create(&i)
					if is_err != nil {
						bodyBytes, _ := io.ReadAll(resp.Body)
						bodyString := string(bodyBytes)
						logger.Error().
							Str("module", "jira").
							Err(is_err).
							Msg(bodyString)
					}
					if resp.Response.StatusCode != 201 {
						logger.Error().
							Str("module", "jira").
							Msg(resp.Response.Status)
					}

					// add watchers
					for _, watName := range proj.Watchers {
						wat_resp, wat_err := jiraClient.Issue.AddWatcher(issue.ID, watName)
						if wat_err != nil {
							logger.Error().
								Str("module", "jira").
								Msg(wat_resp.Response.Status)
						}
					}
					// add attachment
					_, att_resp, att_err := jiraClient.Issue.PostAttachment(issue.ID, r, newTask+".csv")
					if att_err != nil {
						logger.Error().
							Str("module", "jira").
							Msg(att_resp.Response.Status)
					}
					logger.Info().
						Str("module", "jira").
						Msg("Created " + issue.Key + " task for group " + task.Name)
				}
			}
		}
	}
}
