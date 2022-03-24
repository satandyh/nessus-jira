# nessus-jira

Simple app that do next:

1. go to nessus with cert/key and look for tasks that you specify
2. if there is new results for those tasks - app will download csv result file
3. parse csv result - filter only (minimal CVSS3/CVSS2/RISK)
4. create tasks in jira according to projects that you specify

I try to make very intelegense app. Thanks for this:

- github.com/spf13/pflag
- github.com/spf13/viper
- github.com/rs/zerolog

So app use good logging to file/stdout/stderr and ENV/configfile for get arguments for work (just start `nessus-jira -h` to see help).

You can add app to cron for even for every 5 minutes. It still will work properly cause:

- there is lock for more that one simulate start
- 24H timer for lock file live
- every task uses it's own independent goroutine

# building
I created make file - just use `make`

To compile better to use static linked file, than dynamic. Cause app will be more cross used and not need installed specific versions of libs.

```bash
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a
```

# TODO

- separate dir for log and config
- auth for user/pass to nessus
- auth for user/pass to jira
- remove mail - rudiment
