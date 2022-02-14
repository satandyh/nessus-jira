# nessus-jira
nessus-jira export task

# building
To compile better to use static linked file, than dynamic. Cause app will be more cross used and not need installed specific versions of libs.

```bash
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a
```
