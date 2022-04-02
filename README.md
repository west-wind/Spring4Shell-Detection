# Spring4Shell-Detection
Lazy SPL to detect CVE-2022-22965 - Spring4Shell & CVE-2022-22963 exploitation


Splunk detection SPL for CVE-2022-22965 (Spring4Shell) webshell -- https://github.com/craig/SpringCore0day 
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) status=200
| rex field=url "(?<webShell>\/.*\.(jsp|class)\?.*=.*)" 
| rex field=uri "(?<webShell>\/.*\.(jsp|class)\?.*=.*)"
| where isnotnull(webShell) 
| eval Domain = mvappend(dest, domain), fullURL = mvappend(url, uri)
| table _time src_ip Domain status method webShell fullURL sourcetype
```

Splunk detection SPL for CVE-2022-22965 (Spring4Shell) POC exploit attempting to change Tomcat logging
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) (method=POST OR method=GET) url="*?class.module.classloader.resources.context.parent.pipeline.first.pattern=*"
| table _time src_ip dest_domain url headers user_agent status
```

Detection for CVE-2022-22965 (Spring4Shell) POC exploit  
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) status=200 (method=POST OR method=GET) (url=*.jsp* OR *.class*)
| table _time src_ip dest_domain url headers
```

Detecting from Linux syslog (CVE-2022-22963, not Spring4Shell)
```sh
index=linux_index sourcetype=linux_messages_syslog 
| rex field=_raw "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| where isnotnull(execData)
| table _time host execData
```

Detection for POC exploit (CVE-2022-22963, not Spring4Shell) -- https://github.com/dinosn/CVE-2022-22963 
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) (status=200 OR status=500) method=POST url="/functionRouter" // Better not to specify URL as anyone can change this
| rex field=headers "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| table _time src_ip dest_domain execData url
```
