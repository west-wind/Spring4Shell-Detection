# Spring4Shell-Detection
Lazy SPL to detect Spring4Shell exploitation

Detecting from Linux syslog
```sh
index=linux_index sourcetype=linux_messages_syslog 
| rex field=_raw "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| where isnotnull(execData)
| table _time host execData
```

Detection for POC exploit -- https://github.com/dinosn/CVE-2022-22963 
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) (status=200 OR status=500) method=POST url="/functionRouter" // Better not to specify URL as anyone can change this
| rex field=headers "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| table _time src_ip dest_domain execData url
```

Detection for POC exploit -- https://github.com/craig/SpringCore0day 
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) status=200 (method=POST OR method=GET) (url=*.jsp* OR *.class*)
| table _time src_ip dest_domain url headers
```
