# Spring4Shell-Detection with Splunk
Lazy SPL to detect CVE-2022-22965 - Spring4Shell & CVE-2022-22963 exploitation.

[Find more awesome Threat Hunting SPL queries, including BPFDoor detection here](https://github.com/west-wind/Threat-Hunting-With-Splunk)

## Detecting & Responding to Spring4Shell with Splunk | Medium

Read my write up here [Detecting & Responding to Spring4Shell with Splunk | Medium](https://subtlystoic.medium.com/detecting-and-responding-to-spring4shell-with-splunk-89ade99f35fb)

## Detection for Spring4Shell

Splunk detection SPL for CVE-2022-22965 (Spring4Shell) webshell -- [PoC Exploit](https://github.com/craig/SpringCore0day) 

```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) status=200
| rex field=url "(?<webShell>\/.*\.(jsp|class)\?.*=.*)" 
| rex field=uri "(?<webShell>\/.*\.(jsp|class)\?.*=.*)"
| where isnotnull(webShell) 
| eval Domain = mvappend(dest, domain), fullURL = mvappend(url, uri)
| table _time src_ip Domain status method webShell fullURL sourcetype
```

Splunk detection SPL for CVE-2022-22965 (Spring4Shell) [PoC Exploit](https://github.com/craig/SpringCore0day) attempting to change Tomcat logging
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) (method=POST OR method=GET) url="*?class.module.classloader.resources.context.parent.pipeline.first.pattern=*"
| table _time src_ip dest_domain url headers user_agent status
```

Detection based on Linux audit logs (untested). 

If you find suspicious files being created, correlate with type=CWD & check the 'cwd' path. Check if the path is your webapps' ROOT/ directory. Correlate with other above detection rules (nginx/web app firewall) to identify source IP. 
```sh
index=linux_index sourcetype="linux:auditd" type=PATH name="*.jsp"
| table _time host type name
```

Detection for CVE-2022-22965 (Spring4Shell) [PoC Exploit](https://github.com/craig/SpringCore0day)
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) status=200 (method=POST OR method=GET) (url=*.jsp* OR url=*.class*)
| table _time src_ip dest_domain url headers
```
## Detection for CVE-2022-22963 (not Spring4Shell)

Detecting from Linux syslog (CVE-2022-22963, not Spring4Shell)
```sh
index=linux_index sourcetype=linux_messages_syslog 
| rex field=_raw "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| where isnotnull(execData)
| table _time host execData
```

Detection for POC exploit (CVE-2022-22963, not Spring4Shell) -- [PoC Exploit](https://github.com/dinosn/CVE-2022-22963)  
```sh
index=web_apps (sourcetype=nginx OR sourcetype=webapp_firewall) (status=200 OR status=500) method=POST url="/functionRouter" // Better not to specify URL as anyone can change this
| rex field=headers "(?<execData>(?<=\.)getRuntime\(\)\.exec[^;]*)"
| table _time src_ip dest_domain execData url
```
## Discussion Around Additional Detections

Please visit [Discussions](https://github.com/west-wind/Spring4Shell-Detection/discussions/new) 

## Raise an Issue

Want to optimise the SPL queries? Please visit [Issues](https://github.com/west-wind/Spring4Shell-Detection/issues/new)
