---
title: Cozyhosting Report
date: 2023-10-18 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, RCE]

img_path: /assets/img/htb/writeups/cozyhosting
---


## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.230/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
				* [OpenSSH 9.5](https://www.openssh.com/txt/release-9.5)/[9.5p1](https://www.openssh.com/txt/release-9.5) (2023-10-04)
			- Codename: jammy-security [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [NIST](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
			- Valid creds: 
				- None
	* 80/http:
		* Banner grabbing
			* Server: nginx/1.18.0 (Ubuntu)
		* Follow redirect: http://cozyhosting.htb
			* Technologies
				* Bootstrap (v5.2.3)
				* Lightbox
				* Java
				* Php
				* Spring Boot Error Handling
					![](error_framework_detection.png)
			* Headers
				* UncommonHeaders[x-content-type-options]
				* X-Frame-Options[DENY]
				* X-XSS-Protection[0]
			* Cookies
				* JSESSIONID:6F6CD9A616392EDF4F057FC29B5FC88A (JavaServer Pages (JSP) or Servlet) 
		* Directory Fuzzing
			* Spring wordlist
				![](spring_fuzzing.png)
				* /actuator
					* Actuator mean: **Monitoring our app, gathering metrics, and understanding traffic or the state of our database becomes trivial with this dependency**
					* /sessions [Spring actuator enpoints](https://docs.spring.io/spring-boot/docs/current/reference/html/actuator.html)
						![](session_endpoint.png)
			* file: content/dir_fuzzing
		* Login access
			* Kanderson JSESSIONID:704023E2CCDB8CC82763F23F2952F001
				![](connection_setting.png)

	 * 7777/cbt (Core-Based Tree):
		* Network-layer multicast routing protocol [BFC93]
		* Known Unauthorized Use on port 7777 [IANA]
	* 8083/us-srv:
		* Utilistor (Server), registered 2005-08 [IANA]
* **Filtered ports**:	
	* None

## **Vulnerability Assesment**

* * *
* * *

* Burpsuite
	* SSH backend response
		![](ssh_error_response.png)
* Command Injection: ${IFS} bypass
	* Remote code execution
		![](rce_poc.png)

## **Exploitation**

* * *
* * *

* App user access
	![](app_system_access.png)
	* Web Java file analysis (cloud_hosting.jar)
		* [Spring boot folder structure](https://studygyaan.com/spring-boot/spring-boot-project-folder-structure-and-best-practices)
			* application.properties: Properties file for configuring Spring Boot settings.
			* Postgres credentials:
				![](postgress_creds.png)
			* Postgres access
				* Credentials Offline cracking: kanderson:manchesterunited
				![](josh_access.png)

## **Post-exploitation**

* * *
* * *

* Josh user
	* [Privileged binaries](https://gtfobins.github.io/gtfobins/ssh/)
		* (root) /usr/bin/ssh *
			* SSH options:
				* **ProxyCommand** works by forwarding standard in and standard out (stdio) through an intermediate host
				* Example: ssh -o ProxyCommand="ssh -W %h:%p \<jump server\>" \<remote server\>
				* Inyecting interactive Bash payload
				![](root.png)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* Command Injection PoC: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Cozyhosting)
	![](command_inyection_poc.png)