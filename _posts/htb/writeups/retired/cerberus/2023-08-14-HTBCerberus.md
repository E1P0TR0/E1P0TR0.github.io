---
title: Cerberus Notes
date: 2023-08-14 12:00:00 pm
categories: [HTB]
tags: [HTB, Windows, Hard, CVE-2022-24715, CVE-2022-24716]

img_path: /assets/img/htb/writeups/cerberus
---

# Cerberus Notes

* * *

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.205/32 (Windows Machine)

![](target_connection.png)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:

	- **8080/http-proxy**:
		- Banner grabbing
		![](8080_banner_grabbing.png)
		![](8080_banner_grabbing_ww.png)
		![](8080_banner_grabbing_curl.png)
		![](8080_banner_grabbing_lynx.png)
		* Server: Apache/2.4.52 (Ubuntu) (172.16.22.2:80)
			* Server mounted on a **different network**
			* Redirection: http://icinga.cerberus.local:8080/icingaweb2
			* Add to Local DNS server:
			![](8080_add_domain.png)
			![](8080_banner_grabbing_ww_1.png)
		* Web Service enumeration:
			* Firefox:
			![](8080_firefox.png)
			![](8080_TODO.png)
			* Curl Url scrapping:
			![](8080_url_scrap_curl.png)
			* Service: Icinga web2:
				* What is Icinga?: [https://github.com/Icinga](https://github.com/Icinga)
					* Icinga is a resilient, open source monitoring and metric solution system.
					![](Icinga_mean.png)
				* Icinga web2: [https://github.com/Icinga/icingaweb2](https://github.com/Icinga/icingaweb2)
					* A lightweight and extensible web interface to keep an eye on your environment. Analyse problems and act on them.
				* searchsploit:
				![](searchsploit_icinga.png)


## **Vulnerability assessment**

* * *
* * *

* CVE-2022-24716:
![](cve-2022-24716.png)

* NIST: [https://nvd.nist.gov/vuln/detail/CVE-2022-24716](https://nvd.nist.gov/vuln/detail/CVE-2022-24716)

* PoC: [https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/](https://www.sonarsource.com/blog/path-traversal-vulnerabilities-in-icinga-web/)
	* Bash script (PoC):
		![](cve-2022-24716_PoC.png)

* CVE-2022-24715: (authenticated)
![](cve-2022-24715.png)

* Nist: [https://nvd.nist.gov/vuln/detail/CVE-2022-24715](https://nvd.nist.gov/vuln/detail/CVE-2022-24715)

* Exploitation process: [https://exploit-notes.hdks.org/exploit/web/icinga-web-pentesting/](https://exploit-notes.hdks.org/exploit/web/icinga-web-pentesting/)

* Payload:
	![](cve-2022-24715_info.png)

## **Exploitation**

* * *
* * *

* Enumeration (CVE-2022-24716):
	* System:
		* /etc/issue & /etc/lsb-release: **Ubuntu 22.04.1** LTS (codename: jammy)
		* /proc/version: **Linux version 5.15.0-43-generic** (buildd@lcy02-amd64-076) (gcc (Ubuntu 11.2.0-19ubuntu1) 11.2.0, GNU ld (GNU Binutils for Ubuntu) 2.38) 46-Ubuntu SMP Tue Jul 12 10:30:17 UTC 2022
	* Icinga default config files: [https://icinga.com/docs/icinga-web/latest/doc/03-Configuration/](https://icinga.com/docs/icinga-web/latest/doc/03-Configuration/)
		![](icinga_default_conf_files.png)
		* /etc/icingaweb2/resources.ini
		* /etc/icingaweb2/roles.ini
		* /etc/icingaweb2/authentication.ini
		* Python script [https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/CVEs_Cerberus/cve-2022-24716.sh](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/CVEs_Cerberus/cve-2022-24716.sh)
			![](icinga_config_files_creds.png)
		* Icinga administrator Database and authentication credentials: 
			* user:pass: **matthew:IcingaWebPassword2023**
			* dbname: icingaweb2
			* host: 172.16.22.1
		* Icinga web service authentication: (matthew:IcingaWebPassword2023)
			![](dashboard_icinga_service.png)
			* About:
				![](icinga_about.png)

* Exploitation (CVE-2022-24715): [https://github.com/JacobEbben/CVE-2022-24715/blob/main/exploit.py#L331](https://github.com/JacobEbben/CVE-2022-24715/blob/main/exploit.py#L331)(reference)
	* Python script: [https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/CVEs_Cerberus/cve-2022-24715.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/CVEs_Cerberus/cve-2022-24715.py)
	
	. . . 

## **Post-exploitation**

* * *
* * *

## *Lateral movement*

* * *
* * *

## *Proof of concept*

* * *
* * *