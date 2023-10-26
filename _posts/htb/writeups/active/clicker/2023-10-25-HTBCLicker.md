---
title: Clicker Report
date: 2023-10-25 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, Python Scripting, CRLF, Command Injection, RCE]

img_path: /assets/img/htb/writeups/clicker
---


## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.232/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.4
				* [OpenSSH 9.5](https://www.openssh.com/txt/release-9.5)/[9.5p1](https://www.openssh.com/txt/release-9.5) (2023-10-04)
			- Codename: jammy [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [NIST](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
			- Valid creds: 
				- None
	* 80/http:
		* Banner grabbing
			* Server: Apache/2.4.52 (Ubuntu)
		* Follow redirect: http://clicker.htb/
			* Services:
				* The clicker game
			* Technologies
				* Bootstrap v4.3.1
				* PHP
			* Headers
				* None
			* Cookies
				* PHPSESSID=q790rl9f70uasg0i39ib7pgth4 (dynamic)
			* Emails
				* None
			* Users
				* None
		* Directory Fuzzing
			* file: content/dir_fuzzing
			* register.php && login.php:
				* Acccount created: marss:marss
		* Subdomains
			* None
		* Code analysis (clicker.htb)
			* save_game.php
				![](save_game_code.png)
			* db_utils.php
				![](update_data_code.png)
			* authenticate.php
				![](load_profile.png)
			* index.php
				![](admin_role_code.png)
			
	* 111/rpcbind,2049/nfs:
		* Data available to mount: /tmp/backups (Webpage content)
			* clicker.htb
	* Unknown
		* 32791,43287,43905,46507,56687

* **Filtered ports**:	
	* None

## **Vulnerability Assesment**

* * *
* * *

* [CRLF (Carriage Return && Line Feed)](https://book.hacktricks.xyz/pentesting-web/crlf-0d-0a)
	* Bypass \$\_GET request input data
		* Local testing (index.php)
			![](crlf_local_test.png)
			* Valid injections: %0d%0a...,%0a...,...%0d%0a,...%0a
* Remote Code Execution
	* Code injection on "nickname" variable (save_game.php)
		![](code_injection.png)
		![](injeciton_poc.png)
	* Exporting file (no extension check)
		![](extension_bypass.png)
		![](extension_bypass_2.png)

## **Exploitation**

* * *
* * *

* CRLF (Carriage Return && Line Feed)
	* Change User rol to Admin role
		![](change_rol.png)
	* Login again to load profile (authenticate.php)
		![](admin_role_changed.png)
* PHP code injection to RCE
	![](php_code_injection.png)
	![](php_code_injection_2.png)
	![](php_code_injection_3.png)
* www-data enumeration
	* SUID binary (Jack user)
		* Code analysis
			![](code_analysis_binary.png)
			* With an invalid option we can insert any file to save in "sql_file" variable and then read it
				* sql_file = create.sql
				* /usr/bin/mysql -u clicker_db_user --password='clicker_db_password' clicker -v < /home/jack/queries/"sql_file"
			* Read private id_rsa key (jack)
				![](jack_id_rsa.png)

## **Post-exploitation**

* * *
* * *

* Jack enumeration
	* SUID binary (monitor.sh)
		* SETENV: set own enviroment variables
			![](jack_suid.png)
	* /opt/monitor.sh
		![](monitor_sh.png)
		* Perl script
			* ENVIRONMENT: (perlrun)
				* [PERL5OPT](https://www.elttam.com/blog/env/#content): environment variable allows specifying command-line options (-[CDIMTUWdmtw])
				* PERL5DB: load debug code
					![](root.png)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *
* Remote Code execution	[clicker.htb](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Clicker)
	![](rce_poc.png)