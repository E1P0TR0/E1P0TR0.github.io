---
title: Keeper Report
date: 2023-09-04 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Information Leakage, Keepass, CVE-2023-32784]

img_path: /assets/img/htb/writeups/keeper
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.227/32 (Linux)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh**:
		* Banner grabbing
			* Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.3
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			* Codename: jammy-security (codename.py)
			* CVEs Version
				* [https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9)
				![](ssh_posible_cves.png)
		* Valid credentials: (lnorgaard:Welcome2023!)
	
	 * **80/http**:
		* Banner grabbing
			![](http_banner_grabbing_nc.png)
			* Link to an IT Support Ticket domain: http://tickets.keeper.htb/rt/
			* Resolving to Local DNS server
				![](http_banner_grabbing_ww.png)
				* Technologies
					* HttpServer: Nginx/1.18.0 (Ubuntu Linux)
					* Sofware: [Request tracker](https://bestpractical.com/request-tracker) (ticket-tracking software)
						* Version: **4.4.4+dfsg-2ubuntu1 (Debian) Copyright 1996-2019** (2019-03-05)
							* Security updates
							![](rt_4.4.4_security_updates.png)
						* Latest verssion
							* **RT 5.0.4  (2023-05-04)**
						* Github repository: [https://github.com/bestpractical/rt](https://github.com/bestpractical/rt)
						* CVEs version [https://www.cvedetails.com/vulnerability-list/vendor_id-8416/product_id-14710/Bestpractical-Request-Tracker.html](https://www.cvedetails.com/vulnerability-list/vendor_id-8416/product_id-14710/Bestpractical-Request-Tracker.html):
							![](rt_posible_cves.png)
				* HttpOnly header
					* The cookie cannot be accessed through the client-side script (XSS prevention)
				* Email: sales@bestpractical.com
			
			* Login panel
			![](http_rt_login_page.png)
				* Request Tracker (Home)
				![](http_rt_home.png)
				 * Enumeration
					 * Some requests response (Possible cross-site request forgery)
						![](http_rt_approvals.png)
					 * Users
						 * Inorgaard (id:27)(Name: Lise Nørgaard)(Email: lnorgaard@keeper.htb)
							 * Information (Leaked Password in the about section)
								![](http_user_password_leak.png)
						 * root (id:14)(Name: Enoch root)(Email: root@localhost)

## **Vulnerability assessment**

* * *
* * *

* Valid Default credentials (root:password)
	![](google_rt_default_creds.png)
	![](github_rt_default_creds.png)
	* Prevention
		* You should not run this server against port 80 (which is the default port) because that **requires root-level privileges** [https://github.com/bestpractical/rt/blob/stable/docs/web_deployment.pod](https://github.com/bestpractical/rt/blob/stable/docs/web_deployment.pod)
		* Disable root user access, remove privileges or change default password
			![](http_root_prevention.png)

## **Exploitation**

* * *
* * *

* Valid SSH credential (Reuse Credentials) (lnorgaard:Welcome2023!)
	![](ssh_lnorgaard_shell.png)
	* Prevention
		* Inform the employer about **good practices in the exposure and use of passwords**

## **Post-exploitation**

* * *
* * *

* lnorgaard Enumeration
	* RT login (ticket issue)
		![](ticket_issue.png)
		* " Attached to this ticket is a crash dump of the keepass program. Do I need to update the version of the program first...? "
	* Home directory **.zip**: RT30000.zip
		![](rt_zip_content.png)
		![](rt_zip_file_type.png)
		* Keypass files (version 2.x)
			* CVE-2023-32784 [https://nvd.nist.gov/vuln/detail/CVE-2023-32784](https://nvd.nist.gov/vuln/detail/CVE-2023-32784)
				![](kepass_cve_nist.png)
			* Exploits
				* Windows env: [https://github.com/vdohney/keepass-password-dumper](https://github.com/vdohney/keepass-password-dumper)
					![](keepass_exploit.png)
				* Linux env: [https://github.com/4m4Sec/CVE-2023-32784](https://github.com/4m4Sec/CVE-2023-32784)
					![](keepass_exploit_lin.png)
				* Keepass file Password (danish language): "rødgrød med fløde"
* Use **Puttygen** tool to convert .ppk to .pem (open ssh id_rsa)
	![](root_ssh_shell.png)
	* Prevention
		* Upload the latest version
	* Upcoming Keepass Security Preventions (July 2023)
		1. Perform direct API calls for getting/setting the text of the text box, avoiding the creation of managed strings in memory that can leak secrets.
		2. Create dummy fragments containing random characters in the process memory that will have approximately the same length as the user's master password, obfuscating the real key.

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* CVE-2023-32784
	* Windows env (deploy windows virtual machine)
		![](keepassdump_poc.png)
	* Linux env
		![](keepassdump_poc_lin.png)
* Keepass password db access
	* keeweb online [https://app.keeweb.info/](https://app.keeweb.info/) 
		![](keepass_data_root.png)
	* Keepass windows (env machine)
		![](keeepass_root_data.png)