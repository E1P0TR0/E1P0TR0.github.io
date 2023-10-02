---
title: Intentions Report
date: 2023-09-30 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Hard, Python Scripting, SQLI, RCE]

img_path: /assets/img/htb/writeups/intentions
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.220/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			- Codename: jammy [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [NIST](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
			- Valid creds: 
				- greg:Gr3g1sTh3B3stDev3l0per!1998!
	* 80/http:
		* Banner grabbing
			* Server: nginx/1.18.0 (Ubuntu)
			* Technologies
				* Nginx 1.18.0
				* X-XSS-Protection: Stops pages from loading when they detect reflected cross-site scripting (XSS) attacks
				* JavaScript 
					* Frameworks: 
						* VueJS/2.7.14 (latest: 3.3.4): No direct vulnerabilities
					* Libraries: 
						* Axios: Not version
						* Core-js/3.27.1 (latest: 3.32.2): No direct vulnerabilities
						* Lodash/4.17.21 (latest: 4.17.21): No direct vulnerabilities
			* Cookies
				* XSRF-TOKEN: Cross-Site Request Forgery protection
				* intentions_session
			* http://10.10.11.220 (Image Gallery):
				* Web page interface (Login page)
					![](10.10.11.220_http_ss.png)
				* Basic web scrapping: init_url_scrapping.txt
					![](10.10.11.220_web_scrapping.png)
				* Registration enabled
					![](10.10.11.220_http_gallery.png)
					* Your Profile Upate feature and Yor feed
						* genres = " ' " -> 500 Internal server error (MySQL?)
							![](gallery_update.png)
							![](fedd_error_500.png)
						* This is a new feature to curate your personal feed! Input your favorite genres separated by commas.
							* Example: animals,food
								![](valid_response.png)
							* Multiple values in a `WHERE` clause
								* SELECT * FROM images WHERE genres IN ('animals','food');
		* Directory Fuzzing
			* /js/admin.js
				* "This will be a major security upgrade for our users, passwords no longer need to be transmitted to the server in clear text!"
				* "I've assigned Greg to setup a process for legal to transfer approved images directly to the server to avoid any confusion or mishaps"
							
## **Vulnerability Assesment**

* * *
* * *

* Multiple values in a `WHERE` clause + bypass `SPACES`:
	* input: ')/\*\*/or/\*\*/1=1#
		![](poc_sqli.png)
	* Web admin users credentials (not crackeable)
		* steve:\$2y\$10\$M/g27T1kJcOpYOfPqQlI3.YfdLIwr3EWbzWOLfpoTtjpeMqpp4twa
		* greg:$2y$10$95OR7nHSkYuFUUxsT1KS6uoQ93aufmrpknz4jwRqzIbsUpRiiyU5m
		* API v2 Login:
			![](api_v2_auth.png)
			* Edit image
				* system path: /var/www/html/intentions/storage/app/public/animals/ashlee-w-wv36v9TGNBw-unsplash.jpg
				* Google searching: "PHP Imagick vulnerabilities"
					* MSL stands for Magick Scripting Language. It’s a built-in ImageMagick language that facilitates the reading of images, performance of image processing tasks, and writing of results back to the filesystem.

## **Exploitation**

* * *
* * *

* Imagick php library (Magic Scripting Language):
	[https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/)
	1. Create image with embed php code
	2. Create Magic Scripting Language file to read local image and write embeded php code to php file. Use of "vid" and "msl" schema
	3. Call php file to get remote code execution
		![](msl_poc.png)
		![](msl_poc_1.png)

## **Post-exploitation**

* * *
* * *

* (www-data) enumeration:
	* Git folder
		* Greg credentials: greg:Gr3g1sTh3B3stDev3l0per!1998!
		![](greg_git_password_leak.png)

## **Lateral movement**

* * *
* * *

* (greg) enumeration:
	* DMCA scanner binary (copyright)
			* With the flag "-l" we can obtain md5 hash of first x bytes of data and brute force any system file (root access)
		![](md5_brute_char.png)
		![](root_rsa.png)

## **Proof of concept**

* * *
* * *

* Database dump (python script)
	![](dump_db_poc.png)
* Remote code execution (Magic Scripting Language)
	![](rce_poc.png)
* File bruteforce (md5 challenge)
	![](md5_poc.png)

* Repository: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Intentions)