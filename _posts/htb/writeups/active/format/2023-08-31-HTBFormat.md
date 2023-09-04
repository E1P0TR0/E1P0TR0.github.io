---
title: Format Report
date: 2023-08-31 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, LFI, RCE, Python Scripting]

img_path: /assets/img/htb/writeups/format
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.213/32 (Linux)

![](target_connection.png)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh (Secure Shell Protocol)**
		* Banner grabbing
			* Version: OpenSSH_8.4p1 Debian-5+deb11u1
			* Codename
			![](get_codename.png)
	 * **80/http (Hypertext Transfer Protocol)**
		* Banner grabbing
			* http://10.10.11.213
				![](http_banner_grabbing_nc.png)
				* Technologies
					* Server version: Nginx 1.18.0
					* Redirect: http://app.microblog.htb
			* http://app.microblog.htb (app to create blog with any subdomain)
				![](http_banner_grabbing_ww.png)
				* Technologies
					* Jquery 3.6.1
				* Interface
					![](http_firefox.png)
				* Default cookie: username=gegmloskesuar8vml26rnhtg9t
				* Basic url scrapping
					![](basic_url_scrapping.png)
					*  http://app.microblog.htb/register (valid)
						* Created blog: http://marss.microblog.htb/
						* Technologies
							* Php
						* **Vulnerable to basic XSS (Cross Site Scripting)**
							![](basic_xss_poc.png)

	 * **3000/ppp (Point to Point Protocol)**
		* Banner grabbing
			![](http_3000_banner_grabbing.png)
			* Technologies
				* Server: Nginx 1.18.0
				* Redirect: http://microblog.htb:3000
				* Service: Gitea (1.17.3) 
			* Interface
				![](firefox_3000_http.png)
			* Basic url scrapping
				![](basic_url_scrapping_3000_http.png)
			* http://microblog.htb:3000/cooper/microblog (Microblog Git) (Dangerous)
				* User: cooper
				* Code analysis (http://microblog.htb:3000/cooper/microblog.git)
					* microblog/microblog-template/edit/index.php (fetchPage function)
						* This functions add a header or text to our blog:
							1. A file is created with the html content to be entered and without verification, the "id" parameter of the request is used as the file name
							2. Then the "id" value is added to "order.txt"
								![](code_analysis_poc2.png)
						* This function read every line of "order.txt" file and use file_get_contents() **(Local File Inclusion!)**
							![](code_analysis_poc1.png)
							![](lfi_poc.png)

## **Vulnerability assessment**

* * *
* * *

* Nginx server configuration file (/etc/nginx/sites-available/default) (http://app.microblog.htb)
	![](nginx_conf_file.png)
	* Controlling proxied host: [https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/](https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/)
		*  location ~ /static/(.\*)(.\*) -> proxy_pass http:\/\/$1.microbucket.htb\/$2
			* Example: microblog.htb/statis/js/test.js -> http://js.microblog.htb/test.js
			* Nginx supports **proxying requests to local unix sockets**
				* Server unix socket leaked (source code Gitea)
					![](redis_socket_code.png)
				* Example to get info server (no response):
					* Request: INFO /static/unix:/var/run/redis/redis.sock:server%20/app.js HTTP/1.1
					* Breakdown: http://unix:/var/run/redis/redis.sock:server%20microblog.htb/app.js
					* Socket receive: INFO server -microbucket.htb/app.js HTTP/1.0
				* Server example:
					* Change current username (first-name)
						* Redis function: HSET [https://redis.io/commands/hset/](https://redis.io/commands/hset/)
							* HSET key field value
							* Request: HSET /static/unix:/var/run/redis/redis.sock:\<key>%20<field\>%20\<value\>%20/any (last space is important to valid command, see previous example)
							* Breakdown:  http://unix:/var/run/redis/redis.sock:key%20field%20value%20microblog.htb/any
							* Socket receive: HSET key field value microblog.htb/any HTTP/1.0

* Code analysis (microblog/microblog-template/edit/index.php)
	![](upload_image_code_analysis.png)
	![](id_pro_code_analysis.png)
	![](user_creation_pro_field.png)
	![](pro_environment.png)
	* We can change permission to be a **pro user** and upload a "image" with php code (rabbit hole)

## **Exploitation**

* * *
* * *

* Create user and conver to **Pro**
	![](convert_to_pro.png)
	* Like pro user we have access to **/uploads**:
		* path = /var/www/microblog/" . $blogName . "/uploads
		* Use previous LFI to create a file on upload folder and view/execute content (**pwned**)
			![](upload_file_poc.png)
	* Execute reverse shell in bash and receive a shell like **www-data**
		![](www-data_shell.png)
	
## **Post-exploitation**

* * *
* * *

* **www-data** user
	* Redis socket connection (no authentication)
		* Cooper credentials leaked: cooper:zooperdoopercooper
		![](cooper_redis_leak_creds.png)

## **Lateral movement**

* * *
* * *

* Reusing Credentials (cooper:zooperdoopercooper)
	![](cooper_shell.png)
	* Binary with SUDO permissions (/usr/bin/license)
		* Code analysis
			![](format_code.png)
			* Format String vulnerability (PoC below)
				1. Create hash key on redis database to read secret variable
					![](root_secret.png)
					![](root.png)

## **Proof of concept**

* * *
* * *

* Python script **(LFI)**
	![](lfi_poc_py.png)
* Change redis data (redis sock)
	![](redis_socket_change_name_poc.png)
* Python format function vulnerability
	![](python_format_poc.png)
* Python PoC script: [https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Format](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Format)