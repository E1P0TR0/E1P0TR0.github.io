---
title: Topology Report
date: 2023-09-05 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, LaTeXi]

img_path: /assets/img/htb/writeups/topology
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.217/32 (Linux)

**TCP Nmap scan:** 65,535 ports

![](nmap_all_ports_TCP.png)

* **Open ports**:
	* **22/ssh**:
		* Banner grabbing
			* Version: OpenSSH_8.2p1 Ubuntu-4ubuntu0.7
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			* Codename: focal [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			* CVEs Version: [https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.2p1](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.2p1)
		* Valid credentials: (vdaisley:calculus20)
	
	 * **80/http**:
		* Banner grabbing
			![](http_banner_grabbing_nc.png)
			* Resolving to Local DNS server: http://topology,htb
				![](http_banner_grabbing_ww.png)
				* Firefox
					![](http_topology_home_page.png)
				* Technologies
					* HttpServer: Apache/2.4.41 (Ubuntu/Linux)
			* Email: lklein@topology.htb (Posible user)
			* Posible users
				* Professor Lilian Klein, PhD (Head of Topology Group)
				* Vajramani Daisley, PhD (Post-doctoral researcher, software developer)
				* Derek Abrahams, BEng (Master's student, sysadmin)
			* Url Scrapping
				![](http_basic_url_scrapping_curl.png)
				* New subdomain: http://latex.topology.htb/equation.php 
					* Create .PNGs of LaTeX equations in your browser
					![](http_latex_topology_home_page.png)
					* Programming languages: **PHP**
					* Software: Latex (Posible Injection attack)
						* TeX category codes (Latex Math "$")
							![](latex_math_code.png)
						* Latext injections: [https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#latex-injection)
			* Subdomain enumeration
				![](subdomain_fuzz_wfuzz.png)
				* http://dev.topology.htb (401)
					![](dev_domain_http.png)
					* Basic HTTP Authentication [https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)
					![](http_basic_auth.png)
				* http://stats.topology.htb (200)
					![](stats_domain_http.png)

## **Vulnerability Assesment**

* * *
* * *

* Latext In/Out math Mode
	* Input: $ (Out math mode error)
		![](latext_math_mode_error_out.png)
	* Input: \$normalmode\$\frac{x+5}{y-3} (not errors)
		![](latext_math_mode.png)
* http://dev.topology.htb (/var/www/dev)
	* Read .htpasswd (file to password-protect a directory on an Apache server)
		![](http_htpasswd_credential_leak.png)

## **Exploitation**

* * *
* * *

* Crack Hash (vdaisley:calculus20)
	![](password_crack.png)
	*  Vajramani Daisley, PhD (Post-doctoral researcher, **software developer**)
		* Reuse Credentials (SSH access)
			![](vdaisley_ssh_access.png)

## **Post-exploitation**

* * *
* * *

* Daisley Enumeration
	* Listing system process (basic pspy.sh)
		![](pspy.png)
		* Gnuplot: (command-line and GUI program)
		* Create **.plt** file with reverse shell, move file to /opt/gnuplot directory (write access), wait one minute aprox and gain access
			![](root.png)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* Latex injection (Read files)
	* Input: \$\lstinputlisting{/etc/issue}\$ (Out math mode and in math mode again to bypass errors)
		![](latext_file_read_poc.png)
* Gnuplot remote command execution
	![](gnuplot_poc.png)