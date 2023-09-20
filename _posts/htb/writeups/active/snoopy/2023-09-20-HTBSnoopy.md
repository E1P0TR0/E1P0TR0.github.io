---
title: Snoopy Report
date: 2023-09-20 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Hard, LFI, CVE-2023-20052, DNS, Bash Scripting, Python Scripting]

img_path: /assets/img/htb/writeups/snoopy
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.212/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			- Codename: jammy [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:8.9p1)
			- Valid creds: cbrown:sn00pedcr3dential!!!
	* 53/dns:
		* Zone transfer
			![](dns_transfer_zone.png)
			* Nameservers:
				* ns1.snoopy.htb (10.0.50.10)
				* ns2.snoopy.htb (10.0.51.10)
			* Subdomains:
				* mattermost.snoopy.htb (172.18.0.3)
				* mm.snoopy.htb (127.0.0.1)
				* postgres.snoopy.htb (172.18.0.2)
				* provisions.snoopy.htb (172.18.0.4)
				* www.snoopy.htb (127.0.0.1) *

	* 80/http:
		* Banner grabbing
			* Server: nginx/1.18.0 (Ubuntu)
			* Url scrapping:
			![](basic_url_scrapping_curl.png)
			* Domains: snoopy.htb, mail.snoopy.htb
			* Web server: http://10.10.11.212
				* SnoopySec is a leading provider of DevSecOps tooling for web-based businesses
				* Release package: http://snoopy.htb/download
				* PDF announcement: http://snoopy.htb/download?file=announcement.pdf (SnoopySec's DevSecOps tooling or to schedule a demo about: www.snoopy.htb)
			* Contact info:
				* Attention:  As we migrate DNS records to our new domain please be advised that our **mailserver 'mail.snoopy.htb' is currently offline**.
				* SnoopySec PR (pr@snoopy.htb)
				* Form test
				![](contact_form_php_error.png)
			* User enumeration:
				* Charles Schultz (Chief Executive Officer) (cschultz@snoopy.htb)
				* Sally Brown (Product Manger) (sbrown@snoopy.htb)
				* Harold Angel (CTO) (hangel@snoopy.htb)
				* Lucy Van Pelt (Accountant) (lpelt@snoopy.htb)
	* http://mm.snoopy.htb (127.0.0.1)
		![](mm_snoppy_domain.png)
		* Mattermost version: 7.9.0 (X-Version-Id: 7.9.0.7.9.0.c7ce78937711597df2938cf8dd2034c7.false)
		* NO valid credentials
		* Password reset (need email)
			![](mm_password_reset.png)

## **Vulnerability Assesment**

* * *
* * *

* http://snoopy.htb/download?file=<basic_bypass> (vulnerable to LFI)
	![](basic_lfi.png)
* Insecure DNS update
	![](dns_secret_key.png)
	![](insecure_dns_update.png)
	* [allow-update](https://www.zytrax.com/books/dns/ch7/xfer.html#allow-update): **allow-update** defines an [address_match_list](https://www.zytrax.com/books/dns/ch7/address_match_list.html) of hosts that are allowed to **submit dynamic updates for master zones** 
		* We can update mail server records to enable the password reset service on "mattermost" (local)
* Password reset send
	![](smpt_mail_server.png)
	![](pass_reset.png)
	* Remove "=3D" characters to valid token
		![](reset_pass.png)
		* User: cschultz@snoopy.htb
		* Password: password123$!
		![](mattermost_home_page.png)
	* Cbrown: "Hey everyone, I just created a new channel dedicated to submitting requests for new server provisions as we start to roll out our new DevSecOps tool"
		* /server_provision command
		![](server_provision_command.png)

## **Exploitation**

* * *
* * *

* SSH-MITM (cbrown access) [cbrown:sn00pedcr3dential!!!]
	![](ssh_mitm.png)
	* Cbrown enumeration
		* Sudo binary like sbrown
			* CVE-2023-23946
			![](git_apply_poc.png)

## **Post-exploitation**

* * *
* * *

* Sbrrown enumeration
	* Sudo binary like root [CVE-2023-20052](https://nvd.nist.gov/vuln/detail/CVE-2023-20052)
		![](cve_iso_dmg.png)
		![](root.png)
		* DMG generator github [https://github.com/nokn0wthing/CVE-2023-20052](https://github.com/nokn0wthing/CVE-2023-20052)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* http://snoopy.htb/download?file= (vulnerable to LFI)
	![](lfi_poc.png)
* DNS record update
	![](dns_update_poc.png)
* Password reset
	![](password_reset_poc.png)
* Script repository: [https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Snoopy](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Snoopy)
