---
title: Manager Report
date: 2023-11-01 12:00:00 pm
categories: [HTB]
tags: [HTB, Windows, Medium, Active Directory, MSSQL, ADCS]

img_path: /assets/img/htb/writeups/manager
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.236/32 (Windows (AD))

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 53/dns:
		* manager.htb
	* 80/http:
		* Banner grabbing
			* Server: Microsoft-IIS/10.0
		* Follow redirect: 
			* Service:
				* Content Writing Services
			* Technologies
				* Boostrap
				* JQuery[3.4.1] (OwlCarousel2/2.1.3)
				* Javascript
				* Cloudflare
			* Headers
				* None
			* Cookies
				* None
			* Emails
				* None
			* Users
				* None
		* Directory Fuzzing
			* file: content/dir_fuzzing
		* Subdomains
			* None
	* 5985 (winrm)
		* Banner grabbing:
			* Server: Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
			* Valid creds: raven:R4v3nBe5tD3veloP3r!123
	* 88, 464 (kerberos,kpasswd)
		* User enumeration
			* Kerbrute
				![](kerbrute.png)
	* 135, 593 (msrpc):
		* Endpoints (rpcdump_output)
	* 139, 445 (SMB):
		* Banner grabbing
			* Windows 10.0 Build 17763 x64 
			* (name:DC01) (domain:manager.htb) (signing:True) (SMBv1:False)
		* User enumeration:
			* Crackmapexec (rid-cycling brute)
				![](rid_brute_cme.png)
	* 389, 636, 3268, 3269 (ldap, ssl):
		* file: ldap_enum_389
	* 1433 (mssql):
		* ms-sql-ntlm-info: 
			* 10.10.11.236:1433: 
				* Target_Name: MANAGER
				* NetBIOS_Domain_Name: MANAGER
				* NetBIOS_Computer_Name: DC01
				* DNS_Domain_Name: manager.htb
				* DNS_Computer_Name: dc01.manager.htb
				* DNS_Tree_Name: manager.htb
				* Product_Version: 10.0.17763
		* ms-sql-info: 
			* 10.10.11.236:1433: 
				* Version: 
					* name: Microsoft SQL Server 2019 RTM
					* number: 15.00.2000.00
					* Product: Microsoft SQL Server 2019
					* Service pack level: RTM
					* Post-SP patches applied: false

## **Vulnerability Assesment**

* * *
* * *

* Equal username and password
	* MSSQL bruteforce (crackmapexec)
		![](mssql_brute.png)
		* Valid Creds (operator:operator)
* MSSQL public funciton (xp_dirtree)
	* Guest user:
		![](xp_dirtree.png)

## **Exploitation**

* * *
* * *

* List website backup file:
	![](xp_dirtree_leak.png)
	* Backup file analysis:
		* Raven user creds: raven:R4v3nBe5tD3veloP3r!123
			![](config_file_creds.png)
			* Valid winrm credentials
				![](winrm.png)
				![](raven_access.png)
* Ryan Enumeration
	* Certificate Authority service (certsvc.msc) && AD Default Group:
		* [Certificate Service DCOM Access](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups)
		![](cert_group.png)
		* Certipy-ad \_decompose solution: [https://github.com/ly4k/Certipy/issues/108](https://github.com/ly4k/Certipy/issues/108)

## **Post-exploitation**

* * *
* * *

* Vulnerable Certificate Authority Access Control
	* Detection (certipy-ad)
				![](vuln_adcs_detection.png)
		* Exploitation
			1. The first command gives us the "Issue and Manage Certificates" authorization.
			2. The second command allow us to approve failed requests ourselves and roll out the corresponding certificates
				3. We can then **issue the failed certificate** request
				4. We can **retrieve the issued certificate** (administrator.pfx)
				![](certipy_1.png)
				* Then we use certificate to login as Administrator
					* Error: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great), Solution: need to synchronise the host with the DC (sudo ntpdate manager.htb)
						![](admin_access.png)
					
		* References
			* [https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation#vulnerable-certificate-authority-access-control-esc7) (certs escerarios + exploitation)
			* [https://posts.specterops.io/certified-pre-owned-d95910965cd2](https://posts.specterops.io/certified-pre-owned-d95910965cd2) (certs escerarios)
			* [https://www.prosec-networks.com/en/blog/adcs-privescaas/](https://www.prosec-networks.com/en/blog/adcs-privescaas/) (certs escerarios + exploitation + video)
			* [https://social.technet.microsoft.com/wiki/contents/articles/10942.ad-cs-security-guidance.aspx#Roles_and_activities](https://social.technet.microsoft.com/wiki/contents/articles/10942.ad-cs-security-guidance.aspx#Roles_and_activities) (ca roles)