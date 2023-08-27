---
title: Authority Notes
date: 2023-08-03 12:00:00 pm
categories: [HTB]
tags: [HTB, Windows, Medium, ADCS, LDAP Relay]

img_path: /assets/img/htb/writeups/authority
---

# Authority Report

* * *
* * *

## **Information gathering**

* * *

**Scope:** 10.10.11.222 (Windows) [Active Directory]

![](target_ping.png)

### **Open ports:**

**53/domain (Domain name system):**
![](dig_any_records.png)

**80/http (Hypertext transfer protocol):**
* whatweb:
    - HTTPServer[Microsoft-IIS/10.0]
        ![](http_web.png)

**88/kerberos-sec (Kerberos authentication protocol),464/kpasswd5 (allows changing user passwords):**
* No stuff

**135/msrpc (Remote procedure call),593/http-rpc-epmap (RPC over http):**
* Required credentials: True

**139/netbios-ssn,445/microsoft-ds (Network file sharing protocol over NetBIOS):**
* crackmapexec:
    - Windows 10.0 Build 17763 x64 [Windows Server 2019 (version 1809)]
    - (name:AUTHORITY) (domain:[authority.htb]) (signing:True) (SMBv1:False)
* Smbmap:
    - Guest acess: Enabled
        ![](smb_guest_access.png)
* Smbclient:
    - Downloaded data:
        ![](smb_downloaded_share.png)
    * Ansible: Used to [manage and execute core functions in Windows environments], from security updates to remote management [using WinRM]
        - ADCS (Active Directory Certificate Services): Provides [public key infrastructure (PKI)] for cryptography, digital certificates and signature capabilities:
            ![](adcs_ca_key_info.png)
        - requirements.txt:
            - ansible>=2.10
            - jinja2>=2.11.2
        - tox.ini:
            - minversion = 3.21.4
            - envlist = py{310}-ansible-{4,5,6}
        - LDAP (Lightweight directory access protocol)
            - Todo.md
                ![](ldap_TODO.png)
            - .travis.yml
                ![](ldap_travis_env.png)
        - PWM (Pulse Width Modulation): Open source [password self-service application for LDAP directories]
            - ansible.cfg: Ansible configuration file
                - remote_user = svc_pwm
            - ansible_inventory: Allows system administrators to [keep track of their managed remote systems]
                ![](pwn_ansible_creds.png)
            - defaults/main.yml: [https://docs.ansible.com/ansible/latest/vault_guide/vault_managing_passwords.html](https://docs.ansible.com/ansible/latest/vault_guide/vault_managing_passwords.html)
                ![](pwn_creds.png)
            - John cracking: secret -> !@#$%^&*
                ![](pwm_creds_john_cracking.png)
            - ansible-vault: [https://www.shellhacks.com/ansible-vault-encrypt-decrypt-string/](https://www.shellhacks.com/ansible-vault-encrypt-decrypt-string/)
                ![](pwn_ansible_decrypt_creds.png)
            - admin-login: [svc_pwm]
            - admin-password: [pWm_@dm!N_!23]
            - ldap_admin_pass: [DevT3st@123]
            
            - Ansible vaults: Feature that [allows users to encrypt values and data structures within Ansible projects]
                - templates/tomcat-users.xml.j2:
                    - username="[admin]" password="[T0mc@tAdm1n]" roles="manager-gui"
                    - user username="[robot]" password="[T0mc@tR00t]" roles="manager-script"
            - SHARE:
                ![](share_internal_paths.png)

**389/ldap,636/ldapssl (Lightweight directory access protocol):**
* No stuff.

**5985/wsman (Web services-management),47001/winrm (Windows remote management):**
* No stuff.

**8443/https-alt (Http secure):**
* curl:
    ![](https_curl.png)
* PWN: 
    - Config mode:
        ![](ldap_config_mode_msg.png)
    - Version:
        ![](pwm_version.png)
    - Login error: [5017]
        - ldaps://authority.authority.htb:636 as CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
        ![](pwm_https_login_error.png)
        - Access: [pWm_@dm!N_!23]
            - Configuration manager:
                ![](pwm_access_dashboard.png)
        - Confifuration editor:
                ![](pwn_access_editor.png)
            
**9389/adws (Active directory web service):**
* No stuff.

**49664/unknown**

**49665/unknown**

**49666/unknown**

**49667/unknown**

**49671/unknown**

**49684/unknown**

**49685/unknown**

**49687/unknown**

**49688/unknown**

**49696/unknown**

**49699/unknown**

**49704/unknown**

**49713/unknown**

## **Vulnerability assessment**

* * *

* https://authority.htb:8443/pwm/private/config/manager:
    - We can download and upload PWM configuration file: [PwmConfiguration.xml]
        ![](upload_download_config_files.png)

## **Exploitation**

* * *

* LDAP Relay attack:
    - responder: Capturing svc_ldap password in cleartext
        ![](ldap_capture_cleartex_pass.png)
        - [LDAP] Cleartext Client   : 10.10.11.222
        - [LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
        - [LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
    - crackmapexec:
        - Valid credentials to winrm:
            ![](winrm_valid_creds.png)
    - Access-evil-winrm:
        ![](evil-winrm_access.png)

## **Post-exploitation**

* * *

* ADCS Review:
    - A certificate template collection of settings that [defines the policies and rules that a CA uses when a  request for a certificate is received]
    - CA (Certificate Authority]):
    - PKI (Public Key Infrastructure): [Manages certificates and public key encryption]
    - AD CS (Active directory Certificate Services): [Microsoft's PKI implementation which usually runs on domain controllers]
    - CA (Certificate Authority): [PKI that issues certificates]
    - CSR (Certificate Signin Request): [message sent to a CA to request a signed certificate]
    - EKU (Extended/Enhanced Key Usage): object identifiers that [define how a generated certificate may be used]
    - Administrators of AD CS can create several templates that can allow any user with the relevant permissions to request a certificate themselves
    ![](adcs_diagram.png)

* Abusing Active Directory Certificate Services (ADCS):
    - 1st method:
        - Manual search:
            ```powershell
            certutil -v -template > cert_templates.txt
            foreach ($template in type cert_templates.txt | select-string -Pattern 'Template\[\d{1,2}\]|Allow Enroll|Allow Full Control|Client Authentication|CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT') { echo "$template"; }
            ```
            - Template[8]
        - Certify:
            ```powershell
            .\Certify.exe find /vulnerable 
            ```
            ![](template_vulnerable_certify.png)
            ```powershell
            .\Certify.exe request /ca:authority.authority.htb\AUTHORITY-CA /template:CorpVPN /altname:Administrator
            ```
            [FAILED]
    - 2nd method:
        - Authenticated Users group: Can enrol up to 10 new machines on the domain
            - Validate write to DNS hostname: This permission allows us to [update the DNS hostname of our AD Object] associated with the host.
            - Validate write to Service Principal Name (SPN): This permission allows us to [update the SPN of our AD Object] associated with the host.
        - SPNs: Used by Kerberos authentication to [associate a service instance with a service logon account]
            - Process: [https://www.prosec-networks.com/en/blog/adcs-privescaas/](https://www.prosec-networks.com/en/blog/adcs-privescaas/)
                - Compromise the credentials of a low-privileged AD user.
                ![](evil-winrm_access.png)
                - Use those credentials to enrol a new host on the domain.
                ![](add_computer.png)
                - Generate certificate request to added host and vulnerable template Impersonate an administrator.
                ![](generate_Certificate.png)
                - Login with certificate: [Fail] (Error support)
                ![](error_auth.png)
                - The .pfx must be converted to a .crt and to a .key:
                ![](generate_crt_key.png)
                - PassTheCert: [https://github.com/AlmondOffSec/PassTheCert/tree/main/Python](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python)
                - Ldap authentication: [Add user to administrators group]
                ![](add_user_to_administrators_group.png)

## **Lateral movement**

* * *

## **Proof of concept**

* * *
* * *