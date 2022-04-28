---
title: Hackthebox Writeup Timelapse
date: 2022-04-11 03:34:47 am
categories: [HTB, Writeups]
tags: [HTB, Windows, Easy, Active Directory, SMB, Brute Force, SSL/TLS, WinPEAS, LAPS]

img_path: /assets/img/htb/writeups/timelapse/
---

Máquina Windows donde enumeramos por el protocolo **SMB (Server Message Block)** un archivo backup .zip protegido por contraseña, al romperlo por **Brute Force** obtenemos otro archivo **.pfx (Personal Information Exchange)** protegido por contraseña que rompemos fácilmente. Del archivo extraemos con **OpenSSL** certificados digitales del protocolo **SSL/TLS (Secure Socket Layer/Transport Layer Security)** de un usuario para luego entrar con **evil-winrm** y completar la escalada. Ahora para obtener privilegios con la herramienta **WinPEAS** enumeramos un archivo .txt con un historial de comandos que nos permite extraer credenciales de un usuario que pertenece a un grupo del servicio **LAPS**, el cuál le concede acceso a un archivo en texto claro con las credenciales del administrador del sistema.

* * *

![Timelapse](logo.png)

|   OS  |      IP      | Release Date | Difficulty | Points |
|:-----:|:------------:|:------------:|:----------:|:------:|
|Windows| 10.10.11.152 |  26 Mar 2022 |    Easy    |   20   |

Antes de empezar es importante verificar que estamos conectados a la **VPN** de _HackTheBox_ y tenemos conexión con la máquina, para ello usamos el comando `ping`:

![Ping](ping.png){: .shadow }

> Observamos que enviamos un paquete `_1 packets transmitted_` y lo recibimos `_1 received_`, por ende tenemos una conexión exitosa.
{: .prompt-tip}

## Enumeration

* * *

Empezamos enumerando los puertos TCP que están abiertos en la máquina víctima, para ello usamos la herramienta `nmap`:

![Nmap](open_ports_tcp.png){: .shadow}

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
> -n : No buscar nombres de dominio asociadas a la IP en cuestión (rDNS)
>
> -oG \<file\> : Guardar output en un archivo (\<file\>) de formato _grepable_
>
> Agregado :
>
> 2> /dev/null : Redirigir _stderr_ (mensajes de error) al archivo /dev/null ("Agujero Negro")

Como estamos en una instancia `Windows` observamos varios puertos abiertos, para tener un poco más de información realizamos un escaneo a cada uno en específico:

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

A primera vista y observando los puertos podemos deducir que estamos frente a un servicio `Active Directory`, viendo el puerto `445` *(SMB)* podemos tirar de la herramienta `crackmapexec` para confirmarlo:

![Crackmapexec](validate_ac.png){: .shadow }

> Observamos en la información del equipo por el protocolo **SMB** que el Hostname es `DC01` (Domain Controller), el cúal es un concepto asociado a `Active Directory`

![DC\_Concept](dc_and_ad.png){: .shadow }

Ya que el puerto `445` (SMB) está abierto, usamos la herramienta `smbmap` para listar recursos compartidos Samba y descargar un archivo `.zip` con interesante nombre:

![Extract\_Zip](extract_zip.png){: .shadow }

> Ojito: También observamos un archivo `.msi` y documentos `.docx` con la palabra `LAPS`, el cúal es un concepto muy importante que lo veremos más adelante . . .
{: .prompt-tip}

## Foothold

* * *

Al intentar extraer el archivo `.zip` notamos que está protegido con contraseña, para ello usamos `zip2john` para generar un hash del archivo protegido y luego crackearlo con `john`:

![Cracked\_Zip](cracked_zip.png){: .shadow }

Después de extraer el archivo `zip` nos encontramos con un archivo `legacyy_dev_auth.pfx`, para conocer un poco de la extensión investigamos un poco:

![Meaning\_Pfx](meaning_pfx.png){: .shadow }

Con el conocimiento de que el archivo contiene certificados digitales **(SSL, Private keys)** para procesos de autenticación _(el nombre del archivo tiene muchas pistas)_, ahora solo toca buscar una manera de extraer esos certificados.

Para ello, usamos la herramienta `openssl` que está ligada a realizar funciones de criptografía con cifrado SSL **(Secure Sock Layer)**:

![Invalid\password](invalid_pass.png){: .shadow }

Gracias la investigación de este nuevo concepto, sabemos que el archivo contiene una `private key` y por ello una protección por contraseña.

A pesar de ello, aplicamos el mismo método que usamos con el archivo `.zip`, usamos `pfx2john` para generar un hash del archivo protegido y luego crackearlo con `john`:

![Cracked\_Pfx](cracked_pfx.png){: .shadow }

Ahora solo queda extraer los cetificados con `openssl`:

![Extract\_Pfx](extract_pfx.png){: .shadow }

> Explicación de parámetros :
{: .prompt-info}

> pkcs12 : Especificar el formato de la data con la cúal trabajaremos
>
> -in \<file\> : Especificar el archivo (\<file\>) del cuál queremos extraer el certificado y la llave privada
>
> -nocerts : No extraer certificados
>
> -clcerts : Extraer solo certificados de cliente
>
> -nokeys : No extraer llaves privadas
>
> -out \<file\> : Especificar archivo de salida (\<file\>)

Para más información del proceso pueden visitar la siguiente página de **IBM**: [https://www.ibm.com/docs/en/arl/9.7?topic=configurations-ssl-certification](https://www.ibm.com/docs/en/arl/9.7?topic=certification-extracting-certificate-keys-from-pfx-file#r_extratsslcert__keypwd)

Disponemos de un certificado y una llave privada, pero aún no sabemos a quién pertenece.

> Ojito : Desde que descubrimos el archivo .zip tuvimos varias pistas en la descripción de sus nombres: `winrm`\_backup.zip -> `legacyy`\_dev\_auth.pfx
{: .prompt-tip}

Aparte de eso, al mirar el certificado extraído observamos en el campo **Subject** como CN _(Common Name)_ y como Issuer _(Emisor)_ a `legacyy`.

Ahora sí, para asegurarnos del todo investigamos en internet y encontramos con el tipo de certificado `X.509` que proporciona un campo de extensión para añadir campos adicionales al certificado:

![Certificate\_Info](certificate_info.png){: .shadow }

Para más información sobre [Atributos del Certificado](https://docs.oracle.com/cd/E24191_01/common/tutorials/authz_cert_attributes.html)

Con toda la información segura y las pistas, ahora podemos usar la herramienta `evil-winrm` para entrar como el usuario `legacyy` usando el certificado y la llave privada para la autenticación y pa-dentro:

![Foothold](foothold.png){: .shadow }

> Explicación de parámetros:
{: .prompt-info}

> -i \<ip\> : Ip o nombre de host remoto para la conexión
>
> -S : Aplicar protocolo SSL (Secure Socket Layer)
>
> -u \<user\> : Asignar usuario para la autenticación
>
> -c \<certificate\> : Asignar certificado de llave pública
>
> -k \<private key\> : Asignar certificado de llave privada

## Privilege Scalation

* * *

Estamos dentro del sistema como usuerio `legacyy`, ahora usamos la herramienta conocida [winPEAS](https://github.com/carlospolop/PEASS-ng) que nos ayuda a enumerar diversas rutas para poder escalar privilegios. Al ejecutarla encontramos la ruta del `.txt` que guarda el **_historial de Powershell_**:

![PS\_History](ps_history.png){: .shadow }

> Importante! : Para que les permita subir el archivo de nuestra máquina local a la víctima es importante que nos ubiquemos en un [Writeable path](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md) **(rutas por defecto con permisos de escritura para usuarios normales)**
{: .prompt-warning}

Al abrir el archivo encontramos cierta ejecución de comandos con el propósito de iniciar una sesión de cierto usuario para poder ejecutar algún comando:

![Host\_Hisyory](host_history.png){: .shadow }

> Para no tirar siempre de WinPEAS, puedes investigar sobre otras posibles rutas para escalar privilegios en el repositorio [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md)
{: .prompt-tip}

> Aquí puedes tener mayor información sobre la [Creación del objeto de credenciales](https://docs.microsoft.com/en-us/powershell/scripting/learn/deep-dives/add-credentials-to-powershell-functions?view=powershell-7.2) para la sesión
{: .prompt-info}

Ahora que tenemos credenciales del usuario `svc_deploy` solo queda logearnos de nuevo con `evil-winrm`:

![SVC\_Login](svc_login.png){: shadow }

Empezamos con una enumeración básica del usuario actual y encontramos que pertenece al grupo `LAPS_Readers`:

![Laps\_Group](laps_group.png){: .shadow }

¿ Recuerdan los archivos de la enumeración por **SMB** ?, con está información ya estamos completamente seguros que se está aplicando `LAPS` **(Local Administrator Password Solution)**

Investigando en internet sobre esta solución encontramos una vulnerabilidad que permite _visualizar las contraseñas en texto claro de **administradores locales del dominio**_:

![Laps\_Vuln](laps_vuln.png){: .shadow }

> Puede visitar la siguiente página con más vulnerabilidades LAPS: [https://www.attivonetworks.com/blogs/laps-vulnerability-assessment](https://www.attivonetworks.com/blogs/laps-vulnerability-assessment/)
{: .prompt-info}

Asociando estos conceptos con el grupo al que pertenece nuestro usuario actual, estamos listos para explotar esta vulnerabilidad.

Primero verificamos que `LAPS` se encuentre en el sistema para luego ejecutar una linea de comandos extraída de [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#reading-laps-password), y ya que pertenecemos al grupo `LAPS_Readers`, está claro que podremos visualizar las credenciales en texto claro:

![Admin\_Pass](admin_pass.png){: .shadow }

Con las credenciales del usuario `Administrator` solo queda volvernos a logear por `evil-winrm` y pa-dentro:

![Priv\_Scalation](priv_scalation.png){: .shadow }

* * *
