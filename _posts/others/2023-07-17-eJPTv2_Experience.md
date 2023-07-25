---
title: eJPTv2 Certification
date: 2023-07-17 11:04:11 pm
categories: [OTHERS]
tags: [eJPTv2]

img_path: /assets/img/others
---

# Mi experiencia sobre el eJPTv2 _¿Es tan sencilla como dicen?_

* * *

Después de adquirir el voucher del exámen en [INE](https://ine.com/learning/certifications/internal/elearnsecurity-junior-penetration-tester-cert) que contenía el nuevo curso de preparación [Penetration Testing Student](https://my.ine.com/CyberSecurity/learning-paths/61f88d91-79ff-4d8f-af68-873883dbbd8c/penetration-testing-student) y 2 intentos para dar dar el exámen, **logré aprobar el eJPTv2**, aquí les cuento mi experiencia...

![](ejptv2_certificate.png){:. shadow}

[Certification Link](https://my.ine.com/certificate/dd953c07-d0fc-48cd-ad2c-048506f1e40b)

## Preparación previa

* * *

Empecé en el mundo de la ciberseguridad hace un año y pocos meses. Como la mayoría, empecé googleando: _"¿Como empezar en el campo...?"_ hasta llegar a videos de YouTuBe sobre como usar **Linux** y montar un **entorno virtualizado** para empezar en el pentesting/hacking. Luego inicié resolviendo máquinas de la plataforma **HackTheBox** y algunas de **TryHackMe**, despues en paralelo entré un poco al campo de Redes haciendo parte de un curso del **CCNA**. Poco a poco fui aprendiendo cosas nuevas y a sentirme más cómodo, y para almacenar mis conocimientos creé este blog con diversos writeups y mucho python 🐍.

Me decidí a inicio de año comprar el voucher y use como excusa el **plazo de 6 meses** que dan para dar el exámen. Además, el voucher tenía **3 meses de suscripción para acceder a los cursos de INE**, el cuál lo use para completar el **Penetration Testing Student** que me sirvió para fortalecer y aprender nuevos conceptos.

## PTS (Penetration Testing Student)

* * *
El curso tiene un total de 140 horas aproximadamente, se divide en 4 secciones correspondientes al exámen (todo esto ya lo analizan con calma en la página oficial). Con respecto al contenido:

1. Me gustaron los conceptos, pero los **dividian en muchas diapositivas y videos** lo cuál lo hacia tedioso para repasarlo.
2. Por parte de los exponentes del curso, hubo uno que no me contagiaba esa energía de aprender y **explicaba sin ganas**.
3. También lo vi muy innecesario una sección de **muchas horas sobre como aprender a usar el framework Metasploit**, ya que claramente puedes explicarlo en un video y algunas diapositivas.
4. **La repetición de ciertos temas**, un arma de doble filo. Estaba bueno para reforzar pero los repetian en distintas secciones y llegaba a confundir.
5. Sobre los laboratorios para practicar, lo de siempre, son poco comodos y accesibles. Lo bueno es que los **laboratorios de práctica se asimilan muy bien a la prueba**.

En general sí recomandaría el curso a personas que tengan algunos conceptos sobre linux y sepan usarlo de manera básica pero sin mucha experiencia en la parte del pentesting. Si ya hicieron máquinas de **HTB** o **THM** no se molesten en cursarlo, les irá bien!.

## Preparación Post PTS

* * *

Con los 3 meses que me quedaban decidí buscar mas recursos sobre el exámen y los que más destacaría serían estos dos:

1. [Wreath TryHackMe](https://tryhackme.com/room/wreath): Un laboratorio en una red con 3 dispositivos donde deberás explotarlas y realizar pivoting. Solo ignoraría la sección de _Command and Control_.

2. [Entorno propio de máquinas simulando el eJPT](https://www.youtube.com/watch?v=7cjdjGsXNIQ): En el video realiza metodologías útiles para el proceso del exámen y explotación de máquinas pero por separado. Por ello te recomiendo montarlas en un entorno en **VirtualBox**/**VMWare** muy parecido el laboratorio "Wreath" (no temas que configurarlas es cosa de algunos clicks). Aquí te dejo el blog con las máquinas que usa [https://systemweakness.com/ejptv2-review-280ff93d90a2](https://systemweakness.com/ejptv2-review-280ff93d90a2).

## Día del exámen

* * *

El exámen consta de **35 preguntas** y **48 horas**, por ello es recomendable empezar al **medio dia** para así tener toda esa tarde, todo el proximo día y la mañana del siguiente, diría que es la mejor estratégia. En mi caso me tomé aproximadamente unas 6 a 7 horas en terminar el exámen. Estaba bastante entusiasmado y con ganas de ya acabar todo, lo cuál **no recomiendo para nada apurarse tanto**. Ni bien termines sabrás si aprobaste.

## Recomendaciones

* * *

1. La mejor recomendación que te voy a dar es que **ni bien inicies el exámen ignores las preguntas y empieces a escanear tu red y explotar todas las máquinas**. Tomalo como si estuvieras en una auditoría, y no preocupes por el tiempo que irás de sobra y al final las preguntas se resolverán solas. Además, estoy muy seguro que mas importante es explotar todo primero de manera correcta y con tu reporte final en mano lograrás el puntaje máximo.

2. Elige una buena aplicación para tomar notas de manera ordenada y organizada. Yo use **SublimeText** por temas de simplicidad y que estaba en **Windows**. **Notion** y **CherryTree** tambien son buenas alternativas.

3. Es normal que tengas nervios y no te sientas seguro, confia sin miedo y juegatela. El exámen es mas sencillo de lo que crees.

4. Prioriza una buena conexión a internet. No olvides que te proporcionarán un entorno con todas las herramientas necesarias via la página web.

5. No tengamos la idea que usa **Metasploit** es malo. La mejor estrategia es saber juntar tu metodología manual con cualquier herramienta que automatiza algunos procesos.

**No olvidemos que lo mas importante es la experiencia de estar en una auditoria real, disfrutalo!**
