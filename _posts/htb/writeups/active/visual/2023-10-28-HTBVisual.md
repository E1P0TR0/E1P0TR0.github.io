---
title: Visual Report
date: 2023-10-28 12:00:00 pm
categories: [HTB]
tags: [HTB, Windows, Medium, Visual Studio, JuicyPotato]

img_path: /assets/img/htb/writeups/visual
---

## **Information gathering**

* * *
* * *

**Scope:** 10.10.11.234/32 (Windows)

**TCP Nmap scan:** 65,535 ports

* **Open ports**:
	* 80/http:
		* Banner grabbing
			* Server: Apache/2.4.56 (Win64)
		* Follow redirect: 
			* Service:
				* Visual Studio project compilation with Visual
					* Requirements: Git Repo (.sln: file that maintains **state information for a project** in Visual Studio)
					* Compatibility: .NET 6.0 (development platform that **allows developers to build applications for cloud, web, desktop, mobile, gaming, IoT and A**) y C#
					* Return: executable / DLL files
			* Technologies
				* Bootstrap 5.1.3 (latest: v5.3.2)
				* OpenSSL/1.1.1t (recently gone out of support)(latest: 3.1 series)
				* PHP/8.1.17 (latest: 8.2)
			* Headers
				* None
			* Cookies
				* None
			* Emails
				* None
			* Users
				* None
		* Directory Fuzzing
			* file: content/dir_fuzzing
		* Subdomains
			* None
		* [Visual Studio projects and solutions](https://learn.microsoft.com/en-us/visualstudio/ide/solutions-and-projects-in-visual-studio?view=vs-2022)
			* Solution: a container Visual Studio uses to organize one or more related projects
			* Proyect: contains all files that are compiled into an executable, library, or website (source code, icons, images, data files, compiler settings, etc)
				* MSBuild: provides an XML schema for a project file that controls how the build platform processes and builds software
					* Proyect file: XML document that contains all the information and instructions that MSBuild needs to build your project (C# project (.csproj), a Visual Basic project (.vbproj), or a database project (.dbproj))
						* Elements:
							* Properties: name-value pairs that can be used to configure builds
							* Items: inputs into the build system and typically represent files
							* Tasks: **units of executable code that MSBuild projects use to perform build operations** (\*)
								* Exec task: run specified program or command
								* [More taks](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-task-reference?view=vs-2022)
							* Targets: allow the build process to be factored into smaller units
								* Prebuild (like Macros)

## **Vulnerability Assesment**

* * *
* * *

* [MSbuild build events](https://learn.microsoft.com/en-us/visualstudio/ide/how-to-specify-build-events-csharp?view=vs-2022) (C#):
	* Visual Studio project: XML project file using "Target" element to process "[Exec](https://learn.microsoft.com/en-us/visualstudio/msbuild/exec-task?view=vs-2022)" task and execute commands
		![](visual_studio_rce_poc.png)

## **Exploitation**

* * *
* * *

* MSbuild event Process:
	1. On windows virtual Machine with Visual Studio create C# console app project
	2. Then add Target element to project file (example_name.csproj) with "Prebuild" event
	3. On Linux machine set-up local git repository (Gitea) using Docker-hub
	4. Transfer project from windows to linux (compress, etc) and initialize repository with git
	5. Pull repository to Gitea local server
	6. Send URL repository to Build web page (target)
	7. Wait a few seconds and the commad will have executed
	![](foothold.png)

## **Post-exploitation**

* * *
* * *

* Enox enumeration:
	* web server folder permissions (uploads)
		![](apache.png)
		* Upload PHP shell to gain Local service user access (www-data on linux)
* nt authority-local service enum:
	* Local Service [Recovering the **default privilege set** of a service account](https://itm4n.github.io/localservice-privileges/)
		* Enabled SeImpersonatePrivilege [https://github.com/itm4n/FullPowers](https://github.com/itm4n/FullPowers)
			* SeImpersonatePrivilege [GodPotatoe](https://github.com/BeichenDream/GodPotato)
			![](authority_system.png)