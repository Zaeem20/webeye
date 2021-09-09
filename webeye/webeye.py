import socket, time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
from .session import Session

'''
MIT License
Copyright (c) 2021 Zaeem Technical
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''


__all__ = ["Webeye"]


class Webeye:
	"""Main tools of webeye"""
	def __init__(self, *args, **kwargs):
		self.ses = Session(*args, **kwargs)
		self.session = self.ses.session
		self.__exit__ = self.ses.__exit__
		self.args = args
		self.kwargs = kwargs

	async def subenum(self, host: str):
		"""gives a list of subdomains for given host"""
		async with self.session() as req:
			api = await req.get(
			    f"https://api.hackertarget.com/hostsearch/?q={host}")
			out = await api.text()
			await req.close()
		lines = out.split("\n")
		return list(line for line in lines)

    def scan(self, target, port: int, start: Optional[int]=0, dev_mode: Optional[bool]=False):
        list = []
        on = time.time()
        def scan_port(port) -> int: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            conn = sock.connect_ex((socket.gethostbyname(target), port))
            if not conn:
                if dev_mode:
                    list.append(f'{port}/{socket.getservbyport(port)}')
                else:
                    print(f'OPEN_STATE: {port}/{socket.getservbyport(port)}')
            sock.close()
        def execute():
            with ThreadPoolExecutor(max_workers=1000) as host:
                host.map(scan_port, range(start, port))
                if not dev_mode:
                    return f'\nScan done: 1 IP address (1 host up) scanned in {round(time.time()-on, 2)} seconds'
                else:
                    return f'IP: {socket.gethostbyname(target)}'
        runner = execute()
        if dev_mode:
            return runner,list
        else:
            return runner
		
		
	async def grab(self, host):
		'''banner grabber'''
		req = self.session()
		api = await req.get(host)
		await req.close()
		return api.headers

	async def whois(self, host):
		req = self.session()
		api = await req.get(f"https://api.hackertarget.com/whois/?q={host}")
		await req.close()
		return await api.text()

	async def cloudflare(self, host):
		"""Checks for cloudflare"""
		async with self.session() as req:
			api = await req.get(host)
			o = api.headers
			await req.close()
		return True if o["server"] == "cloudflare" else False

	async def dns(self, host):
		'''dns lookup'''
		async with self.session() as req:
			api = await req.get(
			    f"https://api.hackertarget.com/dnslookup/?q={host}")
			o = []
			await req.close()
			o.append(await api.text())
		return o
