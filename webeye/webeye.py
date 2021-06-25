from .session import Session

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

	async def portscan(self, host):
		"""basic port scanner just send list of open/closed ports"""
		async with self.session() as req:
			api = await req.get(f"https://api.hackertarget.com/nmap/?q={host}")
			out = await api.text()
			await req.close()
		return out

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
