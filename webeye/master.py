from .session import Session

Session = Session.start(Session)
__all__ = [
    "subenum", "dns", "whois", "grab", "portscan", "cloudflare", "Session"
]


async def subenum(host: str):
	"""gives a list of subdomains for given host"""
	async with Session.session as req:
		api = await req.get(
		    f"https://api.hackertarget.com/hostsearch/?q={host}")
		out = await api.text()
	line = out.split("\n")
	get = []
	for new in line:
		get.append(new.split(',')[0])
	return get


async def portscan(host):
	"""basic port scanner just send list of open/closed ports"""
	async with Session.session as req:
		api = await req.get(f"https://api.hackertarget.com/nmap/?q={host}")
		out = await api.text()
	return out


async def grab(host):
	'''banner grabber'''
	req = Session.session
	api = await req.get(host)
	return api.headers


async def whois(host):
	req = Session.session
	api = await req.get(f"https://api.hackertarget.com/whois/?q={host}")
	return await api.text()


async def cloudflare(host):
	"""Checks for cloudflare"""
	async with Session.session as req:
		api = await req.get(host)
		o = api.headers
	if o['server'] == 'cloudflare':
		return "Cloudflare Detected"
	else:
		return 'Not detected'


async def dns(host):
	'''dns lookup'''
	async with Session.session as req:
		api = await req.get(f"https://api.hackertarget.com/dnslookup/?q={host}"
		                    )
		o = []
		o.append(await api.text())
	return o
