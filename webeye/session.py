import asyncio
import aiohttp
from datetime import datetime


class Session:
	"""A Session for webeye"""
	def __init__(self, loop=asyncio.get_event_loop(), session=aiohttp.ClientSession, *args, **kwargs):
		self.loop = loop
		self.run = self.loop.run_until_complete
		self.create_task = self.loop.create_task
		self.created = datetime.utcnow().replace(microsecond=0)
		self.kwargs = kwargs
		self.args = args
		self.session = session

	def __exit__(self):
		if self.session:
			try:
				self.run(self.session.close())
			except TypeError:
				pass

	def start(cls,*args,**kwargs):
		return cls(*args,**kwargs)

	def uptime(self):
		return (datetime.utcnow() - self.created).total_seconds()

	def __repr__(self):
		return f'<Session created="{self.created}">'
