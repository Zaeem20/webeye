import asyncio
import aiohttp
from datetime import datetime
# chats
#
'''
- ha kr skta hu
- kon si IP use krna h?
- ar headers? 
- ar cookies?
- btao
- `+ your msg here` krke likho niche
- ur msg here
- chats mt mitao
+ ok
+ hm ko sir new sezsion bana na hai jab quota limit excedd hojayegi
+ ek alag hi session use krte h na
+ haa
+ 1 tool hai jo is cheez ko php me dala hua h
+ abhi tum ho na online???
+ saare return statement hata du session created and close ye sab backend me hona chahiy
- requests use karo aiohttp ki jaga 

'''


class Session:
	"""A Session for webeye"""
	def __init__(self, loop=None, session=None, *args, **kwargs):
		self.loop = loop or asyncio.get_event_loop()
		self.run = self.loop.run_until_complete
		self.create_task = self.loop.create_task
		self.created = datetime.utcnow().replace(microsecond=0)
		self.kwargs = kwargs
		self.args = args
		self.session = session or aiohttp.ClientSession()

	def __exit__(self):
		if self.session:
			self.run(self.session.close())

	def start(cls):
		return cls()

	def uptime(self):
		return (datetime.utcnow() - self.created).total_seconds()

	def __repr__(self):
		return f'<Session created="{self.created}">'
