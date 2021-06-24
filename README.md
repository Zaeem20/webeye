# webeye
A Best Powerful module for making ethical hacking tools easier<br />
# Getting Started
```py
# importing
from webeye import Webeye
# configuring
Tools=Webeye()
# tool for running coroutines
run = Tools.ses.run
# host 
host="quotientbot.xyz"
# schema
schema="https://"
# subdomains
subdomains=run(Tools.subenum(host=host))
# dns lookup
dns=run(Tools.dns(host=host))
# banner grabber
grabbed=run(Tools.grab(host=host))
# check for ports
ports=run(Tools.portscan(host=host))
# cloudflare
detected=run(Tools.cloudflare(host=schema+host))
# stopping the session
Tools.__exit__()
```
# custom things

## custom Loops
```py
Tools=Webeye(loop=your_loop)
```
## custom Sessions
```py
Tools=Webeye(session=your_session)
```
# Support
Join the [support discord server here](https://discord.gg/xmu36SbCXC)
