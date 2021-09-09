# webeye
A Best Powerful module for making ethical hacking tools easier<br />

# Installation
```sh
pip install -U webeye
```
# Getting Started
```py
# importing
from webeye import *
# host 
host="quotientbot.xyz"
# schema
schema="https://"
# subdomains
subdomains=subenum(host=host)
# dns lookup
dns=fetch_dns(host=host)
# banner grabber
grabbed=grab(host=host,schema=schema)
# check for ports
ports=scan(host=host, end=500, start=0, dev_mode = False)
# cloudflare
detected=is_cloudflare(host=host, schema=schema)
# honeypot
honeypot=is_honeypot(host=host)

```


# Support
Join the support [discord server here](https://discord.gg/xmu36SbCXC)
