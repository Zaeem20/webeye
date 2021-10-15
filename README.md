# Webeye
A Powerful Library for making ethical-hacking/pen-testing tools<br />
At your Fingertips, just in 3-5 lines of code...

## Features

• Subdomain Enumerator<br />
• Port scanner<br />
• ReverseDNS Lookup<br />
• ReversIP Lookup<br />
• Banner Grabber<br />
• Cloudflare Detector<br />
• Honeypot Detector (Based on Honeyscore)<br />
• Pagelinks Extractor<br />
• Shared DNS Scanner<br />
• DNS Lookup<br />
• Whois Lookup <br />
• Geo-IP Lookup<br />

## Installation
```sh
pip install -U webeye
```
## Getting Started
```py
# importing
from webeye.core import *
# host 
host="google.com"
# schema
schema="https://"
# subdomains
subdomains=subenum(host=host)
# dns lookup
dns=fetch_dns(host=host)
# banner grabber
grabbed=grab(host=host,schema=schema)
# check for ports
ports=scan(host=host, port=1025, start=0, dev_mode = False)
# cloudflare
detected=is_cloudflare(host=host, schema=schema)
# honeypot
honeypot=is_honeypot(host=host)

```

## Custom Things
You can also scan specific ports, Iterable type args can also be added...</br>

```py
webeye.scan('google.com', [21,80,443])

```

You can get IP address of subdomain too...

```py
print(webeye.subenum(target, no_ip=False))

```
## Webeye as Asynchronous

```py
from webeye import AsyncHelper

asyncmanner = AsyncHelper()

async def portscan(target):
    await asyncmanner.scan(target, 1024)

async def reversedns(target):
    await asyncmanner.reversedns(target)

async def whois(target):
    await asyncmanner.whois(target)

async def extract_pagelink(target):
    await asyncmanner.extract_pagelink(target)

async def shared_dns(target):
    await asyncmanner.fetch_shared_dns(target)

async def bannergrabber(target):
    await asyncmanner.grab(target)

async def geoip(target):
    await asyncmanner.geoip(target)

async def find_subdomains(target):
    await asyncmanner.find_subdomains(target)

async def dnslook(target):
    await asyncmanner.fetch_dns(target)

async def reversiplook(target):
    await asyncmanner.reverseip(target)

async def is_cloudflare(target):
    await asyncmanner.is_cloudflare(target)

async def is_honeypot(target):
    await asyncmanner.is_honeypot(target)

```

## Webeye as CLI

![image](https://user-images.githubusercontent.com/60778335/137212470-c0326195-5fc5-4112-8587-1dbb09e3c0b9.png)

## Support
• **[Discord](https://discord.gg/xmu36SbCXC)**
