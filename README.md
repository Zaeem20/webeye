# webeye
A Best Powerful module for making ethical hacking tools easier
# Getting Started
```py
from webeye import Webeye
Tools=Webeye()
run = Tools.ses.run
host="github.com"
# subdomains
subdomains=run(Tools.subenum(host=host))
# dns lookup
dns=run(Tools.dns(host=host))
# banner grabber
grabbed=run(Tools.grab(host=host))
# check for ports
ports=run(Tools.portscan(host=host))
# cloudflare
detected=run(Tools.cloudflare(host=host))
# stopping the session
Tools.__exit__()
```
