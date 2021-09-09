import socket, time
from typing import Optional
from concurrent.futures import ThreadPoolExecutor
import requests

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

def scan(target, port: int, start: Optional[int]=0, dev_mode=False):
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

def subenum(host: str):
    """gives a list of subdomains for given host"""
    api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}", headers={'Connection':'close'}).text
    lines = api.split("\n")
    return list(line for line in lines)

def grab(host: str, schema: Optional[str]='http://') -> dict:
    '''banner grabber'''
    api = requests.get(schema+host)
    return api.headers

#<----- Closed Whois Lookup ---->

# def whois(host):
#     api =  requests.get(f"https://api.hackertarget.com/whois/?q={host}")
#     return api.text

def is_cloudflare(host, schema='http://'):
    """Checks for cloudflare"""
    target = requests.get(schema+host)
    o = target.headers
    return True if o["server"] == "cloudflare" else False

def fetch_dns(host: str):
    '''dns lookup'''
    api =  requests.get(f"https://api.hackertarget.com/dnslookup/?q={host}",headers={'Connection':'close'}).text
    result = api.split("\n")
    return result
    
def is_honeypot(host: str):
    target = socket.gethostbyname(host)
    honey = f'https://api.shodan.io/labs/honeyscore/{target}?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by'
    try:
        result = requests.get(honey, headers={'Connection':'close'}).text
    except:
        result = None
        return 'No information Available for {}'.format(target)
    return f'Honeypot Probablity: {float(result)*10}%'
