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

def scan(target: str, port: int, start: Optional[int]=0,dev_mode:bool=False):
    '''Python Port Scanner Enumerate all Open Ports of Given Host:\n
    Use dev_mode = True,  if You want response in list.
    '''
    try:
        realip = socket.gethostbyname(target)
        list = []
        on = time.time()
        def scan_port(port) -> int: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            conn = sock.connect_ex((socket.gethostbyname(realip), port))
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
                    return f'IP: {realip}'
        runner = execute()
        if dev_mode:
            return runner,list
        else:
            return runner

    except socket.gaierror:
        return 'Unable To resolve target IP'
    except socket.error:
        return f'{target} is Unreachable'
    except KeyboardInterrupt:
        return 'Process Stopped Exiting: 1'

def subenum(host: str):
    """enumerate a list of subdomains for given host"""
    try:
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}", headers={'Connection':'close'}).text
        lines = api.split("\n")
        return list(line for line in lines)
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return 'Stopped, Exiting: 1'

def grab(host: str, schema='http://') -> dict:
    '''Grab headers of a given host'''
    try:
        api = requests.get(schema+host)
        return api.headers
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return 'Stopped, Exiting: 1'

#<----- Closed Whois Lookup ---->

# def whois(host):
#     api =  requests.get(f"https://api.hackertarget.com/whois/?q={host}")
#     return api.text

def is_cloudflare(host: str, schema='http://'):
    """Check For Cloudflare in a given host"""
    try:
        target = requests.get(schema+host)
        o = target.headers
        return True if o["server"] == "cloudflare" else False
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return 'Stopped, Exiting: 1'

def fetch_dns(host: str):
    '''Start DNS lookup Of a given host'''
    try:
        api =  requests.get(f"https://api.hackertarget.com/dnslookup/?q={host}",headers={'Connection':'close'}).text
        result = api.split("\n")
        return result
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return 'Stopped, Exiting: 1'

def is_honeypot(host: str, score: bool=False):
    '''Return Probablity of Honeypot between [0.0 - 1.0] based on Shodan Honeyscore...'''
    try:
        target = socket.gethostbyname(host)
        honey = f'https://api.shodan.io/labs/honeyscore/{target}?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by'
        try:
            result = requests.get(honey).text
            if 'error' in result:
                return f'No information Available for: {target}'
        except:
            result = None
            return "Couldn't scan Host:- {}".format(target)
        if score:
            return float(result)
        else:
            return f'Honeypot Probablity: {float(result)*100}%'

    except socket.gaierror:
        return 'Unable to resolve address'
    except socket.error:
        return f'{target} is Unreachable'
    except KeyboardInterrupt:
        return 'Stopped, Exiting: 1'


