import socket
import time
import sys
import httpx
import requests
import json as _json
from httpx import AsyncClient
from datetime import datetime
import mechanize
from bs4 import BeautifulSoup
from collections.abc import Iterable
from typing import Union
from concurrent.futures import ThreadPoolExecutor

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


def extract_pagelinks(host: str, cli=False) -> Union[list, None]:
    '''Extract All Pagelinks From Website'''
    api = requests.get(f'https://api.hackertarget.com/pagelinks/?q={host}').text.split('\n')
    api.remove('')
    if cli:
        for count, result in enumerate(api, start=1):
            print(f'{count}). {result}')
    else:
        return api

def fetch_shared_dns(host: str, cli=False) -> Union[list,None]:
    '''Find Shared DNS Server from Website'''
    api = requests.get(f'https://api.hackertarget.com/findshareddns/?q={host}').text.split('\n')
    if cli:
        for count, result in enumerate(api, start=1):
            print(f'{count}). {result}')
    else:
        return api

def reversedns(host: str) -> str:
    '''Reverse DNS Lookup'''
    realip = socket.gethostbyname(host)
    api =  requests.get(f'https://api.hackertarget.com/reversedns/?q={realip}').text.strip(f'{realip} ')
    return api

def scan(target: str, port: Union[int, Iterable], start: int=0, dev_mode: bool=False, api :bool=False) -> Union[tuple,None]:
    '''Python Port Scanner Enumerate all Open Ports of Given Host:\n
    Use dev_mode = True,  if You want response in list.\n
    Use API = True if you are making api
    '''
    try:
        realip = socket.gethostbyname(target)
        lists = [f'\nPyPort started at {datetime.utcnow().strftime("%d-%b-%Y %I:%M %p")}<br/>','PORTS   |   SERVICE']
        on = time.time()
        def scan_port(port) -> Union[str,list]: 
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            conn = sock.connect_ex((socket.gethostbyname(realip), port))
            if not conn:
                if dev_mode:
                    lists.append(f'{port}/{socket.getservbyport(port)}')
                elif api:
                    lists.append(f'{port}/tcp | {socket.getservbyport(port)}')
                else:
                    print(f'{port}/tcp\t |   {socket.getservbyport(port)}\t|   open   |')
            sock.close()

        def execute():
            with ThreadPoolExecutor(max_workers=10000) as host:
                if isinstance(port, Iterable):
                    host.map(scan_port, port)
                    return 'Scan Finished.'
                else:
                    host.map(scan_port, range(start, port))
                if not dev_mode and not api:
                    return f'\nScan done: 1 IP address (1 host up) scanned at rate {round(time.time()-on, 2)}s/port.'
                else:
                    return f'IP: {realip}'
        runner = execute()

        if dev_mode:
            return runner,lists[2:]
        elif api:
            return runner, lists
        else:
            return runner

    except socket.gaierror:
        return 'Unable To resolve target IP'
    except socket.error:
        return f'{target} is Unreachable'
    except KeyboardInterrupt:
        return sys.exit('Process Stopped Exiting: 1')

def subenum(host: str, cli=False, no_ip=True) -> Union[list, None]:
    """Enumerate a list of subdomains for given host Asynchronously"""
    try:
        api = requests.get(f"https://api.hackertarget.com/hostsearch/?q={host}")
        lines = api.text.split("\n")
        if '' in lines:
            lines.remove('')
        if cli:
            cliresponse = []
            for x in lines:
                if no_ip:
                    cliresponse.append(x.split(',')[0])
                else:
                    cliresponse.append(x.split(','))
            for i,v in enumerate(cliresponse, start=1):
                if no_ip:
                    print(f'{i}). {v}')
                else:
                    print(f"{v[0].ljust(60,' ')} | {v[1].rjust(40,' ')}  << ({i})")
        else:
            return list(line.split(',')[0] for line in lines)
    except requests.ConnectionError:
        return 'Connection Lost: Retry Again'
    except requests.ConnectTimeout:
        return 'Taking too long! Exiting: 1'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

def reverseip(host: str, cli=False) -> Union[str, None]:
    '''Reverse IP Lookup For Gievn Host'''
    realip = socket.gethostbyname(host)
    api = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={realip}",headers={'Connection':'close'}).text
    if cli:
        result = api.split("\n")
        for x,y in enumerate(result, start=1):
            print(f'{x}). {y}')
    else:
        return api

def grab(host: str, schema='http://', cli=False) -> Union[dict, None]:
    '''Grab headers of a given host (Banner Grabbing)'''
    try:
        api = requests.get(schema+host)
        if cli:
            for x,y in api.headers.items():
                print(f'{x}: {y}')
        else:
            return dict(api.headers)
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

def whois(target: str) -> str:
    """ Whois Lookup for a Given Host """
    browser = mechanize.Browser()
    url = 'https://www.ipvoid.com/whois/'
    browser.open(url)
    browser.select_form(nr=0)
    browser['host']=target
    response = browser.submit().read()
    # Scraping Content
    soup = BeautifulSoup(response, 'html.parser')
    result = soup.find('textarea').get_text()
    return result

def geoip(host: str, cli=False) -> Union[dict, None]:
    realip = socket.gethostbyname(host)
    api= requests.get(f'http://ip-api.com/json/{realip}?fields=66846715').json()
    if not cli:
        return api
    else:
        a = 0
        for x,y in api.items():
            a+=1
            print(f'{a}). {x}: {y}')


def is_cloudflare(host: str, schema='http://', cli=False) -> Union[bool, None]:
    '''Check For Cloudflare in a given host'''
    try:
        target = requests.get(schema+host)
        o = target.headers
        if o["server"] == "cloudflare":
            if cli:
                print('Cloudflare Detected on: {}'.format(host));return
            return True
        else:
            if cli:
                print('Cloudflare Not Detected on: {}'.format(host));return
            return False
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

def fetch_dns(host: str, cli=False) -> Union[None, list]:
    '''Start DNS lookup Of a given host'''
    try:
        api =  requests.get(f"https://api.hackertarget.com/dnslookup/?q={host}",headers={'Connection':'close'}).text
        if cli:
            print(api)
        else:
            result = api.split("\n")
            return result
    except requests.ConnectionError:
        return 'Connection Lost: Exiting...'
    except requests.ConnectTimeout:
        return 'Unable to Get Response'
    except KeyboardInterrupt:
        return sys.exit('Stopped, Exiting: 1')

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
        return sys.exit('Stopped, Exiting: 1')


# Async helper
class AsyncHelper:
    '''
    With AsyncHelper you can get response Asynchronously...
    '''
    async def extract_pagelinks(self, host: str, cli=False) -> Union[None, list]:
        '''Extract All Pagelinks From Website Asynchronously'''
        async with AsyncClient() as session:
            api = await session.get(f'https://api.hackertarget.com/pagelinks/?q={host}')
            resp = api.text.split('\n')
            resp.remove('')
            if cli:
                for count, result in enumerate(resp, start=1):
                    print(f'{count}). {result}')
            else:
                return resp

    async def fetch_shared_dns(self, host: str, cli=False) -> Union[None, list]:
        '''Find Shared DNS Server from Website Asynchronously'''
        async with AsyncClient() as session:
            api = await session.get(f'https://api.hackertarget.com/findshareddns/?q={host}')
            response = api.text.split('\n')
            if cli:
                for count, result in enumerate(response, start=1):
                    print(f'{count}). {result}')
            else:
                return response

    async def reversedns(self, hostip: str) -> str:
        '''Asynchronous Reverse DNS Lookup'''
        async with AsyncClient() as session:
            realip = socket.gethostbyname(hostip)
            if hostip == realip:
                api =  await session.get(f'https://api.hackertarget.com/reversedns/?q={realip}')
                response = api.text.strip(f'{realip} ')
                return response
            else:
                return 'Enter IP of Host not URL'

    async def scan(self, target: str, port: Union[int, Iterable], start: int=0, dev_mode: bool=False, api :bool=False) -> Union[list, None]:
        '''Asynchronous Python Port Scanner Enumerate all Open Ports of Given Host:\n
        Use dev_mode = True,  if You want response in list.\n
        Use API = True if you are making api
        '''
        try:
            on = time.time()
            realip = socket.gethostbyname(target)
            lists = [f'\nPyPort started at {datetime.utcnow().strftime("%d-%b-%Y %I:%M %p")}<br/>']      
            def scan_port(port) -> Union[None,list]: 
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                conn = sock.connect((realip, port))
                if not conn:
                    if dev_mode:
                        lists.append(f'{port}/{socket.getservbyport(port)}')
                    elif api:
                        lists.append(f'OPEN_PORTS | {port}tcp/{socket.getservbyport(port)}')
                    else:
                        print(f'{port}/tcp\t |   {socket.getservbyport(port)}\t|   open   |')
                sock.close()

            async def execute():
                with ThreadPoolExecutor(max_workers=10000) as host:
                    if isinstance(port, Iterable):
                        host.map(scan_port, port)
                        return 'Scan Finished.'
                    else:
                        host.map(scan_port, range(start, port))
                    if not dev_mode and not api:
                        return f'\nScan done: 1 IP address (1 host up) scanned at rate {round(time.time()-on, 2)}s/port.'
                    else:
                        return f'IP: {realip}'

            runner = await execute()

            if dev_mode:
                return runner, lists[1:]
            elif api:
                return runner, lists
            else:
                return runner

        except socket.gaierror:
            return 'Unable To resolve target IP'
        except socket.error:
            return f'{target} is Unreachable'
        except KeyboardInterrupt:
            return sys.exit('Process Stopped Exiting: 1')

    async def find_subdomains(self,host: str, cli=False, no_ip=True) -> Union[list, None]:
        """Enumerate a list of subdomains for given host Asynchronously"""
        try:
            async with AsyncClient() as session:
                api = await session.get(f"https://api.hackertarget.com/hostsearch/?q={host}")
                lines = api.text.split("\n")
                if cli:
                    cliresponse = []
                    for x in lines:
                        if no_ip:
                            cliresponse.append(x.split(',')[0])
                        else:
                            cliresponse.append(x.split(','))
                    for i,v in enumerate(cliresponse, start=1):
                        if no_ip:
                            print(f'{i}). {v}')
                        else:
                            print(f"{v[0].ljust(60,' ')} | {v[1].rjust(40,' ')}  << ({i})")
                else:
                    return list(line.split(',')[0] for line in lines)
        except httpx.ConnectError:
            return 'Connection Lost: Retry Again'
        except httpx.ConnectTimeout:
            return 'Taking too long! Exiting: 1'
        except KeyboardInterrupt:
            return sys.exit('Stopped, Exiting: 1')

    async def reverseip(self, host: str, cli=False) -> Union[list, None]:
        '''Reverse IP Lookup For Given Host in Asynchronous manner'''
        try:
            async with AsyncClient() as session:
                realip = socket.gethostbyname(host)
                api = await session.get(f"https://api.hackertarget.com/reverseiplookup/?q={realip}",headers={'Connection':'close'})
                response = api.text.split("\n")
                if cli:
                    for x,y in enumerate(response, start=1):
                        print(f'{x}). {y}')
                else:
                    return response
        except httpx.ConnectTimeout:
            return 'Unable to get response'
        except httpx.ConnectError:
            return 'Connection Lost: Retry Again'

    async def grab(host: str, schema='http://', cli=False, json :bool=False, indent: int=2) -> Union[dict, None]:
        '''Grab headers of a given host (Banner Grabbing) Asynchronously'''
        try:
            async with AsyncClient() as session:
                api = await session.get(schema+host)
                result = api.headers
                if cli:
                    for x,y in result.items():
                        print(f'{x}: {y}')
                else:
                    if json:
                        return _json.dumps(dict(result), indent=indent)
                    else:
                        return dict(result)
        except httpx.ConnectError:
            return 'Connection Lost: Exiting...'
        except httpx.ConnectTimeout:
            return 'Unable to Get Response'
        except KeyboardInterrupt:
            return 'Stopped, Exiting: 1'

    async def whois(target: str) -> str:
        try:
            browser = mechanize.Browser()
            url = 'https://www.ipvoid.com/whois/'
            browser.open(url)
            browser.select_form(nr=0)
            browser['host']=target
            response = browser.submit().read()
            # Scraping Content
            soup = BeautifulSoup(response, 'html.parser')
            result = soup.find('textarea').get_text()
            return result
        except Exception as e:
            print(e)

    async def geoip(self, host: str, cli=False) -> Union[dict, None]:
        '''Asynchronous GeoLocation Enumerator of given host'''
        try:
            async with AsyncClient() as session:
                realip = socket.gethostbyname(host)
                api= await session.get(f'http://ip-api.com/json/{realip}?fields=66846715')
                result = api.json()
                if not cli:
                    return result
                else:
                    a = 0
                    for x,y in result.items():
                        a+=1
                        print(f'{a}). {x}: {y}')
        except httpx.ConnectError:
            return 'Connection Lost: Retry Again'
        except socket.gaierror:
            return 'Unable To Resolve host IP'
        except socket.error:
            return 'Something Went Wrong!!!'

    async def is_cloudflare(self, host: str, schema='http://', cli=False) -> Union[bool, None]:
        '''Check For Cloudflare in a given host asynchronously'''
        try:
            async with AsyncClient() as session:
                target = await session.get(schema+host)
                o = dict(target.headers)
                if o["server"] == "cloudflare":
                    if cli:
                        print('Cloudflare Detected on: {}'.format(host));return
                    return True
                else:
                    if cli:
                        print('Cloudflare Not Detected on: {}'.format(host));return
                    return False
        except httpx.ConnectError:
            return 'Connection Lost: Exiting...'
        except httpx.ConnectTimeout:
            return 'Unable to Get Response'
        except KeyboardInterrupt:
            return sys.exit('Stopped, Exiting: 1')


    async def fetch_dns(self, host: str, cli=False) -> Union[None, list]:
        '''Start DNS lookup Of a given host'''
        try:
            async with AsyncClient() as session:
                api = await session.get(f"https://api.hackertarget.com/dnslookup/?q={host}",headers={'Connection':'close'})
                resp = api.text
                if cli:
                    print(resp)
                else:
                    result = resp.split("\n")
                    return result
        except httpx.ConnectError:
            return 'Connection Lost: Exiting...'
        except httpx.ConnectTimeout:
            return 'Unable to Get Response'
        except KeyboardInterrupt:
            return sys.exit('Stopped, Exiting: 1')


    async def is_honeypot(self, host: str, score: bool=False) -> Union[float, None]:
        '''Return Probablity of Honeypot between [0.0 - 1.0] based on Shodan Honeyscore...'''
        try:
            async with AsyncClient() as session:
                target = socket.gethostbyname(host)
                honey = f'https://api.shodan.io/labs/honeyscore/{target}?key=C23OXE0bVMrul2YeqcL7zxb6jZ4pj2by'
                try:
                    result = await session.get(honey)
                    if 'error' in result.text:
                        return f'No information Available for: {target}'
                except:
                    result = None
                    return "Couldn't scan Host:- {}".format(target)
                if score:
                    return float(result)
                else:
                    return f'Honeypot Probablity: {float(result.text)*100}%'

        except socket.gaierror:
            return 'Unable to resolve address'
        except socket.error:
            return f'{socket.gethostbyname(host)} is Unreachable'
        except KeyboardInterrupt:
            return sys.exit('Stopped, Exiting: 1')


