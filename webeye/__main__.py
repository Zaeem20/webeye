import argparse, requests, webeye
from webeye.core import *
import os

def main():
    __author__ = 'Zaeem Techical'

    logo = '''
            ===================================
            |   Python Port Scanner v2.5      |
            |          <--powered by Webeye-->|    
            ===================================
                                                '''

    parser = argparse.ArgumentParser(description=f'|<――――― Webeye v{webeye.__version__} - Help Menu ―――――>|', epilog=f"Author: {__author__} (Zaeem20)")
    parser.add_argument('-s', '--scan',action='store_true', help='Scan Open Ports of Given Host')
    parser.add_argument('-d', '--dns',action='store_true', help='Do DNS Lookup of Given Host')
    parser.add_argument('-hp','--honeypot',action='store_true', help='Find Honeypot Probablity for Given Host')
    parser.add_argument('-hs', '--subdomain',action='store_true', help='Enumerate Subdomain for Given Host')
    parser.add_argument('-C','--cloud',action='store_true', help='Check Site is protected with Cloudflare or not...')
    parser.add_argument('-b', '--grab',action='store_true', help='Grab banner of a Website')
    parser.add_argument('-w', '--whois', action='store_true', help='Whois Lookup of Website')
    parser.add_argument('-sD', '--shareddns',action='store_true',help='Find Shared DNS Server of a Website')
    parser.add_argument('-geo', '--geolookup',action='store_true', help='Find Geolocation and many other info of host')
    parser.add_argument('-rdns', '--reversedns',action='store_true',help='Reverse DNS Lookup of a Website')
    parser.add_argument('-rip', '--reverseip',action='store_true', help='Reverse IP Lookup of a Website')
    parser.add_argument('-e', '--extract',action='store_true',help='Extract ALL Pages from a Website')
    # Required args
    required_args = parser.add_argument_group('Required arguments')
    required_args.add_argument('target', help='Specify target with IP Address or URL')
    # Extras
    ext = parser.add_argument_group('optional extension')
    ext.add_argument('-p', '--range',metavar='', help='Specify port range [eg:- 20-500]')
    ext.add_argument('--no_ip',action='store_true', help='Enumerate All Subdomains without there IP addresses')
    options = parser.parse_args()

    if options.scan:        #port scanner
        try:
            latency = requests.get('http://' + options.target)
            print(logo)
            print()
            print(f'PyPort v2.5 Started at {datetime.utcnow().strftime("%d-%b-%Y %I:%M %p")}')
            print(f'PyPort Scan Report for {options.target} ({socket.gethostbyname(options.target)})')
            print(f"Host is up ({round(latency.elapsed.total_seconds(), 2)}s latency)")
            print(f'rDNS Record for {socket.gethostbyname(options.target)} ({reversedns(options.target)})')
            print()
            print('PORT\t |   SERVICE\t|   STATE  |')
            print('-'*36)
            if options.range:
                ports = options.range.split('-')
                print(scan(options.target, int(ports[1]), int(ports[0])))
            else:
                print(scan(options.target, 1024))  #By default scan all standard ports
        except IndexError:
            print("Please use '-' if you are trying with --range >> format: start-end")
        except socket.error:
            print("Could not connect to host")

    if options.dns:         # DNS Lookup
        fetch_dns(options.target, cli=True)
    if options.geolookup:   #Geo Lookup
        geoip(options.target, cli=True)
    if options.cloud:       # Cloud Lookup
        is_cloudflare(options.target, cli=True)
    if options.reverseip:   # Reverse IP Lookup
        reverseip(options.target, cli=True)
    if options.honeypot:    # Honeypot Lookup
        print(is_honeypot(options.target))
    if options.whois:
        print(whois(options.target))
    if options.reversedns:  # Reverse DNS Lookup
        print(reversedns(options.target))
    if options.subdomain:   # Subdomain Lookup
        if options.no_ip:
            subenum(options.target, cli=True)
        else:
            print(f"{'SUBDOMAINS'.ljust(60,' ')} | {'IP Addresses'.rjust(40,' ')}")
            print('-'*120)
            subenum(options.target, cli=True, no_ip=False)
    if options.grab:      # target Lookup
        grab(options.target, cli=True)
    if options.shareddns:   # Shared DNS Lookup
        fetch_shared_dns(options.target, cli=True)
    if options.extract:     # pagelinks extractor
        extract_pagelinks(options.target, cli=True)

if __name__ == '__main__':
    main()
