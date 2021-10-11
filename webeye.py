import argparse, requests
from core.handler import *


def main():
    __version__= '2.1.5'
    __author__ = 'Zaeem Techical'

    logo = '''
            ===================================
            |   Python Port Scanner v2.5      |
            |          <--powered by Webeye-->|    
            ===================================
                                                '''

    parser = argparse.ArgumentParser(description=f'|<――――― Webeye v{__version__} - Help Menu ―――――>|', epilog=f"Author: {__author__} (Zaeem20)")
    parser.add_argument('-s', '--scan', metavar='', help='Scan Open Ports of Given Host')
    parser.add_argument('-d', '--dns', metavar='', help='Do DNS Lookup of Given Host')
    parser.add_argument('-hp','--honeypot', metavar='', help='Find Honeypot Probablity for Given Host')
    parser.add_argument('-hs', '--subdomain',metavar='', help='Enumerate Subdomain for Given Host')
    parser.add_argument('-C','--cloud', metavar='', help='Check Site is protected with Cloudflare or not...')
    parser.add_argument('-b', '--banner', metavar='', help='Grab Banner of a Website')
    parser.add_argument('-sD', '--shareddns', metavar='',help='Find Shared DNS Server of a Website')
    parser.add_argument('-geo', '--geolookup', metavar='', help='Find Geolocation and many other info of host')
    parser.add_argument('-rdns', '--reversedns', metavar='',help='Reverse DNS Lookup of a Website')
    parser.add_argument('-rip', '--reverseip', metavar='', help='Reverse IP Lookup of a Website')
    parser.add_argument('-e', '--extract', metavar='',help='Extract ALL Pages from a Website')
    # Extras
    ext = parser.add_argument_group('optional extension')
    ext.add_argument('-p', '--range',metavar='', help='Specify port range [eg:- 20-500]')
    ext.add_argument('--no_ip',action='store_true', help='Enumerate All Subdomains without there IP addresses')
    options = parser.parse_args()

    if options.scan:        #port scanner
        try:
            latency = requests.get('http://' + options.scan)
            print(logo)
            print()
            print(f'PyPort v2.5 Started at {datetime.utcnow().strftime("%d-%b-%Y %I:%M %p")}')
            print(f'PyPort Scan Report for {options.scan} ({socket.gethostbyname(options.scan)})')
            print(f"Host is up ({round(latency.elapsed.total_seconds(), 2)}s latency)")
            print(f'rDNS Record for {socket.gethostbyname(options.scan)} ({reversedns(options.scan)})')
            print()
            print('PORT\t |   SERVICE\t|   STATE  |')
            print('-'*36)
            if options.range:
                ports = options.range.split('-')
                print(scan(options.scan, int(ports[1]), int(ports[0])))
            else:
                print(scan(options.scan, 1024))  #By default scan all standard ports
        except IndexError:
            print("Please use '-' if you are trying with --range >> format: start-end")
        except socket.error:
            print("Could not connect to host")

    if options.dns:         # DNS Lookup
        fetch_dns(options.dns, cli=True)
    if options.geolookup:   #Geo Lookup
        geoip(options.geolookup, cli=True)
    if options.cloud:       # Cloud Lookup
        is_cloudflare(options.cloud, cli=True)
    if options.reverseip:   # Reverse IP Lookup
        reverseip(options.reverseip, cli=True)
    if options.honeypot:    # Honeypot Lookup
        print(is_honeypot(options.honeypot))
    if options.reversedns:  # Reverse DNS Lookup
        print(reversedns(options.reversedns))
    if options.subdomain:   # Subdomain Lookup
        if options.no_ip:
            subenum(options.subdomain, cli=True)
        else:
            print(f"{'SUBDOMAINS'.ljust(60,' ')} | {'IP Addresses'.rjust(40,' ')}")
            print('-'*120)
            subenum(options.subdomain, cli=True, no_ip=False)
    if options.banner:      # banner Lookup
        grab(options.banner, cli=True)
    if options.shareddns:   # Shared DNS Lookup
        fetch_shared_dns(options.shareddns, cli=True)
    if options.extract:     # pagelinks extractor
        extract_pagelinks(options.extract, cli=True)

if __name__ == '__main__':
    main()