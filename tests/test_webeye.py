import unittest   # The test framework
from webeye.core import *


class Test_Webeye(unittest.TestCase):
    def test_scan(self):
        self.assertIsInstance(scan('google.com', 1024 ,dev_mode=True), tuple)

    def test_reversedns(self):
        self.assertIsInstance(reversedns('google.com'), str)
    
    def test_extract_pagelink(self):
        self.assertIsInstance(extract_pagelinks('google.com'), list)
    
    def test_shared_dns(self):
        self.assertIsInstance(fetch_shared_dns('google.com'), list)
    
    def test_bannergrabber(self):
        self.assertIsInstance(grab('google.com'), dict)
    
    def test_geoip(self):
        self.assertIsInstance(geoip('google.com'),dict)
    
    def test_find_subdomains(self):
        self.assertIsInstance(subenum('google.com'), list)
    
    def test_dnslook(self):
        self.assertIsInstance(fetch_dns('google.com'), list)
    
    def test_reversiplook(self):
        self.assertIsInstance(reverseip('142.250.183.14'), str)
    
    def test_is_cloudflare(self):
        self.assertIsInstance(is_cloudflare('google.com'), bool)
    
    def test_is_honeypot(self):
        self.assertIsInstance(is_honeypot('google.com'), str)

if __name__ == '__main__':
    unittest.main()