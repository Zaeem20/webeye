import unittest   # The test framework
from webeye.core import AsyncHelper # This is a SRC

a = AsyncHelper()

class Test_AsyncWebeye(unittest.TestCase):
    async def test_scan(self):
        self.assertIsInstance(await a.scan('google.com', 1024 ,dev_mode=True), tuple)
    
    async def test_reversedns(self):
        self.assertIsInstance(await a.reversedns('google.com'), str)
    
    async def test_extract_pagelink(self):
        self.assertIsInstance(await a.extract_pagelinks('google.com'), list)
    
    async def test_shared_dns(self):
        self.assertIsInstance(await a.fetch_shared_dns('google.com'), list)
    
    async def test_bannergrabber(self):
        self.assertIsInstance(await a.grab('google.com'), dict)
    
    async def test_geoip(self):
        self.assertIsInstance(await a.geoip('google.com'),dict)
    
    async def test_find_subdomains(self):
        self.assertIsInstance(await a.find_subdomains('google.com'), list)
    
    async def test_dnslook(self):
        self.assertIsInstance(await a.fetch_dns('google.com'), list)
    
    async def test_reversiplook(self):
        self.assertIsInstance(await a.reverseip('142.250.183.14'), str)
    
    async def test_is_cloudflare(self):
        self.assertIsInstance(await a.is_cloudflare('google.com'), bool)
    
    async def test_is_honeypot(self):
        self.assertIsInstance(await a.is_honeypot('google.com'), str)

if __name__ == '__main__':
    unittest.main()