import unittest

from gglsbl.protocol import URL

class SafeBrowsingListTestCase(unittest.TestCase):
    def setUp(self):
        self.canonical_urls = {
            "http://host/%25%32%35": "http://host/%25",
            "http://host/%25%32%35%25%32%35": "http://host/%25%25",
            "http://host/%2525252525252525": "http://host/%25",
            "http://host/asdf%25%32%35asd": "http://host/asdf%25asd",
            "http://host/%%%25%32%35asd%%": "http://host/%25%25%25asd%25%25",
            "http://www.google.com/": "http://www.google.com/",
            "http://%31%36%38%2e%31%38%38%2e%39%39%2e%32%36/%2E%73%65%63%75%72%65/%77%77%77%2E%65%62%61%79%2E%63%6F%6D/": "http://168.188.99.26/.secure/www.ebay.com/",
            "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/": "http://195.127.0.11/uploads/%20%20%20%20/.verify/.eBaysecure=updateuserdataxplimnbqmn-xplmvalidateinfoswqpcmlx=hgplmcx/",
            "http://host%23.com/%257Ea%2521b%2540c%2523d%2524e%25f%255E00%252611%252A22%252833%252944_55%252B": "http://host%23.com/~a!b@c%23d$e%25f^00&11*22(33)44_55+",
            "http://3279880203/blah": "http://195.127.0.11/blah",
            "http://0xc37f000b/blah": "http://195.127.0.11/blah",
            "http://www.google.com/blah/..": "http://www.google.com/",
            "www.google.com/": "http://www.google.com/",
            "www.google.com": "http://www.google.com/",
            "http://www.evil.com/blah#frag": "http://www.evil.com/blah",
            "http://www.GOOgle.com/": "http://www.google.com/",
            "google.com": "http://google.com/",
            "google.com:443/abc": "http://google.com:443/abc",
            "//google.com:443/abc": "http://google.com:443/abc",
            "ftp://google.com:443/abc": "ftp://google.com:443/abc",
            "http://www.google.com.../": "http://www.google.com/",
            "http://www.google.com/foo\tbar\rbaz\n2":"http://www.google.com/foobarbaz2",
            "http://www.google.com/q?": "http://www.google.com/q?",
            "http://www.google.com/q?r?": "http://www.google.com/q?r?",
            "http://www.google.com/q?r?s": "http://www.google.com/q?r?s",
            "http://evil.com/foo#bar#baz": "http://evil.com/foo",
            "http://evil.com/foo;": "http://evil.com/foo;",
            "http://evil.com/foo?bar;": "http://evil.com/foo?bar;",
            b"http://\x01\x80.com/": "http://%01%80.com/",
            b"http://\x01\xf0.com/": "http://%01%F0.com/",
            "http://notrailingslash.com": "http://notrailingslash.com/",
            "http://www.gotaport.com:1234/": "http://www.gotaport.com:1234/",
            "  http://www.google.com/  ": "http://www.google.com/",
            "http:// leadingspace.com/": "http://%20leadingspace.com/",
            "http://%20leadingspace.com/": "http://%20leadingspace.com/",
            "%20leadingspace.com/": "http://%20leadingspace.com/",
            "https://www.securesite.com/": "https://www.securesite.com/",
            "http://host.com/ab%23cd": "http://host.com/ab%23cd",
            "http://host.com//twoslashes?more//slashes": "http://host.com/twoslashes?more//slashes",
            "http://www.wtp101.com/bk?redir=http%3A%2F%2Ftags.bluekai.com%2Fsite%2F2750%3Fid%3D%3CPARTNER_UUID%3E%0D%0A%26redir%3Dhttp%3A%2F%2Fwww.wtp101.com%2Fpush%2Fbluekai%3Fxid%3D%24BK_UUID": "http://www.wtp101.com/bk?redir=http://tags.bluekai.com/site/2750?id=<PARTNER_UUID>%0D%0A&redir=http://www.wtp101.com/push/bluekai?xid=$BK_UUID",
        }

        self.url_permutations = {
            'http://a.b.c/1/2.html?param=1': [
                'a.b.c/1/2.html?param=1',
                'a.b.c/1/2.html',
                'a.b.c/',
                'a.b.c/1/',
                'b.c/1/2.html?param=1',
                'b.c/1/2.html',
                'b.c/',
                'b.c/1/',
            ],
            'http://a.b.c/1/2/?param=1': [
                'a.b.c/1/2/?param=1',
                'a.b.c/1/2/',
                'a.b.c/',
                'a.b.c/1/',
                'b.c/1/2/?param=1',
                'b.c/1/2/',
                'b.c/',
                'b.c/1/',
            ],
            'http://1.2.3.4/1/2.html?param=1': [
                '1.2.3.4/1/2.html?param=1',
                '1.2.3.4/1/2.html',
                '1.2.3.4/',
                '1.2.3.4/1/',
            ],
            'http://a.b.c/1/2/3/4/5/6/7.html?param=1': [
                'a.b.c/1/2/3/4/5/6/7.html?param=1',
                'a.b.c/1/2/3/4/5/6/7.html',
                'a.b.c/',
                'a.b.c/1/',
                'a.b.c/1/2/',
                'a.b.c/1/2/3/',
                'b.c/1/2/3/4/5/6/7.html?param=1',
                'b.c/1/2/3/4/5/6/7.html',
                'b.c/',
                'b.c/1/',
                'b.c/1/2/',
                'b.c/1/2/3/',
            ],
            'ttp://a.b.c.d.e.f.g/1.html': [
                'a.b.c.d.e.f.g/1.html',
                'a.b.c.d.e.f.g/',
                'c.d.e.f.g/1.html',
                'c.d.e.f.g/',
                'd.e.f.g/1.html',
                'd.e.f.g/',
                'e.f.g/1.html',
                'e.f.g/',
                'f.g/1.html',
                'f.g/',
            ],
            'http://a.b/': [
                'a.b/',
            ],
        }

    def test_canonicalize(self):
        for nu, cu in self.canonical_urls.items():
            self.assertEqual(URL(nu).canonical, cu)

    def test_permutations(self):
        for k,v in self.url_permutations.items():
            p = list(URL.url_permutations(k))
            self.assertEqual(p, v)

