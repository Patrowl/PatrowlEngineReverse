import unittest
import unittest.mock

from base_engine.test_case import TestEngine

__import__("sublist3r")


class T:
    def __init__(self, t):
        self.t = t

    def target(self):
        return self.t


class FakeAnswer:
    def __init__(self, target):
        self.target = target

        class U:
            def to_text(s):
                return str(self)

            def __str__(s):
                return str(self)

        self.response = U()

    def target(self):
        return T()

    def __str__(self):
        return ", ".join(self.target)

    def __iter__(self):
        for t in self.target:
            yield T(t)


class TestEngine(TestEngine):

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_dns_resolve(self, mock_resolver):
        mock_resolver.side_effect = [
            [],
            ["54.36.189.124"],
            [],
            ["1 mx4.mail.ovh.net.", "10 mx3.mail.ovh.net."],
            ["ns20.ovh.net.", "dns20.ovh.net."],
            ['"1|dummy.resolve"'],
            ["dns20.ovh.net. tech.ovh.net. 2023050700 86400 3600 3600000 300"],
            [],
        ]

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.resolve"}],
            "do_dns_resolve": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dns_resolve")
        self.assertEqual(results[0]["result"]["target"]["addr"][0], "dummy.resolve")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    @unittest.mock.patch("dns.zone.from_xfr")
    def test_do_dns_transfer_enabled(self, mock_from_xfr, mock_resolver):
        mock_resolver.side_effect = [
            FakeAnswer(["nsztm1.digi.ninja.", "nsztm2.digi.ninja."]),
            ["213.251.128.143"],
            ["213.251.188.143"],
        ]

        mock_from_xfr.return_value = ["deadbeed"]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.transfer"},
            ],
            "do_dns_transfer": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dns_transfer")
        self.assertEqual(results[0]["result"]["title"], "DNS zone transfer enabled")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    @unittest.mock.patch("dns.zone.from_xfr")
    def test_do_dns_transfer(self, mock_from_xfr, mock_resolver):
        mock_resolver.side_effect = [
            FakeAnswer(["nsztm1.digi.ninja.", "nsztm2.digi.ninja."]),
            ["213.251.128.143"],
            ["213.251.188.143"],
        ]

        mock_from_xfr.return_value = []

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.no_transfer"},
            ],
            "do_dns_transfer": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 0)

    @unittest.mock.patch("utils.is_dns_recursive")
    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_dns_recursive(self, mock_resolver, mock_dns_recursive):
        mock_dns_recursive.return_value = {
            "response": "id 2755\nopcode QUERY\nrcode NOERROR\nflags QR AA RD RA\n;QUESTION\ngoogle.com. IN A\n;ANSWER\ngoogle.com. 60 IN A 8.7.198.46\n;AUTHORITY\n;ADDITIONAL",
            "flags": "QR AA RD RA",
        }
        mock_resolver.side_effect = [
            ["4.4.4.4"],
        ]

        options = {
            "assets": [
                # {"datatype": "domain", "value": "yohangastoud.fr"},
                {
                    "datatype": "domain",
                    "value": "dummy.recursive",
                },
            ],
            "do_dns_recursive": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dns_recursive")
        self.assertEqual(results[0]["result"]["title"], "DNS recursion available")

    @unittest.mock.patch("utils.is_dns_recursive")
    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_no_dns_recursive(self, mock_resolver, mock_dns_recursive):
        mock_dns_recursive.return_value = None
        mock_resolver.side_effect = [
            ["4.4.4.4"],
        ]

        options = {
            "assets": [
                {
                    "datatype": "domain",
                    "value": "dummy.not_recursive",
                },
            ],
            "do_dns_recursive": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
