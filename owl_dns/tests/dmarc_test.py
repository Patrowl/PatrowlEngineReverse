import unittest
import unittest.mock

from base_engine.test_case import TestEngine


class TestEngine(TestEngine):
    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_no_dmarc_check(self, mock_resolver=None):
        mock_resolver.return_value = [""]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dmarc_check")
        self.assertEqual(results[0]["result"]["title"], "No DMARC record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_dmarc_check(self, mock_resolver=None):
        mock_resolver.return_value = [
            "'v=DMARC1; p=reject; rua=mailto:mailauth-reports@google.com'"
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 0)

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_lax_policy_and_low_pct(self, mock_resolver=None):
        mock_resolver.return_value = [
            '"v=DMARC1; p=none; pct=50; rua=mailto:mailauth-reports@google.com"'
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["title"], "Lax DMARC policy")
        self.assertEqual(results[1]["result"]["title"], "Partial DMARC coverage")
        self.assertEqual(
            results[1]["result"]["description"],
            "The DMARC 'pct' value is '50', meaning the DMARC policy will only be applied to 50% of incoming mail.",
        )

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_lax_subdomain_policy(self, mock_resolver=None):
        mock_resolver.return_value = [
            '"v=DMARC1; p=reject; sp=none; rua=mailto:mailauth-reports@google.com"'
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["title"], "Lax DMARC subdomain policy")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_multiple_records(self, mock_resolver=None):
        mock_resolver.return_value = [
            '"v=DMARC1; p=reject; sp=none"',
            '"v=DMARC1; p=reject; rua=mailto:postmaster@example.com, mailto:dmarc@example.com; pct=100; adkim=s; aspf=s"',
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["title"], "Multiple DMARC records")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_no_reporting(self, mock_resolver=None):
        mock_resolver.return_value = [
            '"v=DMARC1; p=reject; adkim=s; aspf=s"',
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["title"], "No DMARC reporting configured")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_malformed(self, mock_resolver=None):
        mock_resolver.return_value = [
            '"v=DMARC1; rua=mailto:postmaster@example.com; p=reject, adkim=s; aspf=s"',
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dmarc_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["title"], "Invalid DMARC record")


if __name__ == "__main__":
    unittest.main()
