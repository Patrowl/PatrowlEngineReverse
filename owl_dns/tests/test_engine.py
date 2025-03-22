import unittest
import json

from pydantic import ValidationError
from engine import engine
from base_engine.test_case import TestEngine


class TestEngine(TestEngine):

    def test_missing_assets(self):
        options = {}

        with self.assertRaises(ValidationError):
            self.engine.test_scan(options, self.metadatas)

    def test_do_subdomains(self):
        options = {
            "assets": [{"datatype": "domain", "value": "yohangastoud.fr"}],
            "do_subdomain_enum": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 52)
        self.assertEqual(results[0]["result"]["type"], "subdomain")

    def test_do_subdomains_resolve(self):
        options = {
            "assets": [{"datatype": "domain", "value": "yohangastoud.fr"}],
            "do_subdomain_enum": True,
            "do_subdomains_resolve": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 104)
        self.assertEqual(results[0]["result"]["type"], "subdomains_resolve")
        self.assertEqual(results[-2]["result"]["type"], "subdomain")
        self.assertEqual(results[-1]["result"]["type"], "subdomains_enum")

    def test_do_dns_resolve(self):
        options = {
            "assets": [{"datatype": "domain", "value": "yohangastoud.fr"}],
            "do_dns_resolve": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)

        self.assertEqual(results[0]["result"]["type"], "dns_resolve")
        self.assertEqual(results[0]["result"]["target"]["addr"][0], "yohangastoud.fr")

    def test_do_dns_transfer(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
                {"datatype": "domain", "value": "zonetransfer.me"},
            ],
            "do_dns_transfer": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)

        self.assertEqual(results[0]["result"]["type"], "dns_transfer")
        self.assertEqual(results[0]["result"]["title"], "DNS zone transfer enabled")

    def test_do_dns_recursive(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
                # {"datatype": "domain", "value": 'mail.chivas.com.cn'}, # Uncomment for a result
            ],
            "do_dns_recursive": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 0)
        # self.assertEqual(len(results), 1)
        # self.assertEqual(results[0]['result']['type'], "dns_recursive")
        # self.assertEqual(results[0]['result']['title'], "DNS recursion available")

    def test_do_seg_check_no_seg(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
            ],
            "do_seg_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "seg_check")
        self.assertEqual(results[0]["result"]["title"], "No Secure Email Gateway found")

    def test_do_seg_check_seg_dict(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "patrowl.io"},
            ],
            "do_seg_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "seg_check")
        self.assertEqual(
            results[0]["result"]["title"],
            "Secure Email Gateway found: Microsoft/Microsoft 365 Defender Overview",
        )

    def test_do_dkim_check(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
            ],
            "do_dkim_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dkim_check")
        self.assertEqual(
            results[0]["result"]["title"],
            "DKIM check for 'yohangastoud.fr' (HASH: 58664d)",
        )

    def test_do_dmarc_check(self):
        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
            ],
            "do_dmarc_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dmarc_check")
        self.assertEqual(
            results[0]["result"]["title"], "DMARC for 'yohangastoud.fr' (HASH: 3938e6)"
        )


if __name__ == "__main__":
    unittest.main()
