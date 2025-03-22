import unittest
import unittest.mock

from owl_dns.tests.spf import mock_data
from base_engine.test_case import TestEngine


class TestEngine(TestEngine):

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_spf(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_FOUND

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.spf"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "SPF record is set")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_no_spf(self, mock_resolve):

        mock_resolve.side_effect = [[]]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.no_spf"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "No SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_miss_termination(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_MISS_TERMINATION

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.miss"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Miss SPF record termination")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_permissive(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_PERMISSIVE

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.permissive"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Permissive SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_malformed(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_MALFORMED

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.malformed"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Malformed SPF record")
        self.assertEqual(
            results[0]["result"]["raw"]["extra_info"], "'nclude' is an illegal term."
        )

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_multiple(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_MULTIPLE

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.multiple"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Multiple SPF records")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_deprecated(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_DEPRECATED

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.deprecated"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1]["result"]["type"], "spf_check")
        self.assertEqual(results[1]["result"]["title"], "Deprecated SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_high_dns_lookup(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_HIGH_LOOKUP

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.high"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[2]["result"]["type"], "spf_check")
        self.assertEqual(results[2]["result"]["title"], "High number of DNS lookup")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_directive_after_all(self, mock_resolve):

        mock_resolve.side_effect = mock_data.SPF_AFTER_ALL

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.directive"},
            ],
            "do_spf_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(
            results[0]["result"]["title"], "Directives after ALL not allowed"
        )


if __name__ == "__main__":
    unittest.main()
