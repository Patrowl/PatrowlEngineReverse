import unittest
import unittest.mock

from base_engine.test_case import TestEngine

__import__("sublist3r")


class TestEngine(TestEngine):

    @unittest.mock.patch("sublist3r.main")
    def test_do_subdomains(self, mock_sublist3r):
        mock_sublist3r.return_value = ["sub.dummy.fr"]

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.fr"}],
            "do_subdomain_enum": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "subdomain")
        self.assertEqual(
            results[0]["result"]["description"], "Subdomain found:\n\nsub.dummy.fr"
        )
        self.assertEqual(results[0]["result"]["target"]["addr"], ["dummy.fr"])

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    @unittest.mock.patch("sublist3r.main")
    def test_do_subdomains_resolve(self, mock_sublist3r, mock_resolve):
        mock_sublist3r.return_value = ["sub.dummy.fr"]
        mock_resolve.return_value = ["1.2.3.4"]

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.fr"}],
            "do_subdomain_enum": True,
            "do_subdomains_resolve": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "subdomains_resolve")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    @unittest.mock.patch("sublist3r.main")
    def test_do_subdomains_resolve_create_new_assets(
        self, mock_sublist3r, mock_resolve
    ):
        mock_sublist3r.return_value = ["sub.dummy.fr"]
        mock_resolve.return_value = ["1.2.3.4"]

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.fr"}],
            "do_subdomain_enum": True,
            "subdomain_as_new_asset": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "subdomain")
        self.assertEqual(results[0]["result"]["target"]["addr"], ["sub.dummy.fr"])


if __name__ == "__main__":
    unittest.main()
