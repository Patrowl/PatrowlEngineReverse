import unittest
import json
import unittest.mock

from pydantic import ValidationError
from engine import engine
from base_engine.test_case import TestEngine
from .mock import WHOIS_RESULT_DOMAIN, WHOIS_RESULT_IP


class TestEngine(TestEngine):

    @unittest.mock.patch("utils.get_whois")
    def test_do_whois(self, mock_resolve):

        mock_resolve.return_value = WHOIS_RESULT_DOMAIN

        options = {
            "assets": [
                {"datatype": "domain", "value": "yohangastoud.fr"},
            ],
            "do_whois": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")

    @unittest.mock.patch("utils.get_whois")
    def test_do_whois_ip(self, mock_resolve):

        mock_resolve.return_value = WHOIS_RESULT_IP

        options = {
            "assets": [
                {"datatype": "ip", "value": "8.8.8.8"},
            ],
            "do_whois": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "whois_ip_fullinfo")

    @unittest.mock.patch("utils.get_whois")
    def test_do_advanced_whois(self, mock_resolve):
        mock_resolve.return_value = WHOIS_RESULT_DOMAIN

        options = {
            "assets": [{"datatype": "domain", "value": "yohangastoud.fr"}],
            "do_advanced_whois": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 9)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")


if __name__ == "__main__":
    unittest.main()
