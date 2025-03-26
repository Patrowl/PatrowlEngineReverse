import unittest
import unittest.mock

from base_engine.test_case import TestEngine


class TestEngine(TestEngine):
    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_dkim_check(self, mock_resolver=None):
        mock_resolver.return_value = [""]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dkim_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dkim_check")
        self.assertEqual(results[0]["result"]["title"], "No DKIM record")


if __name__ == "__main__":
    unittest.main()
