import unittest
import unittest.mock

from pydantic import ValidationError
from base_engine.test_case import TestEngine


class TestEngine(TestEngine):
    def test_missing_assets(self):
        options = {}

        with self.assertRaises(ValidationError):
            self.start_scan(options)

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_seg_check_no_seg(self, mock_resolver):
        mock_resolver.return_value = [["1 mx4.mail.ovh.net.", "10 mx3.mail.ovh.net."]]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.no_seg"},
            ],
            "do_seg_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "seg_check")
        self.assertEqual(results[0]["result"]["title"], "No Secure Email Gateway found")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_seg_check_seg_dict(self, mock_resolver):
        mock_resolver.return_value = ["0 dummy.seg_dict.mail.protection.outlook.com."]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.seg_dict"},
            ],
            "do_seg_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "seg_check")
        self.assertEqual(
            results[0]["result"]["title"],
            "Secure Email Gateway found: Microsoft/Microsoft 365 Defender Overview",
        )

    # @unittest.mock.patch("dns.resolver.Resolver.resolve")
    # def test_do_dkim_check(self, mock_resolver):
    #     mock_resolver.return_value = ["54.36.189.124"]
    #     options = {
    #         "assets": [
    #             {"datatype": "domain", "value": "dummy.dkim"},
    #         ],
    #         "do_dkim_check": True,
    #     }

    #     results = self.start_scan(options)
    #     self.assertEqual(len(results), 1)
    #     self.assertEqual(results[0]["result"]["type"], "dkim_check")
    #     self.assertEqual(
    #         results[0]["result"]["title"],
    #         "DKIM check for 'dummy.dkim' (HASH: 66abfa)",
    #     )


if __name__ == "__main__":
    unittest.main()
