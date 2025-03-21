import unittest
from unittest import mock

from utils import (
    dns_resolve_asset,
    get_lookup_count_and_spf_records,
)
from etc.issues import spf_issues


class TestSPF(unittest.TestCase):
    maxDiff = None

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_dns_resolve_asset(self, mock_resolve):
        # Arrange: set up the mock with a random SPF record
        mock_resolve.return_value = ['"v=spf1 include:spf.protection.outlook.com -all"']

        # Act
        dns_records = dns_resolve_asset("patrowl.io", "TXT")

        # Assert
        self.assertCountEqual(
            dns_records,
            [
                {
                    "record_type": "TXT",
                    "values": ["v=spf1 include:spf.protection.outlook.com -all"],
                    "answers": ['"v=spf1 include:spf.protection.outlook.com -all"'],
                },
            ],
        )

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_check_dns_lookup_limit_less_than_10(self, mock_resolve):
        # Arrange
        mock_resolve.side_effect = [
            [
                '"v=spf1 include:spf.protection.outlook.com include:servers.mcsv.net include:7593890.spf10.hubspotemail.net -all"'
            ],
            [
                '"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/14 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all"'
            ],
            [
                '"v=spf1 ip4:205.201.128.0/20 ip4:198.2.128.0/18 ip4:148.105.8.0/21 -all"'
            ],
            [
                '"v=spf1 ip4:3.93.157.0/24 ip4:3.210.190.0/24 ip4:18.208.124.128/25 ip4:54.174.52.0/24 ip4:54.174.57.0/24 ip4:54.174.59.0/24 ip4:54.174.60.0/23 ip4:54.174.63.0/24 ip4:108.179.144.0/20 ip4:139.180.17.0/24 ip4:141.193.184.32/27 ip4:141.193.184.64/26 ip4:141.193.184.128/25 ip4:141.193.185.32/27 ip4:141.193.185.64/26 ip4:141.193.185.128/25 ip4:143.244.80.0/20 ip4:158.247.16.0/20 -all "'
            ],
        ]

        # Act
        dns_lookup_count, spf_lookup_records = get_lookup_count_and_spf_records(
            domain="patrowl.io"
        )

        # Assert
        self.assertEqual(dns_lookup_count, 3)

    @mock.patch("dns.resolver.Resolver.resolve")
    def test_check_dns_lookup_limit_recursion_error(self, mock_resolve):
        # Arrange (5000 DNS lookup)
        mock_resolve.side_effect = [
            ['"v=spf1 include:spf.protection.outlook.com -all"'] for _ in range(5000)
        ]
        # Assert
        self.assertRaises(
            RecursionError,
            lambda: get_lookup_count_and_spf_records(domain="patrowl.io"),
        )


if __name__ == "__main__":
    unittest.main()
