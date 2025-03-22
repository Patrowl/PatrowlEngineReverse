import unittest
import unittest.mock

from base_engine.test_case import TestEngine


class TestEngine(TestEngine):

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_spf(self, mock_resolve):

        mock_resolve.side_effect = [
            ['"v=spf1 include:_spf-eu.ionos.com ~all"'],
            ['"v=spf1 include:_spf-eu.ionos.com ~all"'],
            [
                '"v=spf1 ip4:212.227.126.128/25 ip4:82.165.159.0/26 ip4:212.227.15.0/25 ip4:212.227.17.0/27 ip4:217.72.192.64/26 ip4:185.48.116.13/32 ?all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "SPF record is set")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_no_spf(self, mock_resolve):

        mock_resolve.side_effect = [[]]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "No SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_miss_termination(self, mock_resolve):

        mock_resolve.side_effect = [
            ['"v=spf1 include:spf2.sbr-master.net"'],
            ['"v=spf1 include:spf2.sbr-master.net"'],
            ['"v=spf1  include:spf.rp01.net -all"'],
            [
                '"v=spf1 ip4:37.97.66.1/25 ip4:185.75.141.192/27 ip4:109.197.241.240/28 ip4:109.197.245.96/27 ip4:185.8.253.136/30 ip4:185.8.253.140/31 ip4:185.8.253.142/32 ip4:217.74.111.144/28 ip4:185.218.212.96/27 ip4:185.140.220.0/24 -all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Miss SPF record termination")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_permissive(self, mock_resolve):

        mock_resolve.side_effect = [
            ['"v=spf1 include:_mailcust.gandi.net ?all"'],
            ['"v=spf1 include:_mailcust.gandi.net ?all"'],
            ['"v=spf1 include:_nblcust.gandi.net ?all"'],
            [
                '"v=spf1 ip4:217.70.178.192/26 ip6:2001:4b98:dc4:8::/64 ip4:217.70.183.192/28 " "ip4:217.70.182.72/32 " "ip4:217.70.182.74/32 " "?all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Permissive SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_malformed(self, mock_resolve):

        mock_resolve.side_effect = [
            [
                '"v=spf1 nclude:spf.protection.outlook.com ip4:195.16.132.104 ip4:195.16.140.232 -all"'
            ],
            [
                '"v=spf1 nclude:spf.protection.outlook.com ip4:195.16.132.104 ip4:195.16.140.232 -all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Malformed SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_multiple(self, mock_resolve):

        mock_resolve.side_effect = [
            [
                '"brevo-code:ce5f011987ae9b374bda49eac5b71e1d"',
                '"v=spf1 include:spf.hornetsecurity.com ~all"',
                '"v=spf1 a mx ip4:37.187.200.41/32 ip4:164.132.197.185/32 include:mx.ovh.com include:spf.protection.outlook.com include:_spf.activetrail.com include:spf.sendinblue.com include:spf.mailjet.com ~all"',
                '"Sendinblue-code:66eee34f398a2040653b8dbe6a020106"',
            ],
            [
                '"Sendinblue-code:66eee34f398a2040653b8dbe6a020106"',
                '"v=spf1 a mx ip4:37.187.200.41/32 ip4:164.132.197.185/32 include:mx.ovh.com include:spf.protection.outlook.com include:_spf.activetrail.com include:spf.sendinblue.com include:spf.mailjet.com ~all"',
                '"brevo-code:ce5f011987ae9b374bda49eac5b71e1d"',
                '"v=spf1 include:spf.hornetsecurity.com ~all"',
            ],
            [
                '"v=spf1 ptr:mail-out.ovh.net ptr:mail.ovh.net ip4:8.33.137.105/32 ip4:192.99.77.81/32 ?all"'
            ],
            [
                '"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip4:52.102.0.0/16 ip4:52.103.0.0/17 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all"'
            ],
            [
                '"v=spf1 ip4:193.105.99.234 ip4:91.199.29.0/24 ip4:88.202.222.133/32 ip4:130.117.78.50/32 ip4:195.82.108.0/24 -all"'
            ],
            [
                '"v=spf1 ip4:185.41.28.0/22 ip4:94.143.16.0/21 ip4:185.24.144.0/22 ip4:153.92.224.0/19 ip4:213.32.128.0/18 ip4:185.107.232.0/22 ip4:77.32.128.0/18 ip4:77.32.192.0/19 ip4:212.146.192.0/18 ip4:172.246.0.0/18 -all"'
            ],
            [
                '"v=spf1 ip4:87.253.232.0/21 ip4:185.189.236.0/22 ip4:185.211.120.0/22 ip4:185.250.236.0/22 ip4:45.14.148.0/22 ~all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(results[0]["result"]["title"], "Multiple SPF records")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_deprecated(self, mock_resolve):

        mock_resolve.side_effect = [
            [
                '"MS=ms38583564"',
                '"v=spf1 ip4:209.17.115.0/24 ip4:64.69.218.0/24 include:eig.spf.a.cloudfilter.net include:spf.websitewelcome.com include:spf1.websitewelcome.com include:spfgwp.websitewelcome.com include:_spf.google.com include:spf.protection.outlook.com -all"',
            ],
            [
                '"MS=ms38583564"',
                '"v=spf1 ip4:209.17.115.0/24 ip4:64.69.218.0/24 include:eig.spf.a.cloudfilter.net include:spf.websitewelcome.com include:spf1.websitewelcome.com include:spfgwp.websitewelcome.com include:_spf.google.com include:spf.protection.outlook.com -all"',
            ],
            ['"v=spf1 ip4:35.89.44.32/29 ip4:44.202.169.32/29 ~all"'],
            [
                '"v=spf1 ip4:192.185.0.0/16 ip4:50.116.64.0/18 ip4:50.87.152.0/21 ip4:108.167.128.0/18 ip4:216.172.160.0/19 ip4:108.179.192.0/18 ip4:162.144.0.0/16 ip4:67.20.127.0/27 ip4:50.87.255.32/27 ip4:66.147.243.192/27 -all"'
            ],
            [
                '"v=spf1 ip4:100.42.48.0/20 ip4:104.152.64.0/21 ip4:104.171.0.0/20 ip4:108.175.144.0/20 ip4:23.91.112.0/20 ip4:198.58.80.0/20 ip4:198.252.64.0/20 ip4:192.169.48.0/20 ip4:162.253.144.0/21 ip4:162.254.160.0/21"'
            ],
            [
                '"v=spf1 ip4:66.147.240.0/20 ip4:67.20.64.0/19 ip4:67.20.96.0/21 ip4:67.222.32.0/19 ip4:69.89.16.0/20 ip4:70.40.192.0/19 ip4:74.220.192.0/19"'
            ],
            [
                '"v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"'
            ],
            [
                '"v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ip4:72.14.192.0/18 ip4:74.125.0.0/16 ip4:108.177.8.0/21 ip4:173.194.0.0/16 ip4:209.85.128.0/17 ip4:216.58.192.0/19 ip4:216.239.32.0/19 ~all"'
            ],
            [
                '"v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ip6:2800:3f0:4000::/36 ip6:2a00:1450:4000::/36 ip6:2c0f:fb50:4000::/36 ~all"'
            ],
            [
                '"v=spf1 ip4:172.217.0.0/19 ip4:172.217.32.0/20 ip4:172.217.128.0/19 ip4:172.217.160.0/20 ip4:172.217.192.0/19 ip4:172.253.56.0/21 ip4:172.253.112.0/20 ip4:108.177.96.0/19 ip4:35.191.0.0/16 ip4:130.211.0.0/22 ~all"'
            ],
            [
                '"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip4:52.102.0.0/16 ip4:52.103.0.0/17 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 2)
        self.assertEqual(results[1]["result"]["type"], "spf_check")
        self.assertEqual(results[1]["result"]["title"], "Deprecated SPF record")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_high_dns_lookup(self, mock_resolve):

        mock_resolve.side_effect = [
            ['"v=spf1 include:spf.protection.outlook.com -all"'] for _ in range(5000)
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[2]["result"]["type"], "spf_check")
        self.assertEqual(results[2]["result"]["title"], "High number of DNS lookup")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_directive_after_all(self, mock_resolve):

        mock_resolve.side_effect = [
            [
                '"v=spf1 +a +mx include:spf1.speig.fr include:spf2.speig.fr include:spf3.speig.fr include:spf4.speig.fr -all ~all"'
            ],
            [
                '"v=spf1 +a +mx include:spf1.speig.fr include:spf2.speig.fr include:spf3.speig.fr include:spf4.speig.fr -all ~all"'
            ],
            [
                '"v=spf1 ip4:41.142.240.168 ip4:164.177.20.16/28 ip4:62.168.123.53 ip4:41.159.134.245 ip4:212.243.252.68 ip4:217.158.88.242 ip4:82.141.226.98 ip4:80.188.142.202 ip4:202.22.224.179 ip4:186.67.163.154 ip4:160.34.64.28 include:spf.protection.outlook.com -all"'
            ],
            [
                '"v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/15 ip4:52.102.0.0/16 ip4:52.103.0.0/17 ip4:104.47.0.0/17 ip6:2a01:111:f400::/48 ip6:2a01:111:f403::/49 ip6:2a01:111:f403:8000::/51 ip6:2a01:111:f403:c000::/51 ip6:2a01:111:f403:f000::/52 -all"'
            ],
            [
                '"v=spf1 ip4:80.214.116.24 ip4:54.229.23.88 ip4:185.132.182.121 ip4:83.166.206.121 ip4:89.149.6.36 ip4:193.77.233.0/24 ip4:213.199.154.23 ip4:213.199.154.87 ip4:200.48.197.50 ip4:207.148.178.4/31 ip4:200.62.27.17 include:spf.tmes.trendmicro.com -all"'
            ],
            [
                '"v=spf1 ip4:18.208.22.64/26 ip4:18.208.22.128/25 ip4:18.185.115.128/26 ip4:18.185.115.0/25 ip4:13.238.202.0/25 ip4:13.238.202.128/26 ip4:18.176.203.128/25 ip4:13.213.174.128/25 ip4:18.177.156.0/25 ip4:13.213.220.0/25 include:spfb.tmes.trendmicro.com ~all"'
            ],
            [
                '"v=spf1 ip4:107.22.223.18 ip4:52.70.252.86 ip4:35.156.245.132 ip4:18.156.0.20 ip4:3.72.196.143 ip4:54.146.4.63 ip4:54.174.82.86 include:spfc.tmes.trendmicro.com ~all"'
            ],
            [
                '"v=spf1 ip4:18.188.9.192/26 ip4:18.188.239.128/26 ip4:34.253.238.128/26 ip4:34.253.238.192/26 ip4:15.168.56.0/25 ip4:15.168.49.64/26 ip4:15.168.56.128/26 ip4:18.97.0.160/27 ip4:18.96.32.128/27 ~all"'
            ],
            [
                '"v=spf1 ip4:72.55.186.32/27 ip4:173.231.127.128/26 ip4:173.231.127.92/30 ip4:70.54.190.249 ip4:162.248.176.71 ip4:196.217.245.142 ip4:216.123.215.194 ip4:212.17.80.98 ip4:213.136.107.34 ip4:41.188.18.131 ip4:197.3.4.74 ip4:202.22.224.132 -all"'
            ],
            [
                '"v=spf1 ip4:190.8.83.2 ip4:80.77.225.51 ip4:193.57.109.3 ip4:193.57.109.19 ip4:193.57.109.27 ip4:79.174.225.141 ip4:197.227.17.186 ip4:80.122.15.134 ip4:46.238.100.102 ip4:62.199.210.178 ip4:197.96.226.225 ip4:62.209.51.110 ip4:91.207.212.100 -all"'
            ],
        ]

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy"},
            ],
            "do_spf_check": True,
        }

        results = self.engine.test_scan(options, self.metadatas)
        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]["result"]["type"], "spf_check")
        self.assertEqual(
            results[0]["result"]["title"], "Directives after ALL not allowed"
        )


if __name__ == "__main__":
    unittest.main()
