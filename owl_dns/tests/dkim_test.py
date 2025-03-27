import unittest
import unittest.mock

from base_engine.test_case import TestEngine


class TestEngine(TestEngine):
    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_no_dkim(self, mock_resolver=None):
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

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_multiple_dkim(self, mock_resolver=None):
        mock_resolver.return_value = [
            "v=DKIM1; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDGB2jMemtae4C4+NWCPr1o4EOqrG68zHEJmEXLS2lUgzCitxGgccPk/l8bRYWT71CoE4TL9svN4GnpSsvLW5ICQcu EnMId6SaORivk2r0K8gKkrY/R1eDbs0FG0H/9ApUHKyAuNIvMFRJcQ4bKjDEccMKDPNkbecHo0eY5LEynLwIDAQAB",
            "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlxj3ojSWxMiNbAYyT7LNtP2hhU2DWDSRB07AeHM6qhxlZV0drzMe/L7b2RIpQ7bHvzfZ77TgMlcdXqa8ksPjuStCxVNcRoYUMR8+QAp7IgfF0KQNQxvu J1/EWRcd/Xx7qoR9rALO8PS0z/OKuh7BXguDGxW/eXHbGvlCT+AE2LwIDAQAB",
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dkim_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dkim_check")
        self.assertEqual(
            results[0]["result"]["title"], "Multiple DKIM records detected"
        )

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_do_missing_p_tag(self, mock_resolver=None):
        mock_resolver.return_value = [
            "v=DKIM1; k=rsa",
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dkim_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dkim_check")
        self.assertEqual(results[0]["result"]["title"], "DKIM p tag not found")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_weak_key(self, mock_resolver=None):
        mock_resolver.return_value = [
            "v=DKIM1; p=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUZ3d0RRWUpLb1pJaHZjTkFRRUJCUUFEU3dBd1NBSkJBSjRUcXNhZFdXQkFGLzFROFJROHFOOGN3SndFdzdPeGNoS2wxZy8zQzZlTTM1NU9SYmJpMjYzSFh3SmNLTmgzNXY0Z2NBbERFNG1tWVZSZjJaZ1BMRjhDQXdFQUFRPT0KLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dkim_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "dkim_check")
        self.assertEqual(results[0]["result"]["title"], "Weak DKIM key")

    @unittest.mock.patch("dns.resolver.Resolver.resolve")
    def test_valid(self, mock_resolver=None):
        mock_resolver.return_value = [
            "v=DKIM1; p=LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF5aG1reHlSQ01JYnRVTWpRcVlqdkpwSnlpUHZOaEJPNHpUTGNCMC9qWUpTb1dCVVpXN2Urb1dQd0FDOVAxZWdWNEVURDR3SWRYUGYxV2YvOUVIOXBmdzRMdmJSYjlqK284TEZDaFBqRWF5WC9JQ3QxNDZKbmI1VW1TYmlrek9HL0EwRmt6dkxNMnhUYks5bjdreFFqcnlBQW9MbXc1Q09yUDlSc05PMWIxWXNBNkpYa3c4YXcwZzdud3l3Q2Y2TjljZkhycWhhZTYyYnc4SW9JL25zOXBtelRwSkpKV0FEU1IvRlVudWl1TytpRi8vZFFYY01ZRThxcVpNLzF4RHhoNmpIbUxJZElGNnVJUDA0SU1CMjJsZDhoek1Yc0cwQkwvb25rdjRnK1NOK3RCdkQ2VnFuYkF6RkxFSVJEYWl4M0U4ajZ5WnIwMWVta3pUR2RjNGNBSndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0t",
        ]
        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.dmarc"},
            ],
            "do_dkim_check": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 0)


if __name__ == "__main__":
    unittest.main()
