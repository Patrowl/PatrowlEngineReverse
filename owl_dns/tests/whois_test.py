import unittest
import unittest.mock

from base_engine.test_case import TestEngine
from tests.mock import whois


class TestEngine(TestEngine):
    @unittest.mock.patch("whois.whois")
    def test_do_whois(self, mock_whois):
        mock_whois.return_value = whois.get_dummy_whois()

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.whois"},
            ],
            "do_whois": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")

    # def test_do_whois_error(self):
    #     options = {
    #         "assets": [
    #             {"datatype": "domain", "value": "sub.yohangastoud.fr"},
    #         ],
    #         "do_whois": True,
    #     }

    #     results = self.start_scan(options)
    #     self.assertEqual(len(results), 1)
    #     print(results)

    # @unittest.mock.patch("ipwhois.IPWhois")
    # def test_do_whois_ip(self, MockIPWhois):

    #     MockIPWhois.return_value = unittest.mock.MagicMock()

    #     MockIPWhois.return_value.lookup_rdap.return_value =  {'nir': None, 'asn_registry': 'SALOPERIE', 'asn': '15169', 'asn_cidr': '8.8.8.0/24', 'asn_country_code': 'US', 'asn_date': '2023-12-28', 'asn_description': 'GOOGLE, US', 'query': '8.8.8.8', 'network': {'handle': 'NET-8-8-8-0-2', 'status': ['active'], 'remarks': None, 'notices': [{'title': 'Terms of Service', 'description': 'By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use', 'links': ['https://www.arin.net/resources/registry/whois/tou/']}, {'title': 'Whois Inaccuracy Reporting', 'description': 'If you see inaccuracies in the results, please visit: ', 'links': ['https://www.arin.net/resources/registry/whois/inaccuracy_reporting/']}, {'title': 'Copyright Notice', 'description': 'Copyright 1997-2025, American Registry for Internet Numbers, Ltd.', 'links': None}], 'links': ['https://rdap.arin.net/registry/ip/8.8.8.0', 'https://whois.arin.net/rest/net/NET-8-8-8-0-2'], 'events': [{'action': 'last changed', 'timestamp': '2023-12-28T17:24:56-05:00', 'actor': None}, {'action': 'registration', 'timestamp': '2023-12-28T17:24:33-05:00', 'actor': None}], 'raw': None, 'start_address': '8.8.8.0', 'end_address': '8.8.8.255', 'cidr': '8.8.8.0/24', 'ip_version': 'v4', 'type': 'DIRECT ALLOCATION', 'name': 'GOGL', 'country': None, 'parent_handle': 'NET-8-0-0-0-0'}, 'entities': ['GOGL'], 'objects': {'GOGL': {'handle': 'GOGL', 'status': None, 'remarks': [{'title': 'Registration Comments', 'description': 'Please note that the recommended way to file abuse complaints are located in the following links. \n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards, \nThe Google Team', 'links': None}], 'notices': None, 'links': ['https://rdap.arin.net/registry/entity/GOGL', 'https://whois.arin.net/rest/org/GOGL'], 'events': [{'action': 'last changed', 'timestamp': '2019-10-31T15:45:45-04:00', 'actor': None}, {'action': 'registration', 'timestamp': '2000-03-30T00:00:00-05:00', 'actor': None}], 'raw': None, 'roles': ['registrant'], 'contact': {'name': 'Google LLC', 'kind': 'org', 'address': [{'type': None, 'value': '1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States'}], 'phone': None, 'email': None, 'role': None, 'title': None}, 'events_actor': None, 'entities': ['ABUSE5250-ARIN', 'ZG39-ARIN']}}, 'raw': None}

    #     # mock_resolve.side_effect = [
    #     #     ['"15169 | 8.8.8.0/24 | US | arin | 2023-12-28"'],
    #             # ['"15169 | US | arin | 2000-03-30 | GOOGLE, US"']
    #     # ]

    #     options = {
    #         "assets": [
    #             {"datatype": "ip", "value": "8.8.8.8"},
    #         ],
    #         "do_whois": True,
    #     }

    #     results = self.start_scan(options)
    #     self.assertEqual(len(results), 1)
    #     self.assertEqual(results[0]["result"]["type"], "whois_ip_fullinfo")

    @unittest.mock.patch("whois.whois")
    def test_do_advanced_whois(self, mock_whois):
        mock_whois.return_value = whois.get_dummy_whois()

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.whois"}],
            "do_advanced_whois": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 9)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")


if __name__ == "__main__":
    unittest.main()
