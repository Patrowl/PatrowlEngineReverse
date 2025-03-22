import unittest
import json
import unittest.mock

from pydantic import ValidationError
from engine import engine
from base_engine.test_case import TestEngine
from .mock_test import WHOIS_RESULT_DOMAIN, WHOIS_RESULT_IP
from whois.parser import WhoisFr

def get_dummy_whois():
    return WhoisFr(domain="dummy.whois",
            text=""""
%%
%% This is the AFNIC Whois server.
%%
%% complete date format: YYYY-MM-DDThh:mm:ssZ
%%
%% Rights restricted by copyright.
%% See https://www.afnic.fr/en/domain-names-and-support/everything-there-is-to-know-about-domain-names/find-a-domain-name-or-a-holder-using-whois/
%%
%%

domain:                        dummy.whois
status:                        ACTIVE
eppstatus:                     active
hold:                          NO
holder-c:                      ANO00-FRNIC
admin-c:                       ANO00-FRNIC
tech-c:                        OVH5-FRNIC
registrar:                     OVH
Expiry Date:                   2025-03-22T16:16:43Z
created:                       2019-03-22T16:16:43Z
last-update:                   2024-02-24T14:10:40.845051Z
source:                        FRNIC

nserver:                       dns20.ovh.net
nserver:                       ns20.ovh.net
source:                        FRNIC

registrar:                     OVH
address:                       2 Rue Kellermann
address:                       59100 ROUBAIX
country:                       FR
phone:                         +33.899701761
fax-no:                        +33.320200958
e-mail:                        support@ovh.net
website:                       http://www.ovh.com
anonymous:                     No
registered:                    1999-10-18T00:00:00Z
source:                        FRNIC

nic-hdl:                       ANO00-FRNIC
type:                          PERSON
contact:                       Ano Nymous
registrar:                     OVH
changed:                       2020-04-07T19:24:29Z
anonymous:                     YES
remarks:                       -------------- WARNING --------------
remarks:                       While the registrar knows him/her,
remarks:                       this person chose to restrict access
remarks:                       to his/her personal data. So PLEASE,
remarks:                       don't send emails to Ano Nymous. This
remarks:                       address is bogus and there is no hope
remarks:                       of a reply.
remarks:                       -------------- WARNING --------------
obsoleted:                     NO
eppstatus:                     associated
eppstatus:                     active
eligstatus:                    not identified
reachstatus:                   not identified
source:                        FRNIC

nic-hdl:                       ANO00-FRNIC
type:                          PERSON
contact:                       Ano Nymous
registrar:                     OVH
anonymous:                     YES
remarks:                       -------------- WARNING --------------
remarks:                       While the registrar knows him/her,
remarks:                       this person chose to restrict access
remarks:                       to his/her personal data. So PLEASE,
remarks:                       don't send emails to Ano Nymous. This
remarks:                       address is bogus and there is no hope
remarks:                       of a reply.
remarks:                       -------------- WARNING --------------
obsoleted:                     NO
eppstatus:                     associated
eppstatus:                     active
eligstatus:                    not identified
reachstatus:                   not identified
source:                        FRNIC

nic-hdl:                       OVH5-FRNIC
type:                          ORGANIZATION
contact:                       OVH NET
address:                       OVH
address:                       140, quai du Sartel
address:                       59100 Roubaix
country:                       FR
phone:                         +33.899701761
e-mail:                        tech@ovh.net
registrar:                     OVH
changed:                       2025-03-21T23:40:01.703279Z
anonymous:                     NO
obsoleted:                     NO
eppstatus:                     associated
eppstatus:                     active
eligstatus:                    not identified
reachstatus:                   not identified
source:                        FRNIC

>>> Last update of WHOIS database: 2025-03-22T01:06:45.953513Z <<<
"""
        )

class TestEngine(TestEngine):

    @unittest.mock.patch("whois.whois")
    def test_do_whois(self, mock_resolve):
        mock_resolve.return_value = get_dummy_whois()

        options = {
            "assets": [
                {"datatype": "domain", "value": "dummy.whois"},
            ],
            "do_whois": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")

    # @unittest.mock.patch("ipwhois.IPWhois", autospec=True)
    # def test_do_whois_ip(self, MockIPWhois):

    #     MockIPWhois.return_value = unittest.mock.MagicMock()
        
    #     # Configurer lookup_rdap() pour renvoyer "test"
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
    def test_do_advanced_whois(self, mock_resolve):
        mock_resolve.return_value = get_dummy_whois()

        options = {
            "assets": [{"datatype": "domain", "value": "dummy.whois"}],
            "do_advanced_whois": True,
        }

        results = self.start_scan(options)
        self.assertEqual(len(results), 9)
        self.assertEqual(results[0]["result"]["type"], "whois_domain_fullinfo")


if __name__ == "__main__":
    unittest.main()
