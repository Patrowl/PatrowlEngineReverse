import datetime

WHOIS_RESULT_DOMAIN = {
    "raw": {
        "dict": {
            "domain_name": "yohangastoud.fr",
            "registrar": "OVH",
            "creation_date": datetime.datetime(2019, 3, 22, 16, 16, 43),
            "expiration_date": datetime.datetime(2025, 3, 22, 16, 16, 43),
            "name_servers": ["dns20.ovh.net", "ns20.ovh.net"],
            "status": ["ACTIVE", "active", "associated", "not identified"],
            "emails": ["support@ovh.net", "tech@ovh.net"],
            "updated_date": datetime.datetime(2024, 2, 24, 14, 10, 40, 845051),
        },
        "text": "%%\n%% This is the AFNIC Whois server.\n%%\n%% complete date format: YYYY-MM-DDThh:mm:ssZ\n%%\n%% Rights restricted by copyright.\n%% See https://www.afnic.fr/en/domain-names-and-support/everything-there-is-to-know-about-domain-names/find-a-domain-name-or-a-holder-using-whois/\n%%\n%%\n\ndomain:                        yohangastoud.fr\r\nstatus:                        ACTIVE\r\neppstatus:                     active\r\nhold:                          NO\r\nholder-c:                      ANO00-FRNIC\r\nadmin-c:                       ANO00-FRNIC\r\ntech-c:                        OVH5-FRNIC\r\nregistrar:                     OVH\r\nExpiry Date:                   2025-03-22T16:16:43Z\r\ncreated:                       2019-03-22T16:16:43Z\r\nlast-update:                   2024-02-24T14:10:40.845051Z\r\nsource:                        FRNIC\r\n\r\nnserver:                       dns20.ovh.net\r\nnserver:                       ns20.ovh.net\r\nsource:                        FRNIC\r\n\r\nregistrar:                     OVH\r\naddress:                       2 Rue Kellermann\r\naddress:                       59100 ROUBAIX\r\ncountry:                       FR\r\nphone:                         +33.899701761\r\nfax-no:                        +33.320200958\r\ne-mail:                        support@ovh.net\r\nwebsite:                       http://www.ovh.com\r\nanonymous:                     No\r\nregistered:                    1999-10-18T00:00:00Z\r\nsource:                        FRNIC\r\n\r\nnic-hdl:                       OVH5-FRNIC\r\ntype:                          ORGANIZATION\r\ncontact:                       OVH NET\r\naddress:                       OVH\r\naddress:                       140, quai du Sartel\r\naddress:                       59100 Roubaix\r\ncountry:                       FR\r\nphone:                         +33.899701761\r\ne-mail:                        tech@ovh.net\r\nregistrar:                     OVH\r\nchanged:                       2025-03-21T21:29:59.371801Z\r\nanonymous:                     NO\r\nobsoleted:                     NO\r\neppstatus:                     associated\r\neppstatus:                     active\r\neligstatus:                    not identified\r\nreachstatus:                   not identified\r\nsource:                        FRNIC\r\n\r\nnic-hdl:                       ANO00-FRNIC\r\ntype:                          PERSON\r\ncontact:                       Ano Nymous\r\nregistrar:                     OVH\r\nanonymous:                     YES\r\nremarks:                       -------------- WARNING --------------\r\nremarks:                       While the registrar knows him/her,\r\nremarks:                       this person chose to restrict access\r\nremarks:                       to his/her personal data. So PLEASE,\r\nremarks:                       don't send emails to Ano Nymous. This\r\nremarks:                       address is bogus and there is no hope\r\nremarks:                       of a reply.\r\nremarks:                       -------------- WARNING --------------\r\nobsoleted:                     NO\r\neppstatus:                     associated\r\neppstatus:                     active\r\neligstatus:                    not identified\r\nreachstatus:                   not identified\r\nsource:                        FRNIC\r\n\r\nnic-hdl:                       ANO00-FRNIC\r\ntype:                          PERSON\r\ncontact:                       Ano Nymous\r\nregistrar:                     OVH\r\nchanged:                       2020-04-07T19:24:29Z\r\nanonymous:                     YES\r\nremarks:                       -------------- WARNING --------------\r\nremarks:                       While the registrar knows him/her,\r\nremarks:                       this person chose to restrict access\r\nremarks:                       to his/her personal data. So PLEASE,\r\nremarks:                       don't send emails to Ano Nymous. This\r\nremarks:                       address is bogus and there is no hope\r\nremarks:                       of a reply.\r\nremarks:                       -------------- WARNING --------------\r\nobsoleted:                     NO\r\neppstatus:                     associated\r\neppstatus:                     active\r\neligstatus:                    not identified\r\nreachstatus:                   not identified\r\nsource:                        FRNIC\r\n\n>>> Last update of WHOIS database: 2025-03-21T23:21:26.618143Z <<<\n\r\n",
    },
    "type": "domain",
}


WHOIS_RESULT_IP = {
    "raw": {
        "dict": {
            "nir": None,
            "asn_registry": "arin",
            "asn": "15169",
            "asn_cidr": "8.8.8.0/24",
            "asn_country_code": "US",
            "asn_date": "2023-12-28",
            "asn_description": "GOOGLE, US",
            "query": "8.8.8.8",
            "network": {
                "handle": "NET-8-8-8-0-2",
                "status": ["active"],
                "remarks": None,
                "notices": [
                    {
                        "title": "Terms of Service",
                        "description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use",
                        "links": ["https://www.arin.net/resources/registry/whois/tou/"],
                    },
                    {
                        "title": "Whois Inaccuracy Reporting",
                        "description": "If you see inaccuracies in the results, please visit: ",
                        "links": [
                            "https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"
                        ],
                    },
                    {
                        "title": "Copyright Notice",
                        "description": "Copyright 1997-2025, American Registry for Internet Numbers, Ltd.",
                        "links": None,
                    },
                ],
                "links": [
                    "https://rdap.arin.net/registry/ip/8.8.8.0",
                    "https://whois.arin.net/rest/net/NET-8-8-8-0-2",
                ],
                "events": [
                    {
                        "action": "last changed",
                        "timestamp": "2023-12-28T17:24:56-05:00",
                        "actor": None,
                    },
                    {
                        "action": "registration",
                        "timestamp": "2023-12-28T17:24:33-05:00",
                        "actor": None,
                    },
                ],
                "raw": None,
                "start_address": "8.8.8.0",
                "end_address": "8.8.8.255",
                "cidr": "8.8.8.0/24",
                "ip_version": "v4",
                "type": "DIRECT ALLOCATION",
                "name": "GOGL",
                "country": None,
                "parent_handle": "NET-8-0-0-0-0",
            },
            "entities": ["GOGL"],
            "objects": {
                "GOGL": {
                    "handle": "GOGL",
                    "status": None,
                    "remarks": [
                        {
                            "title": "Registration Comments",
                            "description": "Please note that the recommended way to file abuse complaints are located in the following links. \n\nTo report abuse and illegal activity: https://www.google.com/contact/\n\nFor legal requests: http://support.google.com/legal \n\nRegards, \nThe Google Team",
                            "links": None,
                        }
                    ],
                    "notices": None,
                    "links": [
                        "https://rdap.arin.net/registry/entity/GOGL",
                        "https://whois.arin.net/rest/org/GOGL",
                    ],
                    "events": [
                        {
                            "action": "last changed",
                            "timestamp": "2019-10-31T15:45:45-04:00",
                            "actor": None,
                        },
                        {
                            "action": "registration",
                            "timestamp": "2000-03-30T00:00:00-05:00",
                            "actor": None,
                        },
                    ],
                    "raw": None,
                    "roles": ["registrant"],
                    "contact": {
                        "name": "Google LLC",
                        "kind": "org",
                        "address": [
                            {
                                "type": None,
                                "value": "1600 Amphitheatre Parkway\nMountain View\nCA\n94043\nUnited States",
                            }
                        ],
                        "phone": None,
                        "email": None,
                        "role": None,
                        "title": None,
                    },
                    "events_actor": None,
                    "entities": ["ABUSE5250-ARIN", "ZG39-ARIN"],
                }
            },
            "raw": None,
        },
        "text": '{"asn": "15169", "asn_cidr": "8.8.8.0/24", "asn_country_code": "US", "asn_date": "2023-12-28", "asn_description": "GOOGLE, US", "asn_registry": "arin", "entities": ["GOGL"], "network": {"cidr": "8.8.8.0/24", "country": null, "end_address": "8.8.8.255", "events": [{"action": "last changed", "actor": null, "timestamp": "2023-12-28T17:24:56-05:00"}, {"action": "registration", "actor": null, "timestamp": "2023-12-28T17:24:33-05:00"}], "handle": "NET-8-8-8-0-2", "ip_version": "v4", "links": ["https://rdap.arin.net/registry/ip/8.8.8.0", "https://whois.arin.net/rest/net/NET-8-8-8-0-2"], "name": "GOGL", "notices": [{"description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use", "links": ["https://www.arin.net/resources/registry/whois/tou/"], "title": "Terms of Service"}, {"description": "If you see inaccuracies in the results, please visit: ", "links": ["https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"], "title": "Whois Inaccuracy Reporting"}, {"description": "Copyright 1997-2025, American Registry for Internet Numbers, Ltd.", "links": null, "title": "Copyright Notice"}], "parent_handle": "NET-8-0-0-0-0", "raw": null, "remarks": null, "start_address": "8.8.8.0", "status": ["active"], "type": "DIRECT ALLOCATION"}, "nir": null, "objects": {"GOGL": {"contact": {"address": [{"type": null, "value": "1600 Amphitheatre Parkway\\nMountain View\\nCA\\n94043\\nUnited States"}], "email": null, "kind": "org", "name": "Google LLC", "phone": null, "role": null, "title": null}, "entities": ["ABUSE5250-ARIN", "ZG39-ARIN"], "events": [{"action": "last changed", "actor": null, "timestamp": "2019-10-31T15:45:45-04:00"}, {"action": "registration", "actor": null, "timestamp": "2000-03-30T00:00:00-05:00"}], "events_actor": null, "handle": "GOGL", "links": ["https://rdap.arin.net/registry/entity/GOGL", "https://whois.arin.net/rest/org/GOGL"], "notices": null, "raw": null, "remarks": [{"description": "Please note that the recommended way to file abuse complaints are located in the following links. \\n\\nTo report abuse and illegal activity: https://www.google.com/contact/\\n\\nFor legal requests: http://support.google.com/legal \\n\\nRegards, \\nThe Google Team", "links": null, "title": "Registration Comments"}], "roles": ["registrant"], "status": null}}, "query": "8.8.8.8", "raw": null}',
    },
    "text": '{"asn": "15169", "asn_cidr": "8.8.8.0/24", "asn_country_code": "US", "asn_date": "2023-12-28", "asn_description": "GOOGLE, US", "asn_registry": "arin", "entities": ["GOGL"], "network": {"cidr": "8.8.8.0/24", "country": null, "end_address": "8.8.8.255", "events": [{"action": "last changed", "actor": null, "timestamp": "2023-12-28T17:24:56-05:00"}, {"action": "registration", "actor": null, "timestamp": "2023-12-28T17:24:33-05:00"}], "handle": "NET-8-8-8-0-2", "ip_version": "v4", "links": ["https://rdap.arin.net/registry/ip/8.8.8.0", "https://whois.arin.net/rest/net/NET-8-8-8-0-2"], "name": "GOGL", "notices": [{"description": "By using the ARIN RDAP/Whois service, you are agreeing to the RDAP/Whois Terms of Use", "links": ["https://www.arin.net/resources/registry/whois/tou/"], "title": "Terms of Service"}, {"description": "If you see inaccuracies in the results, please visit: ", "links": ["https://www.arin.net/resources/registry/whois/inaccuracy_reporting/"], "title": "Whois Inaccuracy Reporting"}, {"description": "Copyright 1997-2025, American Registry for Internet Numbers, Ltd.", "links": null, "title": "Copyright Notice"}], "parent_handle": "NET-8-0-0-0-0", "raw": null, "remarks": null, "start_address": "8.8.8.0", "status": ["active"], "type": "DIRECT ALLOCATION"}, "nir": null, "objects": {"GOGL": {"contact": {"address": [{"type": null, "value": "1600 Amphitheatre Parkway\\nMountain View\\nCA\\n94043\\nUnited States"}], "email": null, "kind": "org", "name": "Google LLC", "phone": null, "role": null, "title": null}, "entities": ["ABUSE5250-ARIN", "ZG39-ARIN"], "events": [{"action": "last changed", "actor": null, "timestamp": "2019-10-31T15:45:45-04:00"}, {"action": "registration", "actor": null, "timestamp": "2000-03-30T00:00:00-05:00"}], "events_actor": null, "handle": "GOGL", "links": ["https://rdap.arin.net/registry/entity/GOGL", "https://whois.arin.net/rest/org/GOGL"], "notices": null, "raw": null, "remarks": [{"description": "Please note that the recommended way to file abuse complaints are located in the following links. \\n\\nTo report abuse and illegal activity: https://www.google.com/contact/\\n\\nFor legal requests: http://support.google.com/legal \\n\\nRegards, \\nThe Google Team", "links": null, "title": "Registration Comments"}], "roles": ["registrant"], "status": null}}, "query": "8.8.8.8", "raw": null}',
    "type": "ip",
}
