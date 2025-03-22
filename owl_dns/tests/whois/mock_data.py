from whois.parser import WhoisFr


def get_dummy_whois():
    return WhoisFr(
        domain="dummy.whois",
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
""",
    )
