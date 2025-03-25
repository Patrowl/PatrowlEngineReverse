import hashlib
import re
import datetime
from etc.issues.dns_issues import DNS_ZONE_TRANSFER, DNS_RECURSION_AVAILABLE
from etc.issues import spf_issues, dmarc_issues


def parse_whois(asset, result):
    if "errors" in result:
        return {
            "severity": "info",
            "confidence": "certain",
            "target": {"addr": [asset], "protocol": "domain"},
            "title": f"[Whois] No match for '{asset}'",
            "description": (
                f"No Whois data available for domain '{asset}'. "
                "Note that Whois is available for registered domains only (not sub-domains):\n"
                f"{result['errors']}"
            ),
            "solution": "n/a",
            "metadata": {"tags": ["whois"]},
            "type": "whois_domain_error",
            "raw": result["errors"],
        }

    else:
        whois_hash = hashlib.sha1(
            str(result["raw"]["text"]).encode("utf-8")
        ).hexdigest()[:6]
        return {
            "severity": "info",
            "confidence": "certain",
            "target": {"addr": [asset], "protocol": "domain"},
            "title": f"Whois info for '{asset}' (HASH: {whois_hash})",
            "description": f"Whois Info (raw):\n\n{result['raw']['text']}",
            "solution": "n/a",
            "metadata": {"tags": ["whois", result["type"]]},
            "type": f"whois_{result['type']}_fullinfo",
            "raw": result["raw"],
        }


def parse_subdomains(asset, result, create_new_assets):
    issues = []
    # subdomain resolve
    if "subdomains_resolve" in result.keys():
        for subdom in result["subdomains_resolve"].keys():
            subdom_resolve_str = ""
            for record in result["subdomains_resolve"][subdom]:
                entry = "Record type '{}': {}".format(
                    record["record_type"], ", ".join(record["values"])
                )
                subdom_resolve_str = "".join((subdom_resolve_str, entry + "\n"))

            subdom_resolve_hash = hashlib.sha1(
                subdom_resolve_str.encode("utf-8")
            ).hexdigest()[:6]

            raw_record = {
                "dns_record": result["subdomains_resolve"][subdom],
                "subdomain": subdom,
            }

            issues.append(
                {
                    "severity": "info",
                    "confidence": "certain",
                    "target": {
                        # "addr": [asset, subdom],
                        "addr": [asset],
                        "protocol": "domain",
                    },
                    "title": "DNS Resolution entries for '{}' (HASH: {})".format(
                        subdom, subdom_resolve_hash
                    ),
                    "description": "DNS Resolution entries for '{}':\n\n{}".format(
                        subdom, subdom_resolve_str
                    ),
                    "solution": "n/a",
                    "metadata": {"tags": ["dns", "resolution", "subdomain"]},
                    "type": "subdomains_resolve",
                    "raw": raw_record,
                }
            )
    # subdomain list
    # bad messages replied by Sublist3r
    bad_str = [
        "Go to http://PTRarchive.com for best",
        "Use http://PTRarchive.com, the engine",
        "Sublist3r recommends",
        "API count exceeded",
        "Too Many Requests",
        "error invalid host",
        "<",
        ">",
    ]
    if "subdomains_list" in result.keys():
        subdomains_str = ""
        subdomains_list = sorted(set(result["subdomains_list"]))
        subdomains_list_clean = []

        for subdomain in subdomains_list:
            subdomain = subdomain.strip().lower()
            if any(x in subdomain for x in bad_str) or subdomain.replace(" ", "") == "":
                continue
            s = subdomain.replace("From http://PTRarchive.com: ", "")
            subdomains_list_clean.append(s)
            subdomains_str = "".join((subdomains_str, s + "\n"))

            # New issue when a subdomain is found
            issues.append(
                {
                    "severity": "info",
                    "confidence": "certain",
                    "target": {
                        "addr": [s if create_new_assets else asset],
                        "protocol": "domain",
                    },
                    "title": "Subdomain found: {}".format(s),
                    "description": "Subdomain found:\n\n{}".format(s),
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "subdomain"]},
                    "type": "subdomain",
                    "raw": s,
                }
            )

        # New issue when on the domain list
        subdomains_hash = hashlib.sha1(subdomains_str.encode("utf-8")).hexdigest()[:6]
        if len(subdomains_list_clean) == 0:
            subdomains_list_clean = []

        issues.append(
            {
                "severity": "info",
                "confidence": "certain",
                "target": {"addr": [asset], "protocol": "domain"},
                "title": "List of subdomains for '{}' ({} found, HASH: {})".format(
                    asset, len(subdomains_list_clean), subdomains_hash
                ),
                "description": "Subdomain list for '{}': \n\n{}".format(
                    asset, subdomains_str
                ),
                "solution": "n/a",
                "metadata": {"tags": ["domains", "subdomains"]},
                "type": "subdomains_enum",
                "raw": subdomains_list_clean,
            }
        )

    return issues


def parse_dns_resolve(asset, result):
    dns_resolve_str = ""

    for record in result:
        entry = "Record type '{}': {}".format(
            record["record_type"], ", ".join(record["values"])
        )
        dns_resolve_str = "".join((dns_resolve_str, entry + "\n"))

    dns_resolve_hash = hashlib.sha1(dns_resolve_str.encode("utf-8")).hexdigest()[:6]

    return {
        "severity": "info",
        "confidence": "certain",
        "target": {"addr": [asset], "protocol": "domain"},
        "title": "DNS Resolution entries for '{}' (HASH: {})".format(
            asset, dns_resolve_hash
        ),
        "description": "DNS Resolution entries for '{}':\n\n{}".format(
            asset, dns_resolve_str
        ),
        "solution": "n/a",
        "metadata": {"tags": ["domains", "dns", "resolution"]},
        "type": "dns_resolve",
        "raw": result,
    }


def parse_seg(asset, result):
    if "seg_dict" in result.keys():
        seg_check = result.get("seg_dict")
        seg_check_dns_records = result.get("seg_dict_dns_records")
        results = []
        for seg in seg_check:
            seg_provider = list(seg.keys())[0]
            seg_title = (
                f"{seg[seg_provider]['provider']}/{seg[seg_provider]['product']}"
            )
            results.append(
                {
                    "severity": "info",
                    "confidence": "certain",
                    "target": {"addr": [asset], "protocol": "domain"},
                    "title": f"Secure Email Gateway found: {seg_title}",
                    "description": f"{seg}\n",
                    "solution": "n/a",
                    "metadata": {"tags": ["domains", "seg"]},
                    "type": "seg_check",
                    "raw": {"provider": seg, "mx_records": seg_check_dns_records},
                }
            )

        return results

    if "no_seg" in result.keys():
        seg_check_failed = result.get("no_seg")
        return {
            "severity": "info",
            "confidence": "certain",
            "target": {"addr": [asset], "protocol": "domain"},
            "title": "No Secure Email Gateway found",
            "description": f"{seg_check_failed}\n",
            "solution": "n/a",
            "metadata": {"tags": ["domains", "no_seg"]},
            "type": "seg_check",
            "raw": seg_check_failed,
        }


def parse_dkim(asset, result):
    if not result:
        return None

    issues = []
    dkim_check = result["dkim_dict"]
    dkim_check_dns_records = result["dkim_dict_dns_records"]
    dkim_hash = hashlib.sha1(str(dkim_check_dns_records).encode("utf-8")).hexdigest()[
        :6
    ]

    issues.append(
        {
            "severity": "info",
            "confidence": "certain",
            "target": {"addr": [asset], "protocol": "domain"},
            "title": "DKIM check for '{}' (HASH: {})".format(asset, dkim_hash),
            "description": "DKIM check for '{asset}':\n\n{}".format(
                asset, str(dkim_check)
            ),
            "solution": "n/a",
            "metadata": {"tags": ["domains", "dkim"]},
            "type": "dkim_check",
            "raw": result["dkim_dict"],
        }
    )

    return issues


def parse_dmarc(asset, result):
    if not result:
        return None
    issues = []
    dmarc_check = result["dmarc_dict"]
    dmarc_check_dns_records = result["dmarc_dict_dns_records"]
    print("dmarc_check", dmarc_check)
    print("dmarc_check_dns_records", dmarc_check_dns_records)

    def _build_issue(issue, value=""):
        return {
            "target": {"addr": [asset], "protocol": "domain"},
            "metadata": {"tags": ["domains", "dmarc"]},
            "type": "dmarc_check",
            "raw": dmarc_check_dns_records,
            **issue,
            "description": issue["description"].format(value=value),
        }

    if "multiple_dmarc" in dmarc_check:
        return _build_issue(dmarc_issues.DMARC_MULTIPLE_RECORDS)

    if "no_dmarc_record" in dmarc_check:
        issues.append(_build_issue(dmarc_issues.NO_DMARC))
    if "insecure_dmarc_policy" in dmarc_check:
        issues.append(
            _build_issue(
                dmarc_issues.DMARC_LAX_POLICY, dmarc_check["insecure_dmarc_policy"]
            )
        )
    if "insecure_dmarc_subdomain_sp" in dmarc_check:
        issues.append(
            _build_issue(
                dmarc_issues.DMARC_LAX_SUBDOMAIN_POLICY,
                dmarc_check["insecure_dmarc_subdomain_sp"],
            )
        )
    if "dmarc_partial_coverage" in dmarc_check:
        issues.append(
            _build_issue(
                dmarc_issues.DMARC_NOT_100_PCT, dmarc_check["dmarc_partial_coverage"]
            )
        )

    if "dmarc_reporting" not in dmarc_check:
        issues.append(_build_issue(dmarc_issues.DMARC_NO_REPORTING))

    if "dmarc_malformed" in dmarc_check:
        issues.append(
            _build_issue(
                dmarc_issues.DMARC_MISCONFIGURED, dmarc_check["dmarc_malformed"]
            )
        )

    return issues


def parse_dns_transfer(asset, result):
    if not result:
        return None
    issue = dict(DNS_ZONE_TRANSFER)
    description = issue.get("description", "")
    if "hosts" in result:
        hosts_with_newlines = "\n".join(result["hosts"])
        description += f"\n\nTransferred subdomains:\n{hosts_with_newlines}"
    if "response" in result:
        description += f"\n\nDNS response:\n{result['response']}"
    return {
        "severity": issue.get("severity", "info"),
        "confidence": issue.get("confidence", "certain"),
        "target": {"addr": [asset], "protocol": "domain"},
        # "title": f"DNS Zone Transfer detected: {len(dns_transfer_hosts)} host(s)",
        "title": issue.get("title"),
        # "description": f"DNS Zone Transfer:\n'{dns_transfer_hosts_txt}'",
        "description": description,
        "solution": issue.get("solution", ""),
        "metadata": {"tags": ["tranfert_zone"]},
        "type": "dns_transfer",
        "raw": result,
    }


def parse_dns_recursive(asset, result):
    if not result:
        return None
    # Done DNS Recursive check ?
    issue = dict(DNS_RECURSION_AVAILABLE)
    description = issue.get("description", "")
    if "flags" in result:
        description += f"\n\nDNS flags:\n{result['flags']}"
    if "response" in result:
        description += f"\n\nDNS response:\n{result['response']}"
    return {
        "severity": issue.get("severity", "info"),
        "confidence": issue.get("confidence", "certain"),
        "target": {"addr": [asset], "protocol": "domain"},
        "title": issue.get("title"),
        "description": description,
        "solution": issue.get("solution", ""),
        "metadata": {"tags": ["dns_recursive"]},
        "type": "dns_recursive",
        "raw": result,
    }


def parse_spf(asset, result):
    # print(asset, result)
    issues = []
    issues_from_spf_check = result["issues"]
    parsed_spf_record = result["parsed_spf_record"]

    for spf_issue in issues_from_spf_check:
        description = spf_issue.get("description")
        if spf_issue.get("value"):
            description += f"\n\nThe SPF record is: {spf_issue['value']}"
        if spf_issue.get("extra_info"):
            description += f"\n\n{spf_issue['extra_info']}"

        issues.append(
            {
                "severity": spf_issue.get("severity", "info"),
                "confidence": spf_issue.get("confidence", "certain"),
                "target": {"addr": [asset], "protocol": "domain"},
                "title": spf_issue.get("title"),
                "description": description,
                "solution": spf_issue.get("solution"),
                "metadata": {"tags": ["domains", "spf"]},
                "type": "spf_check",
                "raw": {
                    "description": spf_issue.get("description"),
                    "solution": spf_issue.get("solution"),
                    "parsed": parsed_spf_record,
                    "value": spf_issue.get("value"),
                    "extra_info": spf_issue.get("extra_info"),
                },
            }
        )
    return issues


def parse_advanced_whois(asset, result):
    issues = [parse_whois(asset, result)]

    if "errors" in result.keys():
        return issues

    def _create_whois_issue(info):
        return {
            "severity": "info",
            "confidence": "certain",
            "target": {"addr": [asset], "protocol": "domain"},
            "solution": "n/a",
            "metadata": {"tags": ["whois"]},
            **info,
        }

    # status
    whois_statuses = ",\n".join(result["raw"]["dict"]["status"])
    issues.append(
        _create_whois_issue(
            {
                "type": "whois_domain_status",
                "title": "[Whois] '{}' domain has status '{}'".format(
                    asset, result["raw"]["dict"]["status"][0]
                ),
                "description": "[Whois] '{}' domain has status '{}'".format(
                    asset, whois_statuses
                ),
                "raw": result["raw"]["dict"]["status"],
            }
        )
    )

    # registrar
    whois_reginfo = "Name: {}\n".format(result["raw"]["dict"]["registrar"])
    whois_reginfo += "ID: {}\n".format(result["raw"]["dict"].get("registrar_id", ""))
    whois_reginfo += "URL(s): {}\n".format(
        ", ".join(result["raw"]["dict"].get("registrar_url", ""))
    )

    issues.append(
        _create_whois_issue(
            {
                "type": "whois_registrar",
                "title": "[Whois] '{}' domain registrar is '{}'".format(
                    asset, result["raw"]["dict"]["registrar"]
                ),
                "description": "[Whois] '{}' domain registrar is '{}': \n{}".format(
                    asset,
                    result["raw"]["dict"]["registrar"],
                    whois_reginfo,
                ),
                "raw": result["raw"]["dict"]["registrar"],
            }
        )
    )

    # emails
    if "emails" in result["raw"]["dict"].keys() and result["raw"]["dict"]["emails"]:
        issues.append(
            _create_whois_issue(
                {
                    "type": "whois_emails",
                    "title": "[Whois] '{}' domain contact emails are set.".format(
                        asset
                    ),
                    "description": "[Whois] '{}' domain contact emails are:\n'{}'".format(
                        asset,
                        ", ".join(result["raw"]["dict"]["emails"]),
                    ),
                    "raw": result["raw"]["dict"]["emails"],
                }
            )
        )

    # nameservers
    issues.append(
        _create_whois_issue(
            {
                "type": "whois_nameservers",
                "title": "[Whois] '{}' domain nameservers are set.".format(asset),
                "description": "[Whois] '{}' domain nameservers are:\n{}".format(
                    asset,
                    ",\n".join(result["raw"]["dict"]["name_servers"]),
                ),
                "raw": result["raw"]["dict"]["name_servers"],
            }
        )
    )
    updated_date = result["raw"]["dict"]["updated_date"]
    update_dates = (
        [updated_date] if not isinstance(updated_date, list) else updated_date
    )
    # updated_date

    issues.append(
        _create_whois_issue(
            {
                "type": "whois_update_dates",
                "title": "[Whois] '{}' domain was lastly updated the '{}'".format(
                    asset,
                    max(update_dates).date().isoformat(),
                ),
                "description": "[Whois] '{}' domain was updated at the following dates: \n\n{}".format(
                    asset, ", ".join(str(v) for v in update_dates)
                ),
                "raw": result["raw"]["dict"]["updated_date"],
            }
        )
    )

    # creation_date
    issues.append(
        _create_whois_issue(
            {
                "type": "whois_creation_dates",
                "title": "[Whois] '{}' domain was lastly created the '{}'".format(
                    asset,
                    (result["raw"]["dict"]["creation_date"]).date().isoformat(),
                ),
                "description": "[Whois] '{}' domain was created at the following dates: \n\n{}".format(
                    asset, (result["raw"]["dict"]["creation_date"])
                ),
                "raw": result["raw"]["dict"]["creation_date"],
            }
        )
    )

    # expiry date
    issues.append(
        _create_whois_issue(
            {
                "type": "whois_expiration_dates",
                "title": "[Whois] '{}' domain is registred until '{}'".format(
                    asset,
                    result["raw"]["dict"]["expiration_date"].date().isoformat(),
                ),
                "description": "[Whois] '{}' domain is registred until '{}'".format(
                    asset,
                    result["raw"]["dict"]["expiration_date"].date().isoformat(),
                ),
                "raw": result["raw"]["dict"]["expiration_date"],
            }
        )
    )

    # Raise alarms at 6 months (low), 3 months (medium), 2 weeks (high) or when expired (high)
    exp_date = result["raw"]["dict"]["expiration_date"]
    six_month_later = datetime.datetime.now() + datetime.timedelta(days=365 / 2)
    three_month_later = datetime.datetime.now() + datetime.timedelta(days=90)
    two_weeks_later = datetime.datetime.now() + datetime.timedelta(days=15)

    if exp_date < datetime.datetime.now():
        issues.append(
            _create_whois_issue(
                {
                    "severity": "high",
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is expired since '{}'".format(
                        asset, exp_date.date().isoformat()
                    ),
                    "description": "[Whois] '{}' domain is expired since '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                        asset,
                        exp_date.date().isoformat(),
                        ", ".join(exp_date.date().isoformat()),
                    ),
                    "raw": result["raw"]["dict"]["expiration_date"],
                    "solution": "Renew the domain",
                }
            )
        )
    elif exp_date < two_weeks_later:
        issues.append(
            _create_whois_issue(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "high",
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)".format(
                        asset, exp_date.date().isoformat()
                    ),
                    "description": "[Whois] '{}' domain is registred until '{}' (less than 2 weeks)\n\nAll dates in record: {}".format(
                        asset,
                        exp_date.date().isoformat(),
                        ", ".join(exp_date.date().isoformat()),
                    ),
                    "raw": result["raw"]["dict"]["expiration_date"],
                    "solution": "Renew the domain",
                }
            )
        )
    elif exp_date < three_month_later:
        issues.append(
            _create_whois_issue(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "medium",
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is registred until '{}' (less than 3 months)".format(
                        asset, exp_date.date().isoformat()
                    ),
                    "description": "[Whois] '{}' domain is registred until '{}' (less than 3 months)\n\nAll dates in record: {}".format(
                        asset,
                        exp_date.date().isoformat(),
                        ", ".join(exp_date.date().isoformat()),
                    ),
                    "raw": result["raw"]["dict"]["expiration_date"],
                    "solution": "Renew the domain",
                }
            )
        )
    elif exp_date < six_month_later:
        issues.append(
            _create_whois_issue(
                {
                    "issue_id": len(issues) + 1,
                    "severity": "low",
                    "type": "whois_expiration_dates",
                    "title": "[Whois] '{}' domain is registred until '{}' (less than 6 months)".format(
                        asset, exp_date.date().isoformat()
                    ),
                    "description": "[Whois] '{}' domain is registred until '{}' (less than 6 months)\n\nAll dates in record: {}".format(
                        asset,
                        exp_date.date().isoformat(),
                        ", ".join(exp_date.date().isoformat()),
                    ),
                    "raw": result["raw"]["dict"]["expiration_date"],
                    "solution": "Renew the domain",
                }
            )
        )
    return issues


def parse_spf_record(dns_records: list[str]) -> tuple[list, list]:
    # Basic mechanisms, they contribute to the language framework.
    # They do not specify a particular type of authorization scheme.
    basic_mechanisms = ["all", "include"]
    # Designated sender mechanisms, they are used to designate a set of <ip> addresses as being permitted or
    # not permitted to use the <domain> for sending mail.
    designed_sender_mechanisms = ["a", "mx", "ptr", "ip4", "ip6", "exists"]

    spf_record_count = 0
    parsed_spf_record = [["Qualifier", "Type", "Value"]]
    issues = []

    for dns_record in dns_records:
        value = dns_record.removeprefix('"').removesuffix('"').replace('" "', "")
        # Check the version
        if "v=spf1" not in value.lower():
            continue
        spf_record_count += 1

        # Issue: MALFORMED_SPF_RECORD
        if value[0] == " ":
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="There is an extra space before the start of the string.",
                )
            )
            value = value.lstrip(" ")
        # Check for extra spaces after the end of the string
        if value[-1] == " ":
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="There is an extra space after the end of the string.",
                )
            )
            value = value.rstrip(" ")
        # Check for quoted TXT record
        if value[0] == '"' or value[-1] == '"':
            issues.append(
                dict(
                    spf_issues.MALFORMED_SPF_RECORD,
                    value=value,
                    extra_info="The SPF record is surrounded quotation marks.",
                )
            )
            value = value.strip('"')

        # Issue: DIRECTIVES_AFTER_ALL
        directives_after_all = re.search(r"[-~?+]?all (.+)", value)
        if directives_after_all:
            issues.append(
                dict(
                    spf_issues.DIRECTIVES_AFTER_ALL,
                    value=value,
                    extra_info=f'These directives after "all" are ignored: {directives_after_all.group(1)}.',
                )
            )

        # Issue: STRING_TOO_LONG
        maximum_string_length = 255
        for character_string in dns_record.strip('"').split('" "'):
            if len(character_string) > maximum_string_length:
                issues.append(
                    dict(
                        spf_issues.STRING_TOO_LONG,
                        value=value,
                        extra_info=f"This part is {len(character_string)} characters long, "
                        f"and therefore too long: {character_string}.",
                    )
                )
                continue

        # List of directives
        spf_directives = value.split()
        spf_directives.pop(0)  # version is not a directive, remove it from directives

        # Issue: MISS_SPF_RECORD_TERMINATION
        if not re.search(r"[-~?+]?(all|redirect=)", spf_directives[-1].lower()):
            issues.append(dict(spf_issues.MISS_SPF_RECORD_TERMINATION, value=value))

        for spf_directive in spf_directives:
            directive_qualifier = "+"  # qualifier is optional, and defaults to "+"
            directive_value = ""
            if "=" in spf_directive:  # Modifiers, and not mechanisms
                directive_type, directive_value = spf_directive.split("=")
                directive_type = directive_type.lower()
                directive_value = directive_value.lower()
                parsed_spf_record.append(
                    [directive_qualifier, directive_type, directive_value]
                )
                # Unrecognized modifiers MUST be ignored
                continue
            if ":" in spf_directive:  # Mechanisms with value
                directive_type, directive_value = spf_directive.split(":")
                directive_type = directive_type.lower()
                directive_value = directive_value.lower()
            else:  # Mechanisms without value
                directive_type = spf_directive.lower()
            if directive_type.startswith(("-", "~", "?", "+")):
                directive_qualifier = directive_type[0]
                directive_type = directive_type[1:].lower()

            if directive_type not in basic_mechanisms + designed_sender_mechanisms:
                issues.append(
                    dict(
                        spf_issues.MALFORMED_SPF_RECORD,
                        value=value,
                        extra_info=f"'{directive_type}' is an illegal term.",
                    )
                )

            if directive_type == "ptr":
                issues.append(dict(spf_issues.PRESENCE_OF_PTR, value=value))
            elif directive_type == "all" and directive_qualifier in ["?", "+"]:
                issues.append(dict(spf_issues.PERMISSIVE_SPF_RECORD, value=value))

            parsed_spf_record.append(
                [directive_qualifier, directive_type, directive_value]
            )

    # Issue: NO_SPF_RECORD
    if spf_record_count == 0:
        issues.append(
            dict(
                spf_issues.NO_SPF_RECORD,
                extra_info=(
                    f"Other DNS TXT records are: {', '.join(dns_records)}."
                    if dns_records
                    else "There is no DNS TXT record."
                ),
            )
        )
    # Issue: MULTIPLE_SPF_RECORDS
    elif spf_record_count > 1:
        issues.append(
            dict(
                spf_issues.MULTIPLE_SPF_RECORDS,
                extra_info=f"Other DNS TXT records are: {', '.join(dns_records)}.",
            )
        )
    # Info: SPF_RECORD_SET
    else:
        issues.append(spf_issues.SPF_RECORD_SET)

    return parsed_spf_record, issues
