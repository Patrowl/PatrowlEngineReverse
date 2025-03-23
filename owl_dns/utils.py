import sys
import json
import dns.zone
import dns.resolver
import dns
import dns.message
import dns.flags
import dns.query
import socket
import validators
import whois
from ipwhois import IPWhois
import re
import parsers
from etc.issues import spf_issues


def __is_ip_addr(host):
    res = False
    try:
        res = socket.gethostbyname(host) == host
    except Exception as e:
        print(f"__is_ip_addr({host}): failed: {e}")
    return res


def __is_domain(host):
    res = False
    try:
        res = validators.domain(host) is True
    except Exception as e:
        print(f"__is_domain({host}): failed: {e}")
    return res


def get_whois(asset):
    if not (__is_domain(asset) or __is_ip_addr(asset)):
        return {}

    return _get_whois_domain(asset) if __is_domain(asset) else _get_whois_ip(asset)


def _get_whois_domain(domain):
    try:
        w = whois.whois(domain)
        if w.domain_name is None:
            return {"errors": w}
        return {
            "raw": {"dict": w, "text": w.text},
            "type": "domain",
        }

    except Exception as e:
        return {domain: {"errors": str(e)}}


def _get_whois_ip(ip):
    try:
        w = IPWhois(ip.strip()).lookup_rdap()
        w_text = json.dumps(w, sort_keys=True) if w else "see raw"
    except Exception:
        w_text = "see raw"

    return {
        "raw": {"dict": w, "text": w_text},
        "type": "ip",
    }


def subdomain_enum(asset, resolve):
    sublist3r = __import__("sublist3r")

    # check the asset is a valid domain name
    if not __is_domain(asset):
        return {}
    res = {}
    try:
        res["subdomains_list"] = sublist3r.main(
            asset,
            1,
            None,
            ports=None,
            silent=True,
            verbose=True,
            enable_bruteforce=False,
            engines=None,
        )
    except Exception as e:
        return {"error": f"Sublist3r failed: {e}"}

    if resolve:
        res["subdomains_resolve"] = {
            s: data for s in res["subdomains_list"] if (data := dns_resolve_asset(s))
        }

    return res


def dns_resolve_asset(
    asset: str, type_of_record: str = None
) -> list[dict[str, str | list[str]]]:
    resolver = dns.resolver.Resolver()
    resolver.nameservers = "8.8.8.8,8.8.4.4,1.1.1.1".split(",")
    res = []
    record_types = ["CNAME", "A", "AAAA", "MX", "NS", "TXT", "SOA", "SRV"]
    if type_of_record:
        record_types = [type_of_record]
    for record_type in record_types:
        try:
            answers = resolver.resolve(asset, record_type)
            # print([str(rdata) for rdata in answers])
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.Timeout:
            pass
        except dns.resolver.NXDOMAIN:
            pass
        except Exception as e:
            pass
            # print(f"DNS resolve raises an exception for asset '{asset}'", e)
        else:
            res.append(
                {
                    "record_type": record_type,
                    "values": [
                        str(rdata).strip('"').replace('" "', " ") for rdata in answers
                    ],
                    "answers": [str(rdata) for rdata in answers],
                }
            )
    return res


def do_dns_transfer(asset: str):
    """Check if asset is vulnerable to DNS Zone Tranfer.

    A DNS zone transfer vulnerability occurs when an attacker gains
    unauthorized access to a DNS server's zone file, allowing them to modify
    or extract sensitive information about a domain.
    """
    # asset = "zonetransfer.me" # For testing purpose
    try:
        ns_answer = dns.resolver.resolve(asset, "NS")
        zone_hosts = set()

        for server in ns_answer:
            try:
                ip_answer = dns.resolver.resolve(server.target, "A")
                for ip in ip_answer:
                    try:
                        zone = dns.zone.from_xfr(dns.query.xfr(str(ip), asset))
                        zone_hosts.update(str(host) for host in zone)
                    except Exception:
                        continue
            except dns.resolver.NoAnswer:
                continue

        if zone_hosts:
            return {"hosts": list(zone_hosts), "response": ns_answer.response.to_text()}
    except dns.resolver.NXDOMAIN:
        return f"Domain {asset} does not exist"
    except dns.exception.DNSException as e:
        return f"DNS error: {e}"

    return None


def is_dns_recursive(ip: str) -> dict:
    """Check if a DNS server allows recursive queries by querying a random domain."""
    try:
        query = dns.message.make_query("google.com", dns.rdatatype.A)
        query.flags |= dns.flags.RD  # Set the RD (Recursion Desired) flag
        response = dns.query.udp(query, str(ip), timeout=5)
        # Check if the RA (Recursion Available) flag is set and there's a valid answer
        if response.flags & dns.flags.RA and len(response.answer) > 0:
            return {
                "response": response.to_text(),
                "flags": dns.flags.to_text(response.flags),
            }
    except Exception:
        pass  # Failure to resolve implies secure configuration
    return None


def do_dns_recursive(asset: str):
    """Check if the DNS server allows recursive queries.

    A server allowing recursive queries from external clients is considered
    misconfigured.
    """
    dns_recursive_issues = None
    try:
        # Resolve the A record for the asset (domain)
        ip_answer = dns.resolver.resolve(asset)
    except Exception:
        return dns_recursive_issues

    # Iterate over all the IPs associated with the asset
    for ip in ip_answer:
        dns_recursive_issues = is_dns_recursive(str(ip))
        if dns_recursive_issues:
            return dns_recursive_issues

    return dns_recursive_issues


def find_seg_provider_for_mx_record(dns_value, seg_providers):
    """Find matching SEG provider based on MX record."""
    for seg_provider, seg_data in seg_providers.items():
        for mx_record in seg_data["mx_records"]:
            if dns_value.endswith(mx_record):
                return {seg_provider: seg_data}
    return None


def do_seg_check(asset_value, seg_providers):
    """Check if Secure Email Gateway (SEG) is configured based on MX records."""
    dns_records = dns_resolve_asset(asset_value, "MX")

    if not dns_records:
        return {"failed": "no MX records found"}

    seg_dict = []
    for dns_record in dns_records:
        for dns_value in dns_record.get("values", []):
            seg_provider_data = find_seg_provider_for_mx_record(
                dns_value, seg_providers
            )
            if seg_provider_data:
                seg_dict.append(seg_provider_data)

    if seg_dict:
        return {"seg_dict": seg_dict, "seg_dict_dns_records": dns_records}
    else:
        return {"no_seg": "MX records found but no Secure Email Gateway set"}


def do_spf_check(asset_value: str):
    """Check SPF record lookup"""
    res = {}

    dns_txt_records = dns_resolve_asset(asset_value, "TXT")
    answers = dns_txt_records[0].get("answers") if dns_txt_records else []
    res["txt_records"] = answers

    # Parses SPF records
    parsed_spf_record, issues = parsers.parse_spf_record(answers)
    res["parsed_spf_record"] = parsed_spf_record
    res["issues"] = issues

    dns_spf_records = dns_resolve_asset(asset_value, "SPF")
    if dns_spf_records:
        res["issues"].append(spf_issues.DEPRECATED_SPF_RECORD)

    dns_lookup_limit = 10
    try:
        dns_lookup_count, spf_lookup_records = get_lookup_count_and_spf_records(
            domain=asset_value
        )
    except RecursionError:
        res["issues"].append(
            dict(
                spf_issues.DNS_LOOKUP_LIMIT,
                extra_info=f"More than {sys.getrecursionlimit()} DNS lookups are required to validate SPF record.",
            )
        )

    else:
        if dns_lookup_count > dns_lookup_limit:
            res["issues"].append(
                dict(
                    spf_issues.DNS_LOOKUP_LIMIT,
                    value=spf_lookup_records[0] if spf_lookup_records else "",
                    extra_info=f"{dns_lookup_count} DNS lookups are required to validate SPF record.",
                )
            )
    return res


def do_dmarc_check(asset_value):
    dmarc_dict = {"no_dmarc_record": "info"}
    dns_records = dns_resolve_asset(asset_value, "TXT")
    for record in dns_records:
        for value in record["values"]:
            if "DMARC" in value:
                dmarc_dict.pop("no_dmarc_record")
                if "p=none" in value:
                    dmarc_dict["insecure_dmarc_policy"] = "high"
                if "sp=none" in value:
                    dmarc_dict["insecure_dmarc_subdomain_sp"] = "high"
                for word in value.split(" "):
                    if "pct=" in word:
                        num = int(re.sub("\D", "", word))
                        if num < 100:
                            dmarc_dict["dmarc_partial_coverage"] = "medium"

    return {"dmarc_dict": dmarc_dict, "dmarc_dict_dns_records": dns_records}


def do_dkim_check(asset_value):
    dkimlist = [
        "s1",
        "s2",
        "selector1",
        "selector2",
        "everlytickey1",
        "everlytickey2",
        "eversrv",
        "k1",
        "mxvault",
        "dkim",
    ]

    dkim_dict = {}
    found_dkim = False
    dkim_found_list = {}
    for selector in dkimlist:
        dkim_record = selector + "._domainkey." + asset_value
        dns_records = dns_resolve_asset(dkim_record)
        if len(dns_records) > 0:
            found_dkim = True
            for dns_record in dns_records:
                for value in dns_record["values"]:
                    dkim_found_list[selector] = value
    if not found_dkim:
        dkim_dict["dkim"] = "couldn't find the selector in our list"
    else:
        dkim_dict["dkim"] = dkim_found_list

    return {"dkim_dict": dkim_dict, "dkim_dict_dns_records": dns_records}


def get_lookup_count_and_spf_records(domain: str) -> tuple[int, list[tuple[str, str]]]:
    """Count the numbers of DNS queries during SPF evaluation and retrieve the SPF records

    The following terms cause DNS queries: the "include", "a", "mx", "ptr", and "exists" mechanisms, and the "redirect"
    modifier. SPF implementations MUST limit the total number of those terms to 10 during SPF evaluation, to avoid
    an unreasonable load on the DNS.

    :param domain: A domain name
    :return: Number of DNS queries during SPF evaluation, and the list of SPF records queried
    """
    dns_records = dns_resolve_asset(domain, "TXT")
    if not dns_records:
        return 0, []

    spf_records = list(
        filter(
            lambda dns_record: dns_record.lower().startswith("v=spf1"),
            dns_records[0].get("values"),
        )
    )
    if not spf_records:
        return 0, []

    spf_record = spf_records[0]
    lookup_domains = re.findall(
        r"\b[+\-~?]?(?:include:|redirect=)(\S+)\b", spf_record, re.IGNORECASE
    )
    other_terms_count = len(
        re.findall(r"\b[+\-~?]?(a|mx|ptr|exists):?\b", spf_record, re.IGNORECASE)
    )
    if not lookup_domains:
        return other_terms_count, [(domain, spf_record)]

    dns_lookup_count = len(lookup_domains) + other_terms_count
    spf_lookup_records = [(domain, spf_record)]
    for lookup_domain in lookup_domains:
        domain_dns_lookup_count, domain_spf_lookup_records = (
            get_lookup_count_and_spf_records(lookup_domain)
        )
        dns_lookup_count += domain_dns_lookup_count
        spf_lookup_records.extend(domain_spf_lookup_records)

    return dns_lookup_count, spf_lookup_records
