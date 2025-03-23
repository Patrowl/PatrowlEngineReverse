import utils
import parsers


def do_whois(asset):
    result = utils.get_whois(asset)
    return parsers.parse_whois(asset, result)


def do_advanced_whois(asset):
    result = utils.get_whois(asset)
    return parsers.parse_advanced_whois(asset, result)


def do_subdomain_enum(asset, resolve, create_new_assets):
    result = utils.subdomain_enum(asset, resolve)
    return parsers.parse_subdomains(asset, result, create_new_assets)


def do_dns_resolve(asset):
    result = utils.dns_resolve_asset(asset)
    return parsers.parse_dns_resolve(asset, result)


def do_dns_transfer(asset):
    result = utils.do_dns_transfer(asset)
    if result:
        return parsers.parse_dns_transfer(asset, result)
    return None


def do_dns_recursive(asset):
    result = utils.do_dns_recursive(asset)
    if result:
        return parsers.parse_dns_recursive(asset, result)
    return None


def do_seg_check(asset, seg_providers):
    result = utils.do_seg_check(asset, seg_providers)
    return parsers.parse_seg(asset, result)


def do_spf_check(asset):
    result = utils.do_spf_check(asset)
    return parsers.parse_spf(asset, result)


def do_dkim_check(asset):
    result = utils.do_dkim_check(asset)
    return parsers.parse_dkim(asset, result)


def do_dmarc_check(asset):
    result = utils.do_dmarc_check(asset)
    return parsers.parse_dmarc(asset, result)
