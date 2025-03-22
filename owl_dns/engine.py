from base_engine.base_engine import Engine, Issue
from metadatas import Metadatas, Options
import concurrent.futures
import os
import sys
import utils
import json
from typing import Any, Generator
import json
import parsers


class OwlDNS(Engine):
    def load_config(self, metadatas: Metadatas):
        sys.path.append(metadatas.sublist3r_bin_path)

        with open(metadatas.seg_path) as seg_providers_file:
            self.seg_providers = json.loads(seg_providers_file.read())["seg"]
        # DnsTwist(engine.scanner["dnstwist_bin_path"])

    def start_scan(self, options: Options) -> Generator[dict | list[dict], Any, None]:
        # Useless to do these two checks
        if options.do_whois and options.do_advanced_whois:
            options.do_advanced_whois = False

        with concurrent.futures.ThreadPoolExecutor(os.cpu_count() or 4) as executor:
            future_to_asset = {}

            def _submit_task(func, asset, parser, *args, **kwargs):
                future = executor.submit(func, asset.value, *args, **kwargs)
                future_to_asset[future] = (asset.value, parser)

            # Scan according to options
            for asset in options.assets:
                # Whois
                if options.do_whois and asset.datatype in ["domain", "ip", "fqdn"]:
                    _submit_task(utils.get_whois, asset, parsers.parse_whois)
                # Whois only on domains
                if options.do_advanced_whois and asset.datatype == "domain":
                    _submit_task(utils.get_whois, asset, parsers.parse_advanced_whois)

                # Subdomains
                if options.do_subdomain_enum and asset.datatype == "domain":
                    _submit_task(
                        utils.subdomain_enum,
                        asset,
                        parsers.parse_subdomains(options.subdomain_as_new_asset),
                        options.do_subdomains_resolve,
                    )
                if options.do_subdomains_bruteforce and asset.datatype == "domain":
                    pass
                # DNS Checks
                if options.do_dns_resolve and asset.datatype == "domain":
                    _submit_task(
                        utils.dns_resolve_asset, asset, parsers.parse_dns_resolve
                    )
                if options.do_dns_transfer and asset.datatype == "domain":
                    _submit_task(
                        utils.do_dns_transfer, asset, parsers.parse_dns_transfer
                    )
                if options.do_dns_recursive and asset.datatype == "domain":
                    _submit_task(
                        utils.do_dns_recursive, asset, parsers.parse_dns_recursive
                    )

                # Seg check
                if options.do_seg_check and asset.datatype in ["domain", "fqdn"]:
                    _submit_task(
                        utils.do_seg_check, asset, parsers.parse_seg, self.seg_providers
                    )

                # SPF check TODO
                if options.do_spf_check and asset.datatype == "domain":
                    _submit_task(utils.do_spf_check, asset, parsers.parse_spf)

                # DKIM check
                if options.do_dkim_check and asset.datatype == "domain":
                    _submit_task(utils.do_dkim_check, asset, parsers.parse_dkim)

                # DMARC check
                if options.do_dmarc_check and asset.datatype == "domain":
                    _submit_task(utils.do_dmarc_check, asset, parsers.parse_dmarc)

            self.logger.debug(f"Number of tasks to process: {len(future_to_asset)}")
            # Get tasks results
            for future in concurrent.futures.as_completed(future_to_asset):
                asset_value, parser = future_to_asset[future]
                try:
                    result = future.result()
                    if result:
                        yield parser(asset_value, result)
                    else:
                        continue
                except Exception as e:
                    self.logger.error(f"Error during parsing", e)


engine = OwlDNS(Options, Metadatas)

if __name__ == "__main__":
    engine.start()
