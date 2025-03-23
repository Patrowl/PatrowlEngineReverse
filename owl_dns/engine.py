from base_engine.base_engine import Engine
from metadatas import Metadatas, Options
import concurrent.futures
import os
import sys
import json
from typing import Any, Generator
import scanners


class OwlDNS(Engine):
    def load_config(self, metadatas: Metadatas):
        sys.path.append(metadatas.sublist3r_bin_path)

        with open(metadatas.seg_path) as seg_providers_file:
            self.seg_providers = json.loads(seg_providers_file.read())["seg"]

    def start_scan(self, options: Options) -> Generator[dict | list[dict], Any, None]:
        # Useless to do these two checks
        if options.do_whois and options.do_advanced_whois:
            options.do_advanced_whois = False

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=os.cpu_count() or 4
        ) as executor:
            future_to_asset = {}

            def _submit_task(func, asset, *args, **kwargs):
                future = executor.submit(func, asset.value, *args, **kwargs)
                future_to_asset[future] = asset.value

            # Scan according to options
            for asset in options.assets:
                # Whois
                if options.do_whois and asset.datatype in ["domain", "ip", "fqdn"]:
                    _submit_task(scanners.do_whois, asset)
                # Whois only on domains
                if options.do_advanced_whois and asset.datatype == "domain":
                    _submit_task(scanners.do_advanced_whois, asset)

                # Subdomains
                if options.do_subdomain_enum and asset.datatype == "domain":
                    _submit_task(
                        scanners.do_subdomain_enum,
                        asset,
                        options.do_subdomains_resolve,
                        options.subdomain_as_new_asset,
                    )
                if options.do_subdomains_bruteforce and asset.datatype == "domain":
                    pass
                # DNS Checks
                if options.do_dns_resolve and asset.datatype == "domain":
                    _submit_task(scanners.do_dns_resolve, asset)
                if options.do_dns_transfer and asset.datatype == "domain":
                    _submit_task(scanners.do_dns_transfer, asset)
                if options.do_dns_recursive and asset.datatype == "domain":
                    _submit_task(scanners.do_dns_recursive, asset)

                # Seg check
                if options.do_seg_check and asset.datatype in ["domain", "fqdn"]:
                    _submit_task(scanners.do_seg_check, asset, self.seg_providers)

                # SPF check
                if options.do_spf_check and asset.datatype == "domain":
                    _submit_task(scanners.do_spf_check, asset)

                # DKIM check
                if options.do_dkim_check and asset.datatype == "domain":
                    _submit_task(scanners.do_dkim_check, asset)

                # DMARC check
                if options.do_dmarc_check and asset.datatype == "domain":
                    _submit_task(scanners.do_dmarc_check, asset)

            self.logger.debug(f"Number of tasks to process: {len(future_to_asset)}")
            # Get tasks results
            for future in concurrent.futures.as_completed(future_to_asset):
                try:
                    result = future.result()
                    if result:
                        yield result
                except Exception as e:
                    self.logger.error("Error during parsing", e)


engine = OwlDNS(Options, Metadatas)

if __name__ == "__main__":
    engine.start()
