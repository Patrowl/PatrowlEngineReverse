from base_engine.base_engine import Engine
from metadatas import Metadatas, Options
import concurrent.futures
import os
import sys
import json
from typing import Any, Generator
from src import scanners
from base_engine.custom_logger import logger


class OwlDNS(Engine):
    def load_config(self, metadatas: Metadatas):
        sys.path.append(metadatas.sublist3r_bin_path)

        with open(metadatas.seg_path) as seg_providers_file:
            self.seg_providers = json.loads(seg_providers_file.read())["seg"]

    def start_scan(self, options: Options) -> Generator[dict | list[dict], Any, None]:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=os.cpu_count() or 4
        ) as executor:
            futures = []

            def _submit_task(func, asset, *args, **kwargs):
                futures.append(executor.submit(func, asset.value, *args, **kwargs))

            # Scan according to options
            for asset in options.assets:
                if asset.datatype in ["ip", "fqdn"]:
                    # Whois
                    if options.do_whois:
                        _submit_task(scanners.do_whois, asset)

                if asset.datatype in ["domain", "fqdn"]:
                    # Seg check
                    if options.do_seg_check:
                        _submit_task(scanners.do_seg_check, asset, self.seg_providers)

                if asset.datatype == "domain":
                    # SPF check
                    if options.do_spf_check:
                        _submit_task(scanners.do_spf_check, asset)

                    # DKIM check
                    if options.do_dkim_check:
                        _submit_task(scanners.do_dkim_check, asset)

                    # DMARC check
                    if options.do_dmarc_check:
                        _submit_task(scanners.do_dmarc_check, asset)

                    # DNS Checks
                    if options.do_dns_resolve:
                        _submit_task(scanners.do_dns_resolve, asset)

                    if options.do_dns_transfer:
                        _submit_task(scanners.do_dns_transfer, asset)

                    if options.do_dns_recursive:
                        _submit_task(scanners.do_dns_recursive, asset)

                    if options.do_advanced_whois:
                        _submit_task(scanners.do_advanced_whois, asset)

                    elif options.do_whois:
                        _submit_task(scanners.do_whois, asset)

                    # Subdomains
                    if options.do_subdomain_enum:
                        _submit_task(
                            scanners.do_subdomain_enum,
                            asset,
                            options.do_subdomains_resolve,
                            options.subdomain_as_new_asset,
                        )
                    if options.do_subdomains_bruteforce:
                        pass
            logger.debug(
                f"Scan {options.id} | Number of tasks to process: {len(futures)}"
            )
            # Get tasks results
            for future in concurrent.futures.as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        yield result
                except Exception as e:
                    logger.error(f"Scan {options.id} | Error during parsing", e)


engine = OwlDNS(Options, Metadatas)

if __name__ == "__main__":
    engine.start()
