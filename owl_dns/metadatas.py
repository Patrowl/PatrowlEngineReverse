from pydantic import BaseModel
from typing import List, Any
from base_engine.base_engine import BaseOptions

class Asset(BaseModel):
    datatype: str
    value: str

class Options(BaseOptions):
    do_whois: bool = False
    do_advanced_whois: bool = False
    do_subdomain_enum: bool = False
    do_subdomains_resolve: bool = False
    subdomain_as_new_asset: bool = False
    do_subdomains_bruteforce: bool = False
    do_dns_resolve: bool = False
    do_dns_transfer: bool = False
    do_dns_recursive: bool = False
    do_seg_check: bool = False
    do_spf_check: bool = False
    do_dkim_check: bool = False
    do_dmarc_check: bool = False
    assets: List[Asset]

class Metadatas(BaseModel):
    name: str
    description: str
    allowed_asset_types: List[str]
    sublist3r_bin_path: str
    seg_path: str