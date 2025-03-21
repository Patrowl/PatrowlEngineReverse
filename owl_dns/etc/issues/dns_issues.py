# fmt: off
# https://www.cloudflare.com/learning/dns/what-is-recursive-dns/
# https://www.beyondsecurity.com/resources/vulnerabilities/dns-server-allows-recursive-queries
DNS_RECURSION_AVAILABLE = {
    "severity": "high",
    "confidence": "certain",
    "title": "DNS recursion available",
    "description": "A recursive DNS lookup is where one DNS server communicates with several other DNS servers to hunt "
                   "down an IP address and return it to the client. Unfortunately, allowing recursive DNS queries on "
                   "open DNS servers creates a security vulnerability, as this configuration can enable attackers to "
                   "perform DNS amplification attacks and DNS cache poisoning.",
    "solution": "Unless this server is an internal server, or intentionally serves name queries, the recursive queries "
                "option should be disable. Ensure that the recursive query is on purpose."
}

# https://beaglesecurity.com/blog/vulnerability/dns-zone-transfer.html
DNS_ZONE_TRANSFER = {
    "severity": "high",
    "confidence": "certain",
    "title": "DNS zone transfer enabled",
    "description": "DNS zone transfer, also known as DNS query type AXFR, is a process by which a DNS server passes a "
                   "copy of part of its database to another DNS server. A zone transfer usually occurs when you bring "
                   "up a new DNS server as a secondary DNS server. Unfortunately, DNS zone transfer does not request "
                   "authentication: this means that unless some kind of protection is introduced, anyone pretending to "
                   "be a client can query the DNS server for a copy of a zone, which gives them a lot of potential "
                   "attack vectors.",
    "solution": "Disable the DNS zone transfer option if not used. Else, create an exclusive list of trusted IPs that "
                "can perform a zone transfer."
}

# fmt: on
