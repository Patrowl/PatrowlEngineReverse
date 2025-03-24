NO_DMARC = {
    "severity": "low",
    "confidence": "certain",
    "title": "No DMARC record",
    "description": "There is no DMARC DNS record associated for the domain",
}
DMARC_LAX_POLICY = {
    "severity": "low",
    "confidence": "certain",
    "title": "Lax DMARC policy",
    "description": "The DMARC policy is set to '{value}'. If the DMARC policy is neither 'reject' nor 'quarantine', spoofed emails are likely to be accepted.",
}
DMARC_LAX_SUBDOMAIN_POLICY = {
    "severity": "low",
    "confidence": "certain",
    "title": "Lax DMARC subdomain policy",
    "description": "The DMARC policy for subdomains is set to '{value}'. If the DMARC policy is neither 'reject' nor 'quarantine', spoofed emails from subdomains are likely to be accepted.",
}
DMARC_NOT_100_PCT = {
    "severity": "low",
    "confidence": "certain",
    "title": "Partial DMARC coverage",
    "description": "The DMARC 'pct' value is '{value}', meaning the DMARC policy will only be applied to {value}% of incoming mail.",
}
