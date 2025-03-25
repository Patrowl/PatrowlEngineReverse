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
DMARC_MULTIPLE_RECORDS = {
    "severity": "high",
    "confidence": "certain",
    "title": "Multiple DMARC records",
    "description": "Multiple DMARC records were found, which is invalid and will cause DMARC to be ignored.",
}
DMARC_MISCONFIGURED = {
    "severity": "high",
    "confidence": "likely",
    "title": "Invalid DMARC record",
    "description": "The DMARC record contains syntax errors or an invalid value: '{value}', making it ineffective.",
}
DMARC_NO_REPORTING = {
    "severity": "medium",
    "confidence": "certain",
    "title": "No DMARC reporting configured",
    "description": "The DMARC record does not include a 'rua' or 'ruf' tag, making it difficult to monitor spoofing attempts.",
}
