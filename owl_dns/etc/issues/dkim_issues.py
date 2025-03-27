NO_DKIM = {
    "severity": "medium",
    "confidence": "certain",
    "title": "No DKIM record",
    "description": "No DKIM DNS record was found for the domain. This may reduce email deliverability and increase the risk of spoofing.",
}
DKIM_WEAK_KEY = {
    "severity": "high",
    "confidence": "certain",
    "title": "Weak DKIM key",
    "description": "The DKIM public key is too short ({value} bits). It is recommended to use at least 1024 bits, preferably 2048 bits, to prevent cryptographic attacks.",
}
DKIM_MULTIPLE_RECORDS = {
    "severity": "high",
    "confidence": "certain",
    "title": "Multiple DKIM records detected",
    "description": "Multiple DKIM records were found for selector '{value}', which may cause validation issues.",
}
DKIM_P_TAG_NOT_FOUND = {
    "severity": "high",
    "confidence": "certain",
    "title": "DKIM p tag not found",
    "description": "The DKIM p tag does not exist.",
}
DKIM_MISCONFIGURED = {
    "severity": "high",
    "confidence": "likely",
    "title": "Invalid DKIM record",
    "description": "The DKIM record for selector '{value}' contains syntax errors or an invalid value, making DKIM ineffective.",
}
