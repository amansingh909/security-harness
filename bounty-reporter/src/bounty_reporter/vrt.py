"""Map a CWE to each program's own taxonomy: HackerOne weakness name and
Bugcrowd VRT id. Small curated table with sensible fallbacks — programs don't
all use CVSS, so the report carries the program-native category too."""
from __future__ import annotations

_CWE_TO_H1: dict[str, str] = {
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-639": "Insecure Direct Object Reference (IDOR)",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "XML External Entities (XXE)",
    "CWE-200": "Information Disclosure",
}

_CWE_TO_BUGCROWD_VRT: dict[str, str] = {
    "CWE-79": "cross_site_scripting_xss.reflected",
    "CWE-89": "server_side_injection.sql_injection",
    "CWE-78": "server_side_injection.command_injection",
    "CWE-22": "server_side_injection.file_inclusion.local",
    "CWE-352": "broken_authentication_and_session_management.cross_site_request_forgery_csrf",
    "CWE-918": "server_side_injection.server_side_request_forgery_ssrf",
    "CWE-639": "broken_access_control.idor",
    "CWE-284": "broken_access_control",
    "CWE-287": "broken_authentication_and_session_management",
    "CWE-434": "unrestricted_file_upload",
    "CWE-502": "server_side_injection.deserialization",
    "CWE-611": "server_side_injection.xml_external_entity_injection_xxe",
    "CWE-200": "sensitive_data_exposure",
}


def hackerone_weakness(cwe: str | None) -> str:
    if cwe and cwe.upper() in _CWE_TO_H1:
        return _CWE_TO_H1[cwe.upper()]
    return "Other"


def bugcrowd_vrt(cwe: str | None) -> str:
    if cwe and cwe.upper() in _CWE_TO_BUGCROWD_VRT:
        return _CWE_TO_BUGCROWD_VRT[cwe.upper()]
    return "other"
