from bounty_reporter.vrt import bugcrowd_vrt, hackerone_weakness


def test_known_mappings():
    assert hackerone_weakness("CWE-89") == "SQL Injection"
    assert bugcrowd_vrt("CWE-89") == "server_side_injection.sql_injection"
    assert bugcrowd_vrt("CWE-918") == "server_side_injection.server_side_request_forgery_ssrf"


def test_fallbacks():
    assert hackerone_weakness(None) == "Other"
    assert hackerone_weakness("CWE-99999") == "Other"
    assert bugcrowd_vrt(None) == "other"


def test_case_insensitive():
    assert hackerone_weakness("cwe-79") == "Cross-site Scripting (XSS)"
