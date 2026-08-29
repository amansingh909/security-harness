from bounty_reporter.dedup import dedupe, fingerprint
from bounty_reporter.models import Finding


def _finding(**over):
    base = dict(
        program="p", vuln_type="IDOR",
        asset="https://app.example.com/api/v2/invoices/4021",
        affected_param="id",
        steps_to_reproduce=["do a thing"],
        observed_result="leaked data", impact="reads other users' invoices",
    )
    base.update(over)
    return Finding(**base)


def test_same_location_different_id_collapses():
    a = _finding(asset="https://app.example.com/api/v2/invoices/1")
    b = _finding(asset="https://app.example.com/api/v2/invoices/2")
    assert fingerprint(a) == fingerprint(b)


def test_different_vuln_type_differs():
    a = _finding(vuln_type="IDOR")
    b = _finding(vuln_type="XSS")
    assert fingerprint(a) != fingerprint(b)


def test_different_host_differs():
    a = _finding(asset="https://app.example.com/x")
    b = _finding(asset="https://evil.example.com/x")
    assert fingerprint(a) != fingerprint(b)


def test_dedupe_keeps_first():
    a = _finding(asset="https://app.example.com/api/v2/invoices/1")
    b = _finding(asset="https://app.example.com/api/v2/invoices/2")
    c = _finding(vuln_type="XSS")
    unique = dedupe([a, b, c])
    assert len(unique) == 2
