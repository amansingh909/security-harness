import pytest

from bounty_reporter.models import Finding


def _valid(**over):
    base = dict(
        program="acme", vuln_type="SSRF",
        asset="https://app.example.com/fetch?url=",
        steps_to_reproduce=["step 1", "step 2"],
        observed_result="internal metadata returned",
        impact="attacker reaches internal 169.254.169.254 metadata endpoint",
    )
    base.update(over)
    return base


def test_valid_finding():
    f = Finding.from_dict(_valid())
    assert f.vuln_type == "SSRF"


def test_missing_required_raises_friendly_error():
    data = _valid()
    del data["impact"]
    with pytest.raises(ValueError) as exc:
        Finding.from_dict(data)
    assert "impact" in str(exc.value)
    assert "fabricat" in str(exc.value).lower()


def test_blank_steps_rejected():
    with pytest.raises(ValueError):
        Finding.from_dict(_valid(steps_to_reproduce=["  ", ""]))


def test_cwe_shape_enforced():
    with pytest.raises(ValueError):
        Finding.from_dict(_valid(cwe="639"))
    assert Finding.from_dict(_valid(cwe="cwe-918")).cwe == "CWE-918"


def test_resolved_title_synthesizes_from_real_fields():
    f = Finding.from_dict(_valid(title=None))
    title = f.resolved_title()
    assert title.startswith("SSRF on https://app.example.com/fetch?url= allows")
