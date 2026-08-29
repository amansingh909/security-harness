import pytest

from bounty_reporter.cvss import (
    CvssError,
    base_score,
    parse_vector,
    qualitative_rating,
)


@pytest.mark.parametrize("vector,expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),   # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),    # classic net read
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 6.5),    # IDOR
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),    # no impact
    ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8),    # low local
])
def test_base_score_reference_vectors(vector, expected):
    assert base_score(vector) == expected


def test_qualitative_bands():
    assert qualitative_rating(0.0) == "NONE"
    assert qualitative_rating(3.9) == "LOW"
    assert qualitative_rating(4.0) == "MEDIUM"
    assert qualitative_rating(6.9) == "MEDIUM"
    assert qualitative_rating(7.0) == "HIGH"
    assert qualitative_rating(9.0) == "CRITICAL"
    assert qualitative_rating(10.0) == "CRITICAL"


def test_parse_rejects_bad_version():
    with pytest.raises(CvssError):
        parse_vector("CVSS:2.0/AV:N")


def test_parse_rejects_missing_metrics():
    with pytest.raises(CvssError):
        parse_vector("CVSS:3.1/AV:N/AC:L")


def test_base_score_rejects_illegal_value():
    with pytest.raises(CvssError):
        base_score("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
