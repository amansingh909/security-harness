from recon_orchestrator.scope import IN, OUT, UNCERTAIN, ScopeGuard, normalize_host


def test_normalize_host_from_url_and_port():
    assert normalize_host("https://api.example.com:8443/path?x=1") == "api.example.com"
    assert normalize_host("Example.COM") == "example.com"


def test_apex_is_not_a_wildcard():
    g = ScopeGuard(in_scope=["example.com"])
    assert g.verdict("example.com").status == IN
    assert g.verdict("dev.example.com").status == OUT


def test_wildcard_matches_subdomain_not_apex():
    g = ScopeGuard(in_scope=["*.example.com"])
    assert g.verdict("api.example.com").status == IN
    assert g.verdict("example.com").status == OUT


def test_rejects_suffix_confusion_bypass():
    g = ScopeGuard(in_scope=["*.example.com"])
    # classic bypass attempt
    assert g.verdict("example.com.evil.com").status == OUT
    assert g.verdict("notexample.com").status == OUT


def test_exclusion_beats_wildcard():
    g = ScopeGuard(in_scope=["*.example.com"], out_of_scope=["admin.example.com"])
    assert g.verdict("admin.example.com").status == OUT
    assert "out-of-scope" in g.verdict("admin.example.com").reason


def test_multilevel_wildcard_uncertain_when_disallowed():
    g = ScopeGuard(in_scope=["*.example.com"], allow_multilevel_wildcard=False)
    assert g.verdict("api.example.com").status == IN          # single level
    assert g.verdict("a.b.example.com").status == UNCERTAIN   # nested
    g2 = ScopeGuard(in_scope=["*.example.com"], allow_multilevel_wildcard=True)
    assert g2.verdict("a.b.example.com").status == IN


def test_cidr_scope():
    g = ScopeGuard(in_scope=["10.0.0.0/24"], out_of_scope=["10.0.0.5"])
    assert g.verdict("10.0.0.9").status == IN
    assert g.verdict("10.0.0.5").status == OUT
    assert g.verdict("10.0.1.1").status == OUT


def test_empty_scope_is_out():
    g = ScopeGuard(in_scope=[])
    assert g.verdict("example.com").status == OUT


def test_is_authorized_only_true_for_clean_in():
    g = ScopeGuard(in_scope=["*.example.com"], allow_multilevel_wildcard=False)
    assert g.is_authorized("api.example.com") is True
    assert g.is_authorized("a.b.example.com") is False  # uncertain -> not authorized
    assert g.is_authorized("evil.com") is False
