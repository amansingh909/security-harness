from harness.programs import Program, Registry


def test_program_runnable_requires_scope_and_seeds():
    ok, why = Program(name="x").is_runnable()
    assert not ok and "in-scope" in why

    ok, why = Program(name="x", in_scope=["*.x.com"]).is_runnable()
    assert not ok and "seed" in why

    ok, _ = Program(name="x", in_scope=["*.x.com"], seeds=["a.x.com"]).is_runnable()
    assert ok


def test_registry_roundtrip(tmp_path):
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["*.acme.com"],
                    out_of_scope=["blog.acme.com"], seeds=["www.acme.com"],
                    cve_index_url="http://localhost:8080"))
    reg.add(Program(name="globex", in_scope=["globex.com"]))
    path = tmp_path / "programs.yaml"
    reg.save(path)

    loaded = Registry.load(path)
    assert loaded.names() == ["acme", "globex"]
    acme = loaded.get("acme")
    assert acme.in_scope == ["*.acme.com"]
    assert acme.out_of_scope == ["blog.acme.com"]
    assert acme.cve_index_url == "http://localhost:8080"


def test_registry_load_missing_file_is_empty(tmp_path):
    reg = Registry.load(tmp_path / "nope.yaml")
    assert reg.names() == []


def test_registry_remove(tmp_path):
    reg = Registry()
    reg.add(Program(name="acme", in_scope=["*.acme.com"], seeds=["a"]))
    assert reg.remove("acme") is True
    assert reg.remove("acme") is False
    assert reg.names() == []


def test_program_mode_defaults_to_real():
    """A program is passive-only ('real') unless explicitly set to 'practice'."""
    assert Program(name="x").mode == "real"


def test_program_h1_handle_defaults_to_none():
    """Only programs imported from HackerOne carry a handle to refresh from."""
    assert Program(name="x").h1_handle is None


def test_program_mode_roundtrips_through_yaml(tmp_path):
    reg = Registry()
    reg.add(Program(name="lab", in_scope=["localhost"], seeds=["localhost"],
                    mode="practice"))
    path = tmp_path / "programs.yaml"
    reg.save(path)
    assert Registry.load(path).get("lab").mode == "practice"
