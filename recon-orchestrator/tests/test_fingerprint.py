from recon_orchestrator.fingerprint import fingerprint


def test_server_header_product_version():
    fps = fingerprint({"Server": "nginx/1.18.0"})
    assert (fps[0].product, fps[0].version) == ("nginx", "1.18.0")


def test_apache_with_extra():
    fps = fingerprint({"Server": "Apache/2.4.49 (Unix)"})
    assert ("apache", "2.4.49") in {(f.product, f.version) for f in fps}


def test_x_powered_by_versionless():
    fps = fingerprint({"X-Powered-By": "Express"})
    assert fps[0].product == "express"
    assert fps[0].version is None


def test_php_version():
    fps = fingerprint({"X-Powered-By": "PHP/7.4.3"})
    assert ("php", "7.4.3") in {(f.product, f.version) for f in fps}


def test_title_cms():
    fps = fingerprint({}, title="Home | Powered by WordPress 5.8")
    assert ("wordpress", "5.8") in {(f.product, f.version) for f in fps}


def test_no_headers_no_fingerprint():
    assert fingerprint({}, None) == []
