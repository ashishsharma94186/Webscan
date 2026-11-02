import pytest, requests
import scanner

def fake_resp(headers=None, text="", url="http://localhost/"):
    r = requests.Response()
    r.headers.update(headers or {})
    r._content = text.encode()
    r.url = url
    r.status_code = 200
    return r

def test_missing_headers_flagged():
    titles = [f["title"] for f in scanner.check_headers(fake_resp())]
    assert "Missing header: Content-Security-Policy" in titles

def test_complete_headers_clean():
    h = {k: "x" for k in scanner.SEC_HEADERS}
    assert scanner.check_headers(fake_resp(h)) == []

def test_version_disclosure():
    out = scanner.check_headers(fake_resp({"Server": "Apache/2.2.8"}))
    assert any("Version disclosure" in f["title"] for f in out)

def test_csrf_form_detected():
    html = '<form method="post" action="/x"><input name="a"></form>'
    assert any("CSRF" in f["title"] for f in scanner.check_forms(fake_resp(text=html)))

def test_csrf_token_ok():
    html = '<form method="post"><input name="csrf_token"></form>'
    assert not any("CSRF" in f["title"] for f in scanner.check_forms(fake_resp(text=html)))

def test_public_host_blocked():
    assert not scanner.is_authorized("http://8.8.8.8/")

def test_localhost_allowed():
    assert scanner.is_authorized("http://127.0.0.1:8000/")

def test_requires_confirmation():
    with pytest.raises(PermissionError):
        scanner.scan("http://127.0.0.1:8000/")
