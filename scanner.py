"""Non-destructive web application security scanner (educational).
Only scan systems you own or are explicitly authorized to test."""
import ipaddress, os, re, socket, ssl, datetime as dt
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl
import requests
from bs4 import BeautifulSoup

TIMEOUT = 8
UA = {"User-Agent": "EduWebScan/1.0 (authorized testing)"}
CANARY = "wsx7391<'\">"

SEC_HEADERS = {
    "Content-Security-Policy": ("medium", "Add a CSP to limit XSS and data injection."),
    "Strict-Transport-Security": ("medium", "Add HSTS to force HTTPS."),
    "X-Frame-Options": ("low", "Set X-Frame-Options or CSP frame-ancestors (clickjacking)."),
    "X-Content-Type-Options": ("low", "Set 'nosniff' to stop MIME sniffing."),
    "Referrer-Policy": ("low", "Set a Referrer-Policy to limit URL leakage."),
    "Permissions-Policy": ("info", "Restrict browser features you don't use."),
}
SENSITIVE_PATHS = ["/.git/HEAD", "/.env", "/backup.zip", "/phpinfo.php",
                   "/server-status", "/admin", "/robots.txt"]
SQL_ERRORS = re.compile(
    r"(sql syntax|sqlite3?\.|psycopg2|ORA-\d{5}|unclosed quotation|mysql_fetch|"
    r"SQLSTATE\[|You have an error in your SQL)", re.I)


def finding(sev, title, detail, fix, url=""):
    return {"severity": sev, "title": title, "detail": detail, "fix": fix, "url": url}


def is_authorized(url):
    """Allow only localhost/private hosts, or hosts listed in WEBSCAN_ALLOWED."""
    host = urlparse(url).hostname
    if not host:
        return False
    allowed = [h.strip().lower() for h in os.getenv("WEBSCAN_ALLOWED", "").split(",") if h.strip()]
    if host.lower() in allowed:
        return True
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if not (ip.is_loopback or ip.is_private):
                return False
        return True
    except (socket.gaierror, ValueError):
        return False


def check_headers(resp):
    out = []
    for h, (sev, fix) in SEC_HEADERS.items():
        if h not in resp.headers:
            out.append(finding(sev, f"Missing header: {h}", f"{h} not set.", fix, resp.url))
    for h in ("Server", "X-Powered-By"):
        v = resp.headers.get(h)
        if v and re.search(r"\d", v):
            out.append(finding("low", f"Version disclosure via {h}", f"{h}: {v}",
                               "Hide product/version banners.", resp.url))
    return out


def check_cookies(resp):
    out = []
    for raw in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []:
        name = raw.split("=", 1)[0]
        low = raw.lower()
        if "httponly" not in low:
            out.append(finding("medium", f"Cookie '{name}' lacks HttpOnly", raw[:80],
                               "Add HttpOnly so scripts can't read it.", resp.url))
        if resp.url.startswith("https") and "secure" not in low:
            out.append(finding("medium", f"Cookie '{name}' lacks Secure", raw[:80],
                               "Add Secure so it only travels over HTTPS.", resp.url))
        if "samesite" not in low:
            out.append(finding("low", f"Cookie '{name}' lacks SameSite", raw[:80],
                               "Set SameSite=Lax or Strict (CSRF defence).", resp.url))
    return out


def check_tls(url):
    p = urlparse(url)
    if p.scheme != "https":
        return [finding("medium", "Site served over HTTP", "No TLS on the scanned URL.",
                        "Serve the site over HTTPS and redirect HTTP to it.", url)]
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((p.hostname, p.port or 443), timeout=TIMEOUT) as s:
            with ctx.wrap_socket(s, server_hostname=p.hostname) as t:
                exp = dt.datetime.strptime(t.getpeercert()["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days = (exp - dt.datetime.utcnow()).days
                if days < 0:
                    return [finding("high", "TLS certificate expired", f"Expired {-days} days ago.", "Renew it.", url)]
                if days < 30:
                    return [finding("low", "TLS certificate expiring soon", f"{days} days left.", "Renew it.", url)]
    except ssl.SSLError as e:
        return [finding("high", "TLS validation failed", str(e)[:120], "Install a valid certificate.", url)]
    except OSError:
        pass
    return []


def check_paths(base, sess):
    out = []
    for path in SENSITIVE_PATHS:
        try:
            r = sess.get(urljoin(base, path), timeout=TIMEOUT, allow_redirects=False)
        except requests.RequestException:
            continue
        if r.status_code == 200 and path != "/robots.txt" and len(r.content) > 0:
            sev = "high" if path in ("/.git/HEAD", "/.env", "/backup.zip") else "medium"
            out.append(finding(sev, f"Exposed path: {path}", f"HTTP 200 ({len(r.content)} bytes).",
                               "Block public access to this resource.", r.url))
    return out


def check_forms(resp):
    out = []
    soup = BeautifulSoup(resp.text, "html.parser")
    for f in soup.find_all("form"):
        method = (f.get("method") or "get").lower()
        action = urljoin(resp.url, f.get("action") or "")
        names = " ".join((i.get("name") or "").lower() for i in f.find_all("input"))
        if method == "post" and not re.search(r"csrf|token|authenticity", names):
            out.append(finding("medium", "POST form without CSRF token", f"Form action: {action}",
                               "Add an anti-CSRF token and verify it server-side.", resp.url))
        if f.find("input", {"type": "password"}):
            if action.startswith("http://"):
                out.append(finding("high", "Password sent over HTTP", f"Form action: {action}",
                                   "Submit credentials over HTTPS only.", resp.url))
            if (f.find("input", {"type": "password"}).get("autocomplete") or "") == "":
                out.append(finding("info", "Password field has no autocomplete hint", action,
                                   "Set autocomplete='current-password' or 'new-password'.", resp.url))
    return out


def check_injection_signals(url, sess):
    """Benign canary reflection + SQL error-message detection. No exploitation."""
    out = []
    params = parse_qsl(urlparse(url).query)
    if not params:
        return out
    base = url.split("?")[0]
    for i, (k, v) in enumerate(params):
        def probe(val):
            q = [(a, val if j == i else b) for j, (a, b) in enumerate(params)]
            return sess.get(base + "?" + urlencode(q), timeout=TIMEOUT)
        try:
            r = probe(CANARY)
            if CANARY in r.text:
                out.append(finding("high", f"Unescaped reflection in '{k}'",
                                   "Special characters returned unencoded (possible reflected XSS).",
                                   "HTML-encode output and add a CSP.", url))
            r2 = probe(v + "'")
            m = SQL_ERRORS.search(r2.text)
            if m:
                out.append(finding("high", f"Database error triggered via '{k}'",
                                   f"Error signature: {m.group(0)}",
                                   "Use parameterized queries; hide error details.", url))
        except requests.RequestException:
            continue
    return out


def scan(url, confirmed=False):
    if not confirmed:
        raise PermissionError("You must confirm you are authorized to test this target.")
    if not is_authorized(url):
        raise PermissionError("Target is not localhost/private and not in WEBSCAN_ALLOWED.")
    sess = requests.Session()
    sess.headers.update(UA)
    resp = sess.get(url, timeout=TIMEOUT)
    findings = []
    findings += check_headers(resp)
    findings += check_cookies(resp)
    findings += check_tls(url)
    findings += check_paths(f"{urlparse(url).scheme}://{urlparse(url).netloc}", sess)
    findings += check_forms(resp)
    findings += check_injection_signals(url, sess)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order[f["severity"]])
    return findings
