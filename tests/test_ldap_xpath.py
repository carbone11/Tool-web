from typing import Optional, Dict

from src.scanners.ldap_xpath_injection import LDAPXPathInjectionScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "ldap_error"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        if not path:
            return FakeResponse(200, text="", url=self.base_url)
        if self.mode == "ldap_error" and "(objectClass%3D*)" in path:
            return FakeResponse(200, text="LDAP: Bad search filter", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_ldap_xpath_error_marker_detection():
    scanner = LDAPXPathInjectionScanner("https://target.local/?filter=")
    scanner.client = FakeClient(scanner.base_url, mode="ldap_error")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "LDAP/XPath Injection" for v in vulns), "LDAP/XPath non détectée"
