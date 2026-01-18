from typing import Optional, Dict

from src.scanners.crlf_injection import CRLFInjectionScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "headers"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        allow_redirects = kwargs.get("allow_redirects", True)
        if not path:
            # Expose a link with a candidate parameter
            html = '<a href="/download?file=readme.txt">dl</a>'
            return FakeResponse(200, text=html, url=self.base_url)
        encoded_hit = "%250d%250a" in path or "%0d%0a" in path
        if self.mode == "headers" and allow_redirects is False and encoded_hit:
            return FakeResponse(200, text="", headers={"X-Test": "injected"}, url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_crlf_header_marker_detection():
    scanner = CRLFInjectionScanner("https://target.local/")
    scanner.client = FakeClient(scanner.base_url, mode="headers")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "CRLF Injection" for v in vulns), "CRLF Injection non détectée"
