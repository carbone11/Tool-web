from typing import Optional, Dict

from src.scanners.ssti import SSTIScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "error"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        if not path:
            return FakeResponse(200, text="", url=self.base_url)
        if self.mode == "error" and "%7B%7B7*7%7D%7D" in path:
            return FakeResponse(200, text="TemplateSyntaxError: unexpected '}'", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_ssti_error_marker_detection():
    scanner = SSTIScanner("https://target.local/?q=")
    scanner.client = FakeClient(scanner.base_url, mode="error")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "SSTI (safe)" for v in vulns), "SSTI non détectée"
