from typing import Optional, Dict

from src.scanners.rce_safe import RCESafeScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "reflect"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        if not path:
            return FakeResponse(200, text="", url=self.base_url)
        if self.mode == "reflect" and ("RCESAFE123" in path or "ECHO_SAFE_456" in path):
            return FakeResponse(200, text="OK RCESAFE123", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_rce_safe_reflection_detection():
    scanner = RCESafeScanner("https://target.local/?run=")
    scanner.client = FakeClient(scanner.base_url, mode="reflect")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "RCE (safe)" for v in vulns), "RCE (safe) non détectée"
