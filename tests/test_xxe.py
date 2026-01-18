from typing import Optional, Dict

from src.scanners.xxe import XXEScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "xxe_disallowed"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        if not path:
            return FakeResponse(200, text="", url=self.base_url)
        if self.mode == "xxe_disallowed" and "DOCTYPE" in path:
            return FakeResponse(200, text="DOCTYPE is disallowed", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_xxe_error_marker_detection():
    scanner = XXEScanner("https://target.local/?xml=")
    scanner.client = FakeClient(scanner.base_url, mode="xxe_disallowed")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "XXE (safe)" for v in vulns), "XXE non détectée"
