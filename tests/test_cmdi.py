from typing import Optional, Dict

from src.scanners.command_injection import CommandInjectionScanner


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
            # Provide a GET link with a candidate parameter 'cmd='
            html = '<a href="/run?cmd=list">run</a>'
            return FakeResponse(200, text=html, url=self.base_url)
        if self.mode == "reflect" and "CYBERINJECT123" in path:
            return FakeResponse(200, text="OK CYBERINJECT123", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)

    def post(self, path: str = "", data: Optional[Dict[str, str]] = None, **kwargs) -> FakeResponse:
        return FakeResponse(200, text="", url=self.base_url + path)


def test_cmdi_reflection_detection():
    scanner = CommandInjectionScanner("https://target.local/")
    scanner.client = FakeClient(scanner.base_url, mode="reflect")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "Command Injection" for v in vulns), "Command Injection non détectée (reflection)"
