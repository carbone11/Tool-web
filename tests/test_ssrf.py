from typing import Optional, Dict

from src.scanners.ssrf import SSRFScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "metadata"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        if not path:
            # Expose a GET link with a parameter 'url='
            html = '<a href="/fetch?url=foo">fetch</a>'
            return FakeResponse(200, text=html, url=self.base_url)
        # When metadata IP is used, return metadata markers
        if self.mode == "metadata" and "169.254.169.254" in path:
            return FakeResponse(200, text="iam\nmeta-data\nsecurity-credentials", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)

    def post(self, path: str = "", data: Optional[Dict[str, str]] = None, **kwargs) -> FakeResponse:
        # Not used in this simple unit test
        return FakeResponse(200, text="", url=self.base_url + path)


def test_ssrf_metadata_detection_get():
    scanner = SSRFScanner("https://target.local/")
    scanner.client = FakeClient(scanner.base_url, mode="metadata")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "SSRF" for v in vulns), "SSRF non détectée via metadata markers"
