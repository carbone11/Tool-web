from typing import Optional, Dict

from src.scanners.nosql_injection import NoSQLInjectionScanner


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
        if self.mode == "error" and "%7B%22%24ne%22%3A%20null%7D" in path:
            return FakeResponse(200, text="MongoError: Cast to ObjectId failed", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_nosql_error_marker_detection():
    scanner = NoSQLInjectionScanner("https://target.local/?user=alice")
    scanner.client = FakeClient(scanner.base_url, mode="error")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "NoSQL Injection" for v in vulns), "NoSQLi non détectée"
