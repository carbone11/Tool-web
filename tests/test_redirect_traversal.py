import types
from typing import Optional, Dict

from src.scanners.redirect_traversal import RedirectTraversalScanner


class FakeResponse:
    def __init__(self, status_code: int = 200, text: str = "", headers: Optional[Dict[str, str]] = None, url: str = ""):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}
        self.url = url


class FakeClient:
    def __init__(self, base_url: str, mode: str = "base"):
        self.base_url = base_url
        self.mode = mode

    def test_connection(self) -> bool:
        return True

    def get(self, path: str = "", **kwargs) -> FakeResponse:
        # Base page content for discovery
        if not path:
            if self.mode == "post_form":
                html = '<html><body><form method="POST" action="/upload"><input name="file" value=""></form></body></html>'
            else:
                html = "<html></html>"
            return FakeResponse(200, text=html, url=self.base_url)

        # Open redirect detection: do not follow redirects
        allow_redirects = kwargs.get("allow_redirects", True)
        if self.mode == "redirect" and allow_redirects is False and "redirect=" in path:
            return FakeResponse(302, text="", headers={"Location": "https://example.com"}, url=self.base_url + path)

        # Default OK
        return FakeResponse(200, text="", url=self.base_url + path)

    def post(self, path: str = "", data: Optional[Dict[str, str]] = None, **kwargs) -> FakeResponse:
        # Path traversal POST: return marker if payload indicates traversal
        data = data or {}
        if self.mode == "post_form" and any("/etc/passwd" in (v or "") for v in data.values()):
            return FakeResponse(200, text="root:x:0:0:root:/root:/bin/bash", url=self.base_url + path)
        return FakeResponse(200, text="", url=self.base_url + path)


def test_open_redirect_detection_get():
    scanner = RedirectTraversalScanner("https://target.local/page?redirect=1")
    # Inject fake client
    scanner.client = FakeClient(scanner.base_url, mode="redirect")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "Open Redirect" for v in vulns), "Open Redirect non détecté"


def test_path_traversal_detection_post():
    scanner = RedirectTraversalScanner("https://target.local/")
    # Inject fake client that exposes a POST form and returns traversal markers
    scanner.client = FakeClient(scanner.base_url, mode="post_form")  # type: ignore[assignment]
    results = scanner.scan()
    vulns = results.get("vulnerabilities", [])
    assert any(v.get("type") == "Path Traversal" and v.get("method") == "POST" for v in vulns), "Path Traversal POST non détecté"
