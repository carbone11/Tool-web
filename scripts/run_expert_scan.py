#!/usr/bin/env python3
"""
Non-interactive runner for expert payload scan + replay.
Use ONLY on authorized targets.
"""

import argparse
import sys
import os

ROOT = os.path.dirname(os.path.abspath(__file__))
WORKSPACE = os.path.dirname(ROOT)
if WORKSPACE not in sys.path:
    sys.path.insert(0, WORKSPACE)

from menu_cli import CyberSecMenu  # type: ignore


def main() -> int:
    ap = argparse.ArgumentParser(description="Expert scan + replay runner (authorized targets only)")
    ap.add_argument("--url", required=True, help="Target URL (authorized)")
    ap.add_argument("--modules", default="xss redirtrav ssrf crlf cmdi nosql xxe ssti ldapxpath sql",
                    help="Space-separated modules (default: a comprehensive set)")
    ap.add_argument("--payload_mode", default="expert", choices=["safe","normal","aggressive","expert","expert-deep"],
                    help="Payload mode level (default: expert)")
    ap.add_argument("--proof_actions", action="store_true", help="Enable visual proof actions where applicable")
    ap.add_argument("--force_css_only", action="store_true", help="Force CSS-only proofs for XSS")
    ap.add_argument("--ascii_mode", action="store_true", help="Disable emojis in CLI output")
    args = ap.parse_args()

    menu = CyberSecMenu()
    menu.target_url = args.url
    menu.selected_modules = [m.strip() for m in args.modules.split() if m.strip()]
    # Configure expert settings
    menu.config['payload_mode'] = args.payload_mode
    menu.config['proof_actions'] = bool(args.proof_actions)
    menu.config['force_css_only'] = bool(args.force_css_only)
    menu.config['ascii_mode'] = bool(args.ascii_mode)

    # Run scan
    menu.run_scan()

    # Collect replayable vulns (in-memory), fallback to latest HTML report if needed
    vulns = menu._collect_vulnerabilities()
    if not vulns:
        vulns = menu._fallback_vulns_from_latest_html()

    # Replay all
    out = menu._replay_vulnerabilities(vulns)
    if out:
        print(f"Execution report: {out}")
        return 0
    else:
        print("No execution report generated")
        return 1


if __name__ == "__main__":
    sys.exit(main())
