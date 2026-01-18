import time
import sys, os
import requests
# Ensure workspace root is on sys.path
sys.path.insert(0, os.path.abspath(os.getcwd()))
from src.scanners.xss_scanner import XSSScanner
from src.utils.report_generator import ReportGenerator

TARGET = 'https://www.kikourou.net/'
print('Scanning target for XSS with visual proofs:', TARGET)

# Run XSS scan with proofs and force CSS-only for reliability
scanner = XSSScanner(base_url=TARGET, threads=5, timeout=10, payload_mode='safe', proof_actions=True, force_css_only=True)
results = scanner.scan()
print('XSS scan completed. Vulns found:', len(results.get('vulnerabilities', [])))

# Filter only XSS entries
xss_vulns = [v for v in results.get('vulnerabilities', []) if 'xss' in (v.get('type','').lower())]
print('XSS vulnerabilities to replay:', len(xss_vulns))

session = requests.Session()
replay_results = []
for v in xss_vulns:
    try:
        proof_url = v.get('proof_url') or v.get('url')
        method = v.get('method', 'GET').upper()
        param = v.get('parameter')
        payload = v.get('proof_payload') or v.get('payload')
        resp = None
        if proof_url and method == 'GET':
            resp = session.get(proof_url, timeout=10)
        elif proof_url and method == 'POST':
            # Minimal POST replay if needed
            data = {param: payload} if (param and payload is not None) else {}
            resp = session.post(proof_url, data=data, timeout=10)
        status = resp.status_code if resp is not None else None
        final_url = resp.url if resp is not None else proof_url
        replay_results.append({
            'type': v.get('type'),
            'method': method,
            'parameter': param,
            'payloads_tried': [payload] if payload is not None else [],
            'status_code': status,
            'final_url': final_url,
            'proof_used': True if v.get('proof_url') else False,
            'proof_url': v.get('proof_url'),
            'success': True if (status and 200 <= status < 400) else False,
        })
    except Exception as e:
        print('Replay error:', e)

# Generate execution report
if replay_results:
    rg = ReportGenerator()
    ts = time.strftime('%Y%m%d_%H%M%S')
    base = f'reports/executions/cybersec_exec_{ts}'
    html_path = base + '.html'
    rg.generate_execution_report(replay_results, TARGET, html_path)
    print('Execution report created:', html_path)
else:
    print('No replay results to report.')
