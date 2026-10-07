#!/usr/bin/env python3
"""
XML-Namespace XSS CTF — a tiny, self-contained, local-only challenge.

Vulnerability class: "XHTML namespace injection" / HTML-in-XML DOM sinks.

The page lets you submit a snippet of XML. The client-side JS parses it with
DOMParser in XML mode and inserts the resulting nodes into the live DOM with
importNode(). That is the vulnerable sink: if any node in your XML declares
the XHTML namespace (http://www.w3.org/1999/xhtml), the browser will treat
that node as a *real* HTML element — including its event-handler attributes
— even though the surrounding document is XML, not HTML. Escaping
"<script>" does nothing here because no <script> tag is used.

Note: a namespaced <a:body onload="..."/> will NOT fire in this sink, even
though the namespace trick itself works and a real HTMLBodyElement does get
created. That's because onload/onerror/onscroll on <body> only forward to
the Window's load event when the element is actually installed as
document.body, which never happens here (we just appendChild it into an
already-loaded page). Use an element whose handler is dispatched directly
on itself instead, e.g. <a:img src="x" onerror="..."/>. See the in-page
hints for the full explanation.

Goal: get the page to pop an alert() containing the flag.

Run:
    python3 server.py
Then open http://127.0.0.1:8000/ in a browser.

Everything here is local (127.0.0.1 only), has no external dependencies,
and the "flag" is just a placeholder string for practice.
"""

import http.server
import socketserver

HOST = "127.0.0.1"
PORT = 8000

FLAG = "CTF{xhtml_ns_smuggles_an_img_onerror_past_the_xml_parser}"

PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>XML Namespace XSS — Local CTF</title>
<style>
  body {{ font-family: system-ui, sans-serif; max-width: 760px; margin: 40px auto; padding: 0 16px; line-height: 1.5; }}
  textarea {{ width: 100%; height: 120px; font-family: monospace; font-size: 14px; }}
  button {{ padding: 8px 16px; font-size: 14px; cursor: pointer; }}
  #sink {{ border: 2px dashed #999; padding: 12px; margin-top: 16px; min-height: 40px; }}
  .hint {{ background: #f4f4f4; padding: 10px; border-left: 4px solid #888; margin: 16px 0; }}
  code {{ background: #eee; padding: 2px 4px; border-radius: 3px; }}
  pre {{ background: #f4f4f4; padding: 10px; overflow-x: auto; }}
</style>
</head>
<body>

<h1>XML Namespace XSS — Local CTF</h1>

<p>
  This page has a text box that accepts a snippet of <strong>XML</strong>.
  Your input is parsed with <code>DOMParser</code> in XML mode and the
  resulting node is imported straight into the page's DOM. The page's own
  JavaScript never does anything with <code>&lt;script&gt;</code> tags, and
  there is no <code>innerHTML</code> of raw HTML anywhere — so naive payloads
  like <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> or
  <code>&lt;img onerror=...&gt;</code> (without a namespace) will just sit
  there as inert XML nodes.
</p>

<p><strong>Goal:</strong> make the page execute
  <code>alert(FLAG)</code> anyway.</p>

<form id="xmlForm">
  <textarea id="xmlInput" placeholder="Paste your XML payload here..."></textarea>
  <br><br>
  <button type="submit">Render XML</button>
</form>

<div id="sink"><em>(rendered XML will appear here)</em></div>

<details>
  <summary>Hint 1 (click to expand)</summary>
  <div class="hint">
    The sink parses your input as generic XML, so an element name like
    <code>&lt;body onload="..."&gt;</code> is just an arbitrary tag with an
    arbitrary attribute — it does nothing special. But browsers treat one
    specific XML namespace URI as meaning "this subtree is actually HTML":
    <code>http://www.w3.org/1999/xhtml</code>. If an element lives in that
    namespace, the browser renders it with full HTML behavior, including
    event handlers.
  </div>
</details>

<details>
  <summary>Hint 2 (click to expand)</summary>
  <div class="hint">
    You can declare a namespace prefix on any wrapper element with
    <code>xmlns:a="http://www.w3.org/1999/xhtml"</code>, then use that
    prefix on an HTML element name, e.g. <code>&lt;a:body onload="..."/&gt;</code>.
    Once that node is imported into the live document, the browser really
    does create it as a genuine <code>HTMLBodyElement</code> — the
    namespace trick works. But <code>onload</code>/<code>onerror</code>/
    <code>onscroll</code> on <code>&lt;body&gt;</code> are <em>special</em>:
    per spec they only forward to the <code>Window</code>'s own
    <code>load</code> event when that element is actually installed as
    <code>document.body</code>. Since our sink just appends it into an
    already-loaded page, it's never really "the" body, so that event never
    fires — this exact payload will sit there inertly here. You need an
    HTML element whose handler fires on <em>itself</em>, from an event
    targeted directly at that node, regardless of document structure.
  </div>
</details>

<details>
  <summary>Solution (click to expand — try it yourself first!)</summary>
  <pre>&lt;a xmlns:a="http://www.w3.org/1999/xhtml"&gt;&lt;a:img src="x" onerror="alert(FLAG)"/&gt;&lt;/a&gt;</pre>
  <p>
    The outer &lt;a&gt; element is just scaffolding to declare the namespace
    prefix. <code>a:img</code> resolves to a real
    <code>HTMLImageElement</code> because of the XHTML namespace — the same
    underlying trick as the <code>&lt;a:body onload&gt;</code> version. The
    difference is that <code>img</code>'s <code>error</code> event is
    dispatched directly on the <code>&lt;img&gt;</code> node itself the
    moment its (bogus) <code>src="x"</code> fails to load — it doesn't
    depend on being "the" document body, so it fires reliably as soon as
    the node is connected to the live DOM.
  </p>
</details>

<script>
  // Placeholder secret for this local practice page only.
  window.FLAG = {flag_js!r};

  document.getElementById('xmlForm').addEventListener('submit', function (e) {{
    e.preventDefault();
    const raw = document.getElementById('xmlInput').value;
    const sink = document.getElementById('sink');
    sink.innerHTML = '';

    // --- VULNERABLE SINK ---
    // Parsing as XML (not HTML) and importing nodes directly into the
    // document. This is the realistic pattern: think "render an uploaded
    // SVG", "render an Atom/RSS feed item", "render a custom XML template".
    const doc = new DOMParser().parseFromString(raw, 'application/xml');

    const parserError = doc.querySelector('parsererror');
    if (parserError) {{
      sink.textContent = 'XML parse error — check your syntax.';
      return;
    }}

    const imported = document.importNode(doc.documentElement, true);
    sink.appendChild(imported);
    // --- END VULNERABLE SINK ---
  }});
</script>

</body>
</html>
"""


class Handler(http.server.BaseHTTPRequestHandler):
    def _serve_page(self):
        body = PAGE.format(flag_js=FLAG).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Set-Cookie", "TheFlagIs="+FLAG+"; Max-Age=3600; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_page()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        # Quieter server log line.
        print("[server]", fmt % args)


def main():
    with socketserver.TCPServer((HOST, PORT), Handler) as httpd:
        print(f"Serving XML-namespace XSS CTF at http://{HOST}:{PORT}/")
        print("Press Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down.")


if __name__ == "__main__":
    main()
