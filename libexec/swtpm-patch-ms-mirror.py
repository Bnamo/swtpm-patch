#!/usr/bin/env python3
"""swtpm-patch-ms-mirror.py - TLS mirror for the detector's TrustedTpm.cab fetch."""
import ssl, sys, argparse
from http.server import HTTPServer, BaseHTTPRequestHandler

FWLINK_PATH = "/fwlink"
CAB_PATH = "/download/D/6/5/D65270B2-EAFD-43FD-B9BA-F65CA00B153E/TrustedTpm.cab"
CAB_TARGET = "https://download.microsoft.com" + CAB_PATH


class H(BaseHTTPRequestHandler):
    cab_file = None

    def log_message(self, fmt, *args):
        sys.stderr.write("[ms-mirror] %s %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        host = self.headers.get("Host", "")
        if "go.microsoft.com" in host and self.path.startswith(FWLINK_PATH):
            self.send_response(302)
            self.send_header("Location", CAB_TARGET)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path.split("?")[0] == CAB_PATH:
            data = open(self.cab_file, "rb").read()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--cab", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    a = ap.parse_args()
    H.cab_file = a.cab

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(a.cert, a.key)
    srv = HTTPServer((a.bind, a.port), H)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
