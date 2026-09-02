#!/usr/bin/env python3
"""Serve one validated DER TPM issuer certificate on an exact HTTP route."""

from __future__ import annotations

import argparse
import ipaddress
import re
import threading
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

AMD_CA_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AMD fTPM CA"),
    ]
)
ISSUER_EXTENSION_OIDS = {
    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.KEY_USAGE,
}
DNS_NAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)

class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, *args: object, **kwargs: object) -> None:
        self._request_slots = threading.BoundedSemaphore(8)
        super().__init__(*args, **kwargs)

    def process_request(self, request: object, client_address: object) -> None:
        if not self._request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._request_slots.release()
            raise

    def process_request_thread(self, request: object, client_address: object) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._request_slots.release()

def validity_utc(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    not_valid_before = getattr(certificate, "not_valid_before_utc", None)
    not_valid_after = getattr(certificate, "not_valid_after_utc", None)
    if not_valid_before is None:
        not_valid_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if not_valid_after is None:
        not_valid_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return not_valid_before, not_valid_after

def verify_self_signature(certificate: x509.Certificate) -> None:
    public_key = certificate.public_key()
    algorithm = certificate.signature_hash_algorithm
    parameters = certificate.signature_algorithm_parameters
    if algorithm is None:
        raise ValueError("issuer signature has no supported hash algorithm")

    if isinstance(public_key, rsa.RSAPublicKey):
        if not isinstance(parameters, (padding.PKCS1v15, padding.PSS)):
            raise ValueError("unsupported RSA issuer signature parameters")
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            parameters,
            algorithm,
        )
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if not isinstance(parameters, ec.ECDSA):
            parameters = ec.ECDSA(algorithm)
        public_key.verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            parameters,
        )
    else:
        raise ValueError("issuer key must be RSA or EC")

def validate_issuer_certificate(certificate: x509.Certificate) -> None:
    if certificate.subject != AMD_CA_SUBJECT:
        raise ValueError("certificate subject does not match the pinned AMD fTPM CA")
    if certificate.issuer != certificate.subject:
        raise ValueError("certificate must be self-issued")

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048 or public_key.public_numbers().e != 65537:
            raise ValueError("issuer RSA key is below the pinned profile")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise ValueError("issuer EC curve is outside the pinned profile")
    else:
        raise ValueError("issuer key must be RSA or EC")

    present = {extension.oid for extension in certificate.extensions}
    if present != ISSUER_EXTENSION_OIDS:
        raise ValueError("issuer certificate extension set is not exact")

    constraints_extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS
    )
    if (
        not constraints_extension.critical
        or not constraints_extension.value.ca
        or constraints_extension.value.path_length is not None
    ):
        raise ValueError("certificate must have critical CA:TRUE without a path limit")

    usage_extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.KEY_USAGE
    )
    usage = usage_extension.value
    if (
        not usage_extension.critical
        or usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or not usage.key_cert_sign
        or not usage.crl_sign
    ):
        raise ValueError("certificate KeyUsage must contain only CA signing usage")

    ski_extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    )
    aki_extension = certificate.extensions.get_extension_for_oid(
        ExtensionOID.AUTHORITY_KEY_IDENTIFIER
    )
    if ski_extension.critical or aki_extension.critical:
        raise ValueError("issuer SKI and AKI must be non-critical")
    if aki_extension.value.key_identifier != ski_extension.value.digest:
        raise ValueError("issuer AKI does not match its SKI")

    verify_self_signature(certificate)
    not_valid_before, not_valid_after = validity_utc(certificate)
    now = datetime.now(timezone.utc)
    if not not_valid_before <= now <= not_valid_after:
        raise ValueError("issuer certificate is not currently valid")

def make_handler(
    certificate: bytes,
    route: str,
    expected_host: str,
) -> type[BaseHTTPRequestHandler]:
    class CertificateHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(5)

        def _write_response(
            self,
            status: HTTPStatus,
            body: bytes = b"",
            *,
            content_type: str | None = None,
            include_body: bool = True,
            declared_length: int | None = None,
            allow: str | None = None,
        ) -> None:
            self.send_response_only(status)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            if allow is not None:
                self.send_header("Allow", allow)
            length = len(body) if declared_length is None else declared_length
            self.send_header("Content-Length", str(length))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if include_body and body:
                self.wfile.write(body)

        def _host_matches(self) -> bool:
            supplied = self.headers.get("Host", "").strip().lower()
            port = self.server.server_port
            return supplied in {expected_host, f"{expected_host}:{port}"}

        def send_certificate(self, include_body: bool) -> None:
            if not self._host_matches() or self.path != route:
                self._write_response(HTTPStatus.NOT_FOUND)
                return
            self._write_response(
                HTTPStatus.OK,
                certificate,
                content_type="application/pkix-cert",
                include_body=include_body,
                declared_length=len(certificate),
            )

        def do_GET(self) -> None:
            self.send_certificate(include_body=True)

        def do_HEAD(self) -> None:
            self.send_certificate(include_body=False)

        def _method_not_allowed(self) -> None:
            self._write_response(HTTPStatus.METHOD_NOT_ALLOWED, allow="GET, HEAD")

        do_POST = _method_not_allowed
        do_PUT = _method_not_allowed
        do_PATCH = _method_not_allowed
        do_DELETE = _method_not_allowed
        do_OPTIONS = _method_not_allowed
        do_TRACE = _method_not_allowed
        do_CONNECT = _method_not_allowed

        def send_error(
            self,
            code: int,
            message: str | None = None,
            explain: str | None = None,
        ) -> None:
            del message, explain
            self._write_response(HTTPStatus(code))

        def log_message(self, format_string: str, *args: object) -> None:
            print(f"{self.client_address[0]} - {format_string % args}", flush=True)

    return CertificateHandler

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--route", default="/pki/aia/amd-ftpm-ca.cer")
    parser.add_argument("--host", default="ftpm.amd.com")
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    bind_address = ipaddress.ip_address(args.bind)
    if bind_address.version != 4:
        raise ValueError("bind address must be an IPv4 literal")
    if not 1 <= args.port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    if not args.route.startswith("/") or "?" in args.route or "#" in args.route:
        raise ValueError("route must be an absolute URL path without query or fragment")

    expected_host = args.host.lower().rstrip(".")
    if not DNS_NAME.fullmatch(expected_host):
        raise ValueError("host must be a valid DNS name without a port")

    certificate_bytes = args.certificate.read_bytes()
    if not certificate_bytes:
        raise ValueError("certificate is empty")
    certificate = x509.load_der_x509_certificate(certificate_bytes)
    validate_issuer_certificate(certificate)
    if args.check:
        return 0

    handler = make_handler(certificate_bytes, args.route, expected_host)
    with ReusableThreadingHTTPServer((str(bind_address), args.port), handler) as server:
        server.serve_forever()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
