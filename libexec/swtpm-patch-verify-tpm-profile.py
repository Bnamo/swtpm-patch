#!/usr/bin/env python3
"""Emit a machine-readable coherence report for an AMD TPM EK certificate pair."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

def load_reissuer(path: Path | None) -> ModuleType:
    candidates = []
    if path is not None:
        candidates.append(path)
    candidates.extend(
        [
            Path(__file__).with_name("swtpm-patch-reissue-ek-cert.py"),
            Path("/usr/local/libexec/swtpm-patch-reissue-ek-cert.py"),
        ]
    )
    module_path = next((candidate for candidate in candidates if candidate.is_file()), None)
    if module_path is None:
        raise FileNotFoundError("reissuer not found")
    spec = importlib.util.spec_from_file_location("swtpm_reissue_ek_cert", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot import {module_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def load_public_key(path: Path) -> object:
    data = path.read_bytes()
    try:
        return serialization.load_pem_public_key(data)
    except ValueError:
        return serialization.load_der_public_key(data)

def key_der(key: object) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

class Report:
    def __init__(self) -> None:
        self.checks: dict[str, bool] = {}
        self.failures: list[str] = []

    def check(self, name: str, condition: bool, detail: str) -> None:
        self.checks[name] = bool(condition)
        if not condition:
            self.failures.append(f"{name}: {detail}")

    def run(self, name: str, function: object) -> None:
        try:
            function()
        except Exception as exc:
            detail = str(exc) or type(exc).__name__
            self.check(name, False, detail)
        else:
            self.check(name, True, "")

def certificate_summary(certificate: x509.Certificate) -> dict[str, object]:
    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_profile = f"rsa-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_profile = f"ecc-{public_key.curve.name}"
    else:
        key_profile = type(public_key).__name__
    not_before = getattr(certificate, "not_valid_before_utc", None)
    not_after = getattr(certificate, "not_valid_after_utc", None)
    if not_before is None:
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if not_after is None:
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serial_hex": format(certificate.serial_number, "x"),
        "serial_bits": certificate.serial_number.bit_length(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "public_key_profile": key_profile,
        "sha256": hashlib.sha256(
            certificate.public_bytes(serialization.Encoding.DER)
        ).hexdigest(),
    }

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--issuer", required=True, type=Path)
    parser.add_argument("--rsa-certificate", required=True, type=Path)
    parser.add_argument("--ecc-certificate", required=True, type=Path)
    parser.add_argument("--rsa-public", required=True, type=Path)
    parser.add_argument("--ecc-public", required=True, type=Path)
    parser.add_argument("--rsa-bits", type=int, default=2048)
    parser.add_argument("--ecc-curve", default="secp384r1")
    parser.add_argument("--reissuer-module", type=Path)
    parser.add_argument("--output", type=Path)
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    profile = load_reissuer(args.reissuer_module)
    issuer = profile.load_certificate(args.issuer)
    rsa_certificate = profile.load_certificate(args.rsa_certificate)
    ecc_certificate = profile.load_certificate(args.ecc_certificate)
    report = Report()

    report.run("issuer_profile", lambda: profile.validate_issuer(issuer))
    report.run(
        "rsa_certificate_profile",
        lambda: profile.validate_reissued_certificate(
            rsa_certificate,
            issuer,
            rsa_certificate.public_key(),
            profile.EXPECTED_AIA_URI,
        ),
    )
    report.run(
        "ecc_certificate_profile",
        lambda: profile.validate_reissued_certificate(
            ecc_certificate,
            issuer,
            ecc_certificate.public_key(),
            profile.EXPECTED_AIA_URI,
        ),
    )

    for label, certificate in (
        ("rsa", rsa_certificate),
        ("ecc", ecc_certificate),
    ):
        report.check(
            f"{label}_subject",
            certificate.subject == profile.AMD_EK_SUBJECT,
            "EK subject differs from the pinned AMD profile",
        )
        report.check(
            f"{label}_serial_strength",
            profile.MIN_SERIAL_BITS
            <= certificate.serial_number.bit_length()
            <= profile.MAX_SERIAL_BITS,
            "EK serial is outside the 128-159 bit profile",
        )

    rsa_key = rsa_certificate.public_key()
    ecc_key = ecc_certificate.public_key()
    report.check(
        "rsa_key_type",
        isinstance(rsa_key, rsa.RSAPublicKey),
        "RSA certificate does not contain an RSA key",
    )
    report.check(
        "rsa_key_bits",
        isinstance(rsa_key, rsa.RSAPublicKey) and rsa_key.key_size == args.rsa_bits,
        f"expected RSA-{args.rsa_bits}",
    )
    report.check(
        "ecc_key_type",
        isinstance(ecc_key, ec.EllipticCurvePublicKey),
        "ECC certificate does not contain an EC key",
    )
    report.check(
        "ecc_curve",
        isinstance(ecc_key, ec.EllipticCurvePublicKey)
        and ecc_key.curve.name == args.ecc_curve,
        f"expected {args.ecc_curve}",
    )
    report.check(
        "serials_unique",
        rsa_certificate.serial_number != ecc_certificate.serial_number,
        "RSA and ECC EK certificates share a serial number",
    )

    expected_rsa = load_public_key(args.rsa_public)
    report.check(
        "rsa_tpm_public_match",
        key_der(rsa_key) == key_der(expected_rsa),
        "RSA certificate key differs from the TPM persistent EK",
    )
    expected_ecc = load_public_key(args.ecc_public)
    report.check(
        "ecc_tpm_public_match",
        key_der(ecc_key) == key_der(expected_ecc),
        "ECC certificate key differs from the TPM persistent EK",
    )

    result = {
        "schema": "swtpm-amd-tpm-profile-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "passed": not report.failures,
        "checks": report.checks,
        "failures": report.failures,
        "issuer": certificate_summary(issuer),
        "rsa": certificate_summary(rsa_certificate),
        "ecc": certificate_summary(ecc_certificate),
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
