#!/usr/bin/env python3
"""Validate and re-sign an AMD TPM 2.0 EK certificate."""

from __future__ import annotations

import argparse
import os
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtensionOID,
    NameOID,
)

EK_CERTIFICATE_EKU = x509.ObjectIdentifier("2.23.133.8.1")
OID_TCG_TPM_MANUFACTURER = x509.ObjectIdentifier("2.23.133.2.1")
OID_TCG_TPM_MODEL = x509.ObjectIdentifier("2.23.133.2.2")
OID_TCG_TPM_VERSION = x509.ObjectIdentifier("2.23.133.2.3")

EK_TPM_MANUFACTURER = "AMD"
EK_TPM_MODEL = "AMD"
EK_TPM_SAN_MANUFACTURER = "id:414D4400"
EK_TPM_SAN_VERSION = "id:00060300"
EK_VALIDITY_YEARS = 10
MIN_SERIAL_BITS = 128
MAX_SERIAL_BITS = 159
EXPECTED_AIA_URI = "http://ftpm.amd.com:8080/pki/aia/amd-ftpm-ca.cer"

EXPECTED_SUBJECT_DIRECTORY_ATTRIBUTES = bytes.fromhex(
    "3019301706056781050210310e300c0c03322e30020100020200b7"
)

AMD_CA_SUBJECT = x509.Name(
    [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Advanced Micro Devices"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AMD fTPM CA"),
    ]
)

AMD_EK_SUBJECT = x509.Name(
    [
        x509.NameAttribute(OID_TCG_TPM_MANUFACTURER, EK_TPM_MANUFACTURER),
        x509.NameAttribute(OID_TCG_TPM_MODEL, EK_TPM_MODEL),
    ]
)

AMD_EK_DIRECTORY_NAME = x509.Name(
    [
        x509.NameAttribute(OID_TCG_TPM_MANUFACTURER, EK_TPM_SAN_MANUFACTURER),
        x509.NameAttribute(OID_TCG_TPM_MODEL, EK_TPM_MODEL),
        x509.NameAttribute(OID_TCG_TPM_VERSION, EK_TPM_SAN_VERSION),
    ]
)

PROFILE_EXTENSION_OIDS = {
    ExtensionOID.EXTENDED_KEY_USAGE,
    ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES,
    ExtensionOID.KEY_USAGE,
}

REISSUED_EXTENSION_OIDS = PROFILE_EXTENSION_OIDS | {
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.AUTHORITY_INFORMATION_ACCESS,
}

ISSUER_EXTENSION_OIDS = {
    ExtensionOID.SUBJECT_KEY_IDENTIFIER,
    ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
    ExtensionOID.BASIC_CONSTRAINTS,
    ExtensionOID.KEY_USAGE,
}

def load_certificate(path: Path) -> x509.Certificate:
    data = path.read_bytes()
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)

def public_key_der(key: object) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

def validity_utc(certificate: x509.Certificate) -> tuple[datetime, datetime]:
    not_valid_before = getattr(certificate, "not_valid_before_utc", None)
    not_valid_after = getattr(certificate, "not_valid_after_utc", None)
    if not_valid_before is None:
        not_valid_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
    if not_valid_after is None:
        not_valid_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)
    return not_valid_before, not_valid_after

def verify_certificate_signature(
    certificate: x509.Certificate, public_key: object
) -> None:
    parameters = certificate.signature_algorithm_parameters
    algorithm = certificate.signature_hash_algorithm
    if algorithm is None:
        raise ValueError("certificate signature has no supported hash algorithm")

    if isinstance(public_key, rsa.RSAPublicKey):
        if not isinstance(parameters, (padding.PKCS1v15, padding.PSS)):
            raise ValueError("unsupported RSA certificate signature parameters")
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
        raise ValueError("certificate signing key must be RSA or EC")

def _add_years(moment: datetime, years: int) -> datetime:
    try:
        return moment.replace(year=moment.year + years)
    except ValueError:
        return moment.replace(year=moment.year + years, day=28)

def _extension(
    certificate: x509.Certificate,
    oid: x509.ObjectIdentifier,
    *,
    critical: bool,
) -> x509.Extension[x509.ExtensionType]:
    extension = certificate.extensions.get_extension_for_oid(oid)
    if extension.critical is not critical:
        state = "critical" if critical else "non-critical"
        raise ValueError(f"{oid.dotted_string} must be {state}")
    return extension

def _validate_public_key(public_key: object) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size not in {2048, 3072, 4096}:
            raise ValueError("RSA EK key size must be 2048, 3072, or 4096 bits")
        if public_key.public_numbers().e != 65537:
            raise ValueError("RSA EK public exponent must be 65537")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise ValueError("ECC EK curve must be P-256 or P-384")
        return
    raise ValueError("EK public key must be RSA or EC")

def _validate_key_usage(usage: x509.KeyUsage, public_key: object) -> None:
    always_false = (
        usage.digital_signature,
        usage.content_commitment,
        usage.data_encipherment,
        usage.key_cert_sign,
        usage.crl_sign,
    )
    if any(always_false):
        raise ValueError("EK KeyUsage contains a disallowed capability")

    if isinstance(public_key, rsa.RSAPublicKey):
        if not usage.key_encipherment or usage.key_agreement:
            raise ValueError("RSA EK KeyUsage must contain only keyEncipherment")
        return

    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError("EK public key must be RSA or EC")
    if usage.key_encipherment or not usage.key_agreement:
        raise ValueError("ECC EK KeyUsage must contain only keyAgreement")
    if usage.encipher_only or usage.decipher_only:
        raise ValueError("ECC EK KeyUsage must not set encipherOnly or decipherOnly")

def validate_issuer(certificate: x509.Certificate) -> None:
    if certificate.subject != AMD_CA_SUBJECT:
        raise ValueError("issuer subject does not match the pinned AMD fTPM CA profile")
    if certificate.issuer != certificate.subject:
        raise ValueError("issuer certificate must be self-issued")

    public_key = certificate.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048 or public_key.public_numbers().e != 65537:
            raise ValueError("issuer RSA key is below the pinned profile")
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in {"secp256r1", "secp384r1"}:
            raise ValueError("issuer EC curve is outside the pinned profile")
    else:
        raise ValueError("issuer certificate key must be RSA or EC")

    present = {extension.oid for extension in certificate.extensions}
    if present != ISSUER_EXTENSION_OIDS:
        raise ValueError("issuer certificate extension set is not exact")

    constraints = _extension(
        certificate, ExtensionOID.BASIC_CONSTRAINTS, critical=True
    ).value
    if not constraints.ca or constraints.path_length is not None:
        raise ValueError("issuer BasicConstraints must be CA:TRUE without a path limit")

    usage = _extension(certificate, ExtensionOID.KEY_USAGE, critical=True).value
    if (
        usage.digital_signature
        or usage.content_commitment
        or usage.key_encipherment
        or usage.data_encipherment
        or usage.key_agreement
        or not usage.key_cert_sign
        or not usage.crl_sign
    ):
        raise ValueError("issuer KeyUsage must contain only keyCertSign and cRLSign")

    subject_key_identifier = _extension(
        certificate, ExtensionOID.SUBJECT_KEY_IDENTIFIER, critical=False
    ).value
    authority_key_identifier = _extension(
        certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False
    ).value
    if authority_key_identifier.key_identifier != subject_key_identifier.digest:
        raise ValueError("issuer AKI does not match its SKI")

    verify_certificate_signature(certificate, public_key)
    not_valid_before, not_valid_after = validity_utc(certificate)
    now = datetime.now(timezone.utc)
    if not not_valid_before <= now <= not_valid_after:
        raise ValueError("issuer certificate is not currently valid")

def validate_ek_profile(
    certificate: x509.Certificate,
) -> None:
    present = {extension.oid for extension in certificate.extensions}
    unknown = present - REISSUED_EXTENSION_OIDS
    missing = PROFILE_EXTENSION_OIDS - present
    if unknown:
        names = ", ".join(sorted(oid.dotted_string for oid in unknown))
        raise ValueError(f"EK certificate has unapproved extensions: {names}")
    if missing:
        names = ", ".join(sorted(oid.dotted_string for oid in missing))
        raise ValueError(f"EK certificate is missing required extensions: {names}")

    public_key = certificate.public_key()
    _validate_public_key(public_key)

    eku = _extension(
        certificate, ExtensionOID.EXTENDED_KEY_USAGE, critical=False
    ).value
    if list(eku) != [EK_CERTIFICATE_EKU]:
        raise ValueError("EK certificate EKU must contain only tcg-kp-EKCertificate")

    san = _extension(
        certificate, ExtensionOID.SUBJECT_ALTERNATIVE_NAME, critical=True
    ).value
    if list(san) != [x509.DirectoryName(AMD_EK_DIRECTORY_NAME)]:
        raise ValueError("EK certificate SAN does not match the pinned AMD identity")

    constraints = _extension(
        certificate, ExtensionOID.BASIC_CONSTRAINTS, critical=True
    ).value
    if constraints.ca or constraints.path_length is not None:
        raise ValueError("EK certificate BasicConstraints must be CA:FALSE")

    directory_attributes = _extension(
        certificate, ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES, critical=False
    ).value
    if not isinstance(directory_attributes, x509.UnrecognizedExtension):
        raise ValueError("unexpected SubjectDirectoryAttributes representation")
    if directory_attributes.value != EXPECTED_SUBJECT_DIRECTORY_ATTRIBUTES:
        raise ValueError("TPM specification attributes are not 2.0/0/1.83")

    usage = _extension(certificate, ExtensionOID.KEY_USAGE, critical=True).value
    _validate_key_usage(usage, public_key)

def _strong_serial_number(current: int) -> int:
    if MIN_SERIAL_BITS <= current.bit_length() <= MAX_SERIAL_BITS:
        return current
    while True:
        candidate = x509.random_serial_number()
        if MIN_SERIAL_BITS <= candidate.bit_length() <= MAX_SERIAL_BITS:
            return candidate

def validate_reissued_certificate(
    certificate: x509.Certificate,
    issuer_certificate: x509.Certificate,
    expected_public_key: object,
    aia_uri: str,
) -> None:
    validate_ek_profile(certificate)
    if {extension.oid for extension in certificate.extensions} != REISSUED_EXTENSION_OIDS:
        raise RuntimeError("reissued EK certificate extension set is not exact")
    if certificate.subject != AMD_EK_SUBJECT:
        raise RuntimeError("reissued EK subject does not match the AMD profile")
    if certificate.issuer != issuer_certificate.subject:
        raise RuntimeError("reissued EK issuer changed unexpectedly")
    if not MIN_SERIAL_BITS <= certificate.serial_number.bit_length() <= MAX_SERIAL_BITS:
        raise RuntimeError("reissued EK serial number is not high entropy")
    if public_key_der(certificate.public_key()) != public_key_der(expected_public_key):
        raise RuntimeError("EK public key changed while rebuilding certificate")

    issuer_ski = issuer_certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_KEY_IDENTIFIER
    ).value
    authority_key_identifier = _extension(
        certificate, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, critical=False
    ).value
    if authority_key_identifier.key_identifier != issuer_ski.digest:
        raise RuntimeError("reissued EK AKI does not match issuer SKI")

    aia = _extension(
        certificate, ExtensionOID.AUTHORITY_INFORMATION_ACCESS, critical=False
    ).value
    expected_aia = x509.AuthorityInformationAccess(
        [
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(aia_uri),
            )
        ]
    )
    if aia != expected_aia:
        raise RuntimeError("reissued EK AIA does not match the pinned endpoint")

    verify_certificate_signature(certificate, issuer_certificate.public_key())
    not_valid_before, not_valid_after = validity_utc(certificate)
    issuer_not_before, issuer_not_after = validity_utc(issuer_certificate)
    now = datetime.now(timezone.utc)
    if not issuer_not_before <= not_valid_before <= now <= not_valid_after:
        raise RuntimeError("reissued EK validity window is incoherent")
    if not_valid_after > issuer_not_after:
        raise RuntimeError("reissued EK certificate outlives its issuer")
    if not_valid_after > _add_years(not_valid_before, EK_VALIDITY_YEARS):
        raise RuntimeError("reissued EK validity exceeds ten years")

def atomic_write(path: Path, data: bytes) -> None:
    current_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o640
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary_path, current_mode)
        os.replace(temporary_path, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary_path.unlink(missing_ok=True)

def reissue_certificate(
    certificate_path: Path,
    issuer_certificate_path: Path,
    issuer_key_path: Path,
    aia_uri: str,
) -> None:
    if aia_uri != EXPECTED_AIA_URI:
        raise ValueError("AIA URI does not match the pinned AMD endpoint")

    certificate = load_certificate(certificate_path)
    issuer_certificate = load_certificate(issuer_certificate_path)
    issuer_key = serialization.load_pem_private_key(
        issuer_key_path.read_bytes(), password=None
    )

    if not isinstance(issuer_key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise ValueError("issuer key must be RSA or EC")
    if public_key_der(issuer_key.public_key()) != public_key_der(
        issuer_certificate.public_key()
    ):
        raise ValueError("issuer private key does not match issuer certificate")

    validate_issuer(issuer_certificate)
    if certificate.issuer != issuer_certificate.subject:
        raise ValueError("EK certificate issuer does not match configured CA subject")
    verify_certificate_signature(certificate, issuer_certificate.public_key())
    validate_ek_profile(certificate)

    input_not_before, input_not_after = validity_utc(certificate)
    issuer_not_before, issuer_not_after = validity_utc(issuer_certificate)
    now = datetime.now(timezone.utc)
    if not input_not_before <= now <= input_not_after:
        raise ValueError("input EK certificate is not currently valid")

    not_valid_before = max(input_not_before, issuer_not_before)
    not_valid_after = min(
        _add_years(not_valid_before, EK_VALIDITY_YEARS), issuer_not_after
    )
    if not_valid_after <= not_valid_before:
        raise ValueError("issuer validity cannot contain a new EK certificate")

    builder = (
        x509.CertificateBuilder()
        .subject_name(AMD_EK_SUBJECT)
        .issuer_name(issuer_certificate.subject)
        .public_key(certificate.public_key())
        .serial_number(_strong_serial_number(certificate.serial_number))
        .not_valid_before(not_valid_before)
        .not_valid_after(not_valid_after)
    )

    for oid in (
        ExtensionOID.EXTENDED_KEY_USAGE,
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.SUBJECT_DIRECTORY_ATTRIBUTES,
        ExtensionOID.KEY_USAGE,
    ):
        extension = certificate.extensions.get_extension_for_oid(oid)
        builder = builder.add_extension(extension.value, extension.critical)

    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(
            issuer_certificate.public_key()
        ),
        critical=False,
    )
    builder = builder.add_extension(
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(
                    AuthorityInformationAccessOID.CA_ISSUERS,
                    x509.UniformResourceIdentifier(aia_uri),
                )
            ]
        ),
        critical=False,
    )

    reissued = builder.sign(private_key=issuer_key, algorithm=hashes.SHA256())
    validate_reissued_certificate(
        reissued,
        issuer_certificate,
        certificate.public_key(),
        aia_uri,
    )
    atomic_write(certificate_path, reissued.public_bytes(serialization.Encoding.DER))

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--certificate", required=True, type=Path)
    parser.add_argument("--issuer-certificate", required=True, type=Path)
    parser.add_argument("--issuer-key", required=True, type=Path)
    parser.add_argument("--aia-uri", required=True)
    return parser.parse_args()

def main() -> int:
    args = parse_args()
    reissue_certificate(
        args.certificate,
        args.issuer_certificate,
        args.issuer_key,
        args.aia_uri,
    )
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
