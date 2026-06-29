"""
TrustFeed — Certificate helpers
Low-level primitives for key generation, certificate building,
serialization and loading. Used by authority.py — not called directly.

Algorithm map (from technical diagram):
  Root CA key:        RSA-4096
  Intermediate CA:    ECDSA P-384
  Publisher cert:     ECDSA P-256
  IOC signing key:    Ed25519  (keypair, not a certificate)
"""

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# ── Key generation ────────────────────────────────────────────────────────────

def gen_rsa_4096():
    """RSA-4096 private key — Root CA only."""
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def gen_ecdsa_p384():
    """ECDSA P-384 private key — Intermediate CA."""
    return ec.generate_private_key(ec.SECP384R1())


def gen_ecdsa_p256():
    """ECDSA P-256 private key — publisher identity certificates."""
    return ec.generate_private_key(ec.SECP256R1())


def gen_ed25519():
    """Ed25519 private key — IOC signing (not used in X.509 certs)."""
    return ed25519.Ed25519PrivateKey.generate()


# ── Subject builder ───────────────────────────────────────────────────────────

def build_subject(cn: str, org: str = "TrustFeed", country: str = "NP") -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


# ── Certificate builders ──────────────────────────────────────────────────────

def build_root_ca_cert(key, subject: x509.Name, validity_days: int) -> x509.Certificate:
    """
    Self-signed Root CA certificate.
    RSA-4096 key, SHA-256 signature, basic constraints CA=True path_length=1.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)          # self-signed
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def build_intermediate_ca_cert(
    int_key, root_key, root_cert: x509.Certificate,
    subject: x509.Name, validity_days: int
) -> x509.Certificate:
    """
    Intermediate CA certificate signed by Root CA.
    ECDSA P-384 key, path_length=0 (cannot issue further CAs).
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(int_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )


def build_publisher_cert(
    pub_key, int_key, int_cert: x509.Certificate,
    subject: x509.Name, validity_days: int
) -> x509.Certificate:
    """
    Publisher end-entity certificate signed by Intermediate CA.
    ECDSA P-256 key. Extended key usage: digital signature only.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(int_cert.subject)
        .public_key(pub_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(pub_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()),
            critical=False,
        )
        .sign(int_key, hashes.SHA256())
    )


# ── Serialization ─────────────────────────────────────────────────────────────

def save_private_key(key, path: Path, password: bytes = None) -> None:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password else serialization.NoEncryption()
    )
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        enc,
    ))


def save_cert(cert: x509.Certificate, path: Path) -> None:
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def load_private_key(path: Path, password: bytes = None):
    return serialization.load_pem_private_key(path.read_bytes(), password)


def load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def save_ed25519_private(key, path: Path) -> None:
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))


def save_ed25519_public(key, path: Path) -> None:
    path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))


def load_ed25519_private(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), None)


def load_ed25519_public(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def ed25519_pub_b64(key) -> str:
    """Return base64 of Ed25519 public key raw bytes — stored in publisher registry."""
    import base64
    raw = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode()