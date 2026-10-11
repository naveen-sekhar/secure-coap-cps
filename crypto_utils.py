"""Cryptographic credentials and certificate generation for CPS devices and Gateway.

Generates genuine X.509 certificates for mutual DTLS authentication.
Never uses custom encryption; leverages OpenSSL via cryptography & pyOpenSSL.
"""

import os
import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

def _generate_rsa_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def _save_key_pem(key, path):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(path, "wb") as f:
        f.write(pem)

def _save_cert_pem(cert, path):
    pem = cert.public_bytes(serialization.Encoding.PEM)
    with open(path, "wb") as f:
        f.write(pem)

def generate_ca(output_dir=CERTS_DIR, common_name="CPS-Root-CA"):
    os.makedirs(output_dir, exist_ok=True)
    ca_key = _generate_rsa_key()
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure CPS Research Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_path = os.path.join(output_dir, "ca.crt")
    key_path = os.path.join(output_dir, "ca.key")
    _save_cert_pem(ca_cert, cert_path)
    _save_key_pem(ca_key, key_path)
    return cert_path, key_path, ca_cert, ca_key

def generate_signed_cert(ca_cert, ca_key, common_name, filename_prefix, output_dir=CERTS_DIR):
    os.makedirs(output_dir, exist_ok=True)
    device_key = _generate_rsa_key()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure CPS Research Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(device_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    cert_path = os.path.join(output_dir, f"{filename_prefix}.crt")
    key_path = os.path.join(output_dir, f"{filename_prefix}.key")
    _save_cert_pem(cert, cert_path)
    _save_key_pem(device_key, key_path)
    return cert_path, key_path

def ensure_credentials(certs_dir=CERTS_DIR):
    """Generate all lab certificates if they do not exist."""
    os.makedirs(certs_dir, exist_ok=True)
    ca_crt_path = os.path.join(certs_dir, "ca.crt")
    ca_key_path = os.path.join(certs_dir, "ca.key")
    
    if os.path.exists(ca_crt_path) and os.path.exists(ca_key_path):
        with open(ca_crt_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    else:
        _, _, ca_cert, ca_key = generate_ca(certs_dir)

    devices = [
        ("coap-gateway", "gateway"),
        ("sensor-01", "sensor_01"),
        ("controller-01", "controller_01"),
    ]
    for cn, prefix in devices:
        c_path = os.path.join(certs_dir, f"{prefix}.crt")
        k_path = os.path.join(certs_dir, f"{prefix}.key")
        if not (os.path.exists(c_path) and os.path.exists(k_path)):
            generate_signed_cert(ca_cert, ca_key, cn, prefix, certs_dir)

    # Also generate an untrusted rogue certificate signed by an untrusted rogue CA for attack simulation
    rogue_dir = os.path.join(certs_dir, "rogue")
    os.makedirs(rogue_dir, exist_ok=True)
    rogue_ca_crt = os.path.join(rogue_dir, "rogue_ca.crt")
    if not os.path.exists(rogue_ca_crt):
        _, _, r_ca_cert, r_ca_key = generate_ca(rogue_dir, common_name="Rogue-Attacker-CA")
        generate_signed_cert(r_ca_cert, r_ca_key, "rogue-attacker", "rogue_device", rogue_dir)

if __name__ == "__main__":
    ensure_credentials()
    print(f"All certificates successfully generated in: {CERTS_DIR}")
