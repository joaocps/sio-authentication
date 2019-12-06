from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature

import datetime
import os
import logging

logger = logging.getLogger('root')


class ServerCert:

    def __init__(self):
        self.private_key = None

    """
    Generate RSA key pair for certificate
    Note: password is hardcoded just for academic purpose 
    """

    def key_gen(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        if not os.path.exists("server-keys"):
            os.mkdir("server-keys")
        with open("server-keys/certKey.pem", "wb") as f:
            f.write(self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.BestAvailableEncryption(b'serverSIO'),
            ))

    """
    Generate server self signed certificate 
    """

    def cert_gen(self):
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u"PT"),
            x509.NameAttribute(NameOID.JURISDICTION_LOCALITY_NAME, u"Aveiro"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u"Aveiro"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SIO"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"serverSIO"),
        ])
        if self.private_key is not None:
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=10)
            ).add_extension(
                x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
                critical=False,
            ).sign(self.private_key, hashes.SHA256(), default_backend())

            if not os.path.exists("certs"):
                os.mkdir("certs")
            with open("certs/server.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))

    """
    Test validity of server certificate
    """

    def is_valid(self, cert):
        if cert.not_valid_before < datetime.datetime.utcnow() < cert.not_valid_after:
            try:
                cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(),
                                         cert.signature_hash_algorithm)
            except InvalidSignature:
                return False

            return True
        else:
            return False

    def load_cert(self):
        with open("certs/server.pem", "rb") as f:
            cert = f.read()
        return load_pem_x509_certificate(cert, default_backend())

    def load_privKey_cert(self):
        with open("server-keys/certKey.pem", "rb") as key:
            return serialization.load_pem_private_key(
                key.read(),
                password=b'serverSIO',
                backend=default_backend()
            )


def main():
    """
    Main function that invoke method to create certificate if none exists or
    test validity this exists, if validity fails generate a new certificate
    """
    s = ServerCert()
    if not os.path.exists("certs/server.pem"):
        logger.info("No certificate found, Generating")
        s.key_gen()
        s.cert_gen()
    else:
        cert = s.load_cert()
        if s.is_valid(cert):
            logger.info("Certificate still valid")
        else:
            logger.error("Certificate expired generating a new one")
            s.key_gen()
            s.cert_gen()

# to test module
# if __name__ == '__main__':
#     main()
