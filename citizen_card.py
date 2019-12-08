import sys
import PyKCS11
import logging
import datetime

from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from cryptography.x509.oid import *
from cryptography.x509 import *
from cryptography.exceptions import InvalidSignature


logger = logging.getLogger('root')
pkcs11 = PyKCS11.PyKCS11Lib()

# Add option for different SO (Win or linux)
pkcs11.load('C:\\Windows\\System32\\pteidpkcs11.dll' if sys.platform == 'win32' else '/usr/local/lib/libpteidpkcs11.so')


class CitizenCard:
    def __init__(self):
        """
        Constructor with of Citizen Card class, sessions and slots are named were
        """
        self.name = None
        self.slot = pkcs11.getSlotList()[-1]
        self.session = pkcs11.openSession(self.slot)
        self.backend = default_backend()

    def get_name(self):
        """
        Called to get the name of certificate owner
        @return: Certificate owner name
        """
        if self.name is None:
            certificate, *_ = self.get_x509_certificates()
            self.name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return self.name

    def get_x509_certificates(self, **kwargs):
        """
        Called to get the certificates
        @param kwargs: The KEY USAGE of certificate
        @return: Certificate's find
        """
        certificates = [load_der_x509_certificate(certificate, self.backend) for certificate in self.get_certificates()]
        if 'KEY_USAGE' not in kwargs:
            kwargs['KEY_USAGE'] = lambda ku: ku.value.digital_signature and ku.value.key_agreement
            print(kwargs['KEY_USAGE'])
        for key, value in kwargs.items():
            if key in dir(ExtensionOID):
                certificates = [certificate for certificate in certificates if
                                value(certificate.extensions.get_extension_for_oid(getattr(ExtensionOID, key)))]
            elif key in dir(NameOID):
                certificates = [certificate for certificate in certificates if
                                value(certificate.subject.get_attributes_for_oid(getattr(NameOID, key)))]
        return certificates

    def get_certificates(self):
        certificates = list()
        attribute_keys = [key for key in list(PyKCS11.CKA.keys()) if isinstance(key, int)]
        for obj in self.session.findObjects():
            attributes = self.session.getAttributeValue(obj, attribute_keys)
            attributes = dict(zip(map(PyKCS11.CKA.get, attribute_keys), attributes))
            if attributes['CKA_CERTIFICATE_TYPE'] != None:
                certificates.append(bytes(attributes['CKA_VALUE']))
        return certificates

    def get_public_key(self,
                       transformation=lambda key: serialization.load_der_public_key(bytes(key.to_dict()['CKA_VALUE']),
                                                                                    default_backend())):
        return transformation(self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0])

    def get_private_key(self):
        return self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0]

    def serialize(self, key, encoding=serialization.Encoding.PEM, **kwargs):
        if type(key) == _Certificate:
            return key.public_bytes(encoding=encoding)
        elif type(key) == _RSAPublicKey:
            return key.public_bytes(encoding=encoding, format=kwargs[
                'format'] if 'format' in kwargs else serialization.PublicFormat.SubjectPublicKeyInfo)
        else:
            return key.private_bytes(encoding=encoding, format=kwargs[
                'format'] if 'format' in kwargs else serialization.PrivateFormat.TraditionalOpenSSL,
                                     encryption_algorithm=kwargs[
                                         'encryption_algorithm'] if 'encryption_algorithm' in kwargs else serialization.NoEncryption())

    def sign_with_cc(self, content, mechanism=PyKCS11.CKM_SHA1_RSA_PKCS, param=None):
        return self.session.sign(self.get_private_key(), content, PyKCS11.Mechanism(mechanism, param))

    def deserialize_x509_pem_cert_public_key(self, certificate):
        return load_pem_x509_certificate(certificate, default_backend()).public_key()

    def verify_signature(self, pkey, signature, data):
        try:
            pkey.verify(signature, data, asymmetric.padding.PKCS1v15(), hashes.SHA1())
        except InvalidSignature:
            return False
        return True

    def verify_cert_cc(self, cert):
        if cert.not_valid_before < datetime.datetime.utcnow() < cert.not_valid_after:
            cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuerid = cn[0].value[-4:]
            c = open(
                "certs\\cc\\EC de Aute ticacao do Cartao de Cidadao " + issuerid + ".pem"
                if sys.platform == 'win32'
                else "certs/cc/EC de Aute ticacao do Cartao de Cidadao " + issuerid + ".pem",
                "rb")
            c = load_pem_x509_certificate(c.read(), default_backend())
            if c.not_valid_before < datetime.datetime.utcnow() < c.not_valid_after:
                try:
                    c.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        asymmetric.padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                except InvalidSignature:
                    logger.error("Could not validate Citizen Card certificate")
                    return False
            else:
                logger.error("Sub CA certificate expired")
                return False
        else:
            logger.error("Client certificate expired")
            return False
        cn_sub_ca = c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        sub_ca_upid = cn_sub_ca[0].value[-3:]
        return self.verify_cert_subca(c, sub_ca_upid)

    def verify_cert_subca(self, cert, issuerid):
        if cert.not_valid_before < datetime.datetime.utcnow() < cert.not_valid_after:
            c = open(
                "certs\\cc\\Cartao de Cidadao " + issuerid + ".pem"
                if sys.platform == 'win32'
                else "certs/cc/Cartao de Cidadao " + issuerid + ".pem",
                "rb")
            c = load_pem_x509_certificate(c.read(), default_backend())
            if c.not_valid_before < datetime.datetime.utcnow() < c.not_valid_after:
                try:
                    c.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        asymmetric.padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                except InvalidSignature:
                    logger.error("Could not validate Sub CA certificate")
                    return False
            else:
                logger.error("Sub CA 2 certificate expired")
                return False
        else:
            logger.error("Sub CA certificate expired")
            return False
        return self.verify_cert_rootca(c)

    def verify_cert_rootca(self, cert):
        if cert.not_valid_before < datetime.datetime.utcnow() < cert.not_valid_after:
            c = open(
                "certs\\cc\\ecraizestado.pem"
                if sys.platform == 'win32'
                else "certs/cc/ecraizestado.pem",
                "rb")
            c = load_pem_x509_certificate(c.read(), default_backend())
            if c.not_valid_before < datetime.datetime.utcnow() < c.not_valid_after:
                try:
                    c.public_key().verify(
                        cert.signature,
                        cert.tbs_certificate_bytes,
                        asymmetric.padding.PKCS1v15(),
                        cert.signature_hash_algorithm,
                    )
                except InvalidSignature:
                    logger.error("Could not validate Sub CA certificate")
                    return False
            else:
                logger.error("Root CA certificate expired")
                return False
        else:
            logger.error("Sub CA 2 certificate expired")
            return False
        logger.info("Validation chain complete")
        return True
