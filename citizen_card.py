import base64

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import _CipherContext
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.backends.openssl.x509 import _Certificate
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import asymmetric
from cryptography.x509.oid import *
from cryptography.x509 import *
import os, PyKCS11, sys
import cryptography
import socket

pkcs11 = PyKCS11.PyKCS11Lib()
pkcs11.load('C:\\Windows\\System32\\pteidpkcs11.dll' if sys.platform == 'win32' else '/usr/local/lib/libpteidpkcs11.so')


class CitizenCard:
    def __init__(self):
        self.name = None
        self.slot = pkcs11.getSlotList()[-1]
        self.session = pkcs11.openSession(self.slot)
        self.backend = default_backend()

    def get_name(self):
        if self.name is None:
            certificate, *_ = self.get_x509_certificates()
            self.name = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        return self.name

    def get_x509_certificates(self, **kwargs):
        certificates = [load_der_x509_certificate(certificate, self.backend) for certificate in self.get_certificates()]
        if 'KEY_USAGE' not in kwargs:
            kwargs['KEY_USAGE'] = lambda ku: ku.value.digital_signature and ku.value.key_agreement
        for key, value in kwargs.items():
            if key in dir(ExtensionOID):
                certificates = [certificate for certificate in certificates if
                                value(certificate.extensions.get_extension_for_oid(getattr(ExtensionOID, key)))]
            elif key in dir(NameOID):
                certificates = [certificate for certificate in certificates if
                                value(certificate.subject.get_attributes_for_oid(getattr(NameOID, key)))]
        print(certificates)
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
                       transformation=lambda key: serialization.load_der_public_key(bytes(key.to_dict()['CKA_VALUE']), default_backend())):
        print(str(transformation(self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0])))
        return transformation(self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0])

    def get_private_key(self):
        return self.session.findObjects([
            (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
            (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')
        ])[0]

    def serialize(self,key, encoding=serialization.Encoding.PEM, **kwargs):
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
