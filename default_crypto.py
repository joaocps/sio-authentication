import os
import base64
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, asymmetric
from cryptography.hazmat.primitives.twofactor.totp import TOTP


class Asymmetric(object):
    """
    Class with asymmetric encryption methods
    """

    def generate_rsa_keys(self, password):
        """
        Create and save the rsa private and public key to file
        """
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password.encode()))

        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo)

        return private_key, public_pem

    def load_rsa_public_key(self, file):
        """
        Load RSA public key from file
        :param file:
        :return: public_key
        """

        with open(file, "rb") as pubkey_file:
            public_key = load_pem_public_key(pubkey_file.read(), backend=default_backend())
            if not isinstance(public_key, rsa.RSAPublicKey):
                print("ERROR, public key not loaded")
            else:
                return public_key

    """
    Auxiliary method to load a public key from a string/bytes text
    """

    def load_pub_from_str(self, pk):
        return serialization.load_pem_public_key(
            pk,
            backend=default_backend())

    """
    Encrypt content to send using a RSA public key of the destination
    Used to create an hybrid cipher
    """

    def encrypt(self, pubk, content):
        ciphertext = pubk.encrypt(
            content,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    """
    Decrypt received content using local RSA private key
    Used to access parameters og hybrid cipher
    """

    def decrypt(self, privk, content):
        plaintext = privk.decrypt(
            content,
            asymmetric.padding.OAEP(
                mgf=asymmetric.padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext

    """
    Sign message with rsa key 
    Valid just for server certificate 
    """

    def sign(self, privkey, message):
        return privkey.sign(message,
                            asymmetric.padding.PSS(
                                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                                salt_length=asymmetric.padding.PSS.MAX_LENGTH
                            ),
                            hashes.SHA256()
                            )

    """
    Verify message signature
    Valid just for server certificate
    """

    def verify(self, pubkey, message, signature):
        return pubkey.verify(
            signature,
            message,
            asymmetric.padding.PSS(
                mgf=asymmetric.padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric.padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )


class Symmetric:
    """
    Initializing Class Asymmetric to use methods encrypt/decrypt for Hybrid Cipher
    """

    def __init__(self):
        self.rsa = Asymmetric()

    """
    Generic symmetric encrypt method 
    :param algorithm accepts 
            1 - AES
            2 - TriplesDES
            3 - ChaCha20
    :param hasht accepts
            1 - SHA256
            2 - SHA512
    :param block only used for AES
            1 - CBC
            2 - CTR 
    :param msg content do encrypt
    :param pkey target Public Key
    :return hybrid cipher + encrypt content as base64
    """

    def encrypt(self, algorithm, msg, hasht, block, pkey):
        backend = default_backend()
        salt = os.urandom(16)
        password = os.urandom(32)

        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            iv = os.urandom(16)

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)
            hybrid = self.rsa.encrypt(pkey, iv + salt + password)
            cipher = Cipher(algorithms.AES(key), mode=m, backend=backend)

            encryptor = cipher.encryptor()

            if block == 1:
                padder = padding.PKCS7(128).padder()
                padded_data = padder.update(msg)
                padded_data += padder.finalize()
                ct = encryptor.update(padded_data)
                ct += encryptor.finalize()
                return base64.b64encode(hybrid + ct)
            else:
                ct = encryptor.update(msg)
                ct += encryptor.finalize()
                return base64.b64encode(hybrid + ct)

        # 3DES Não aceita CTR
        elif algorithm == 2:
            iv = os.urandom(8)

            kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            cipher = Cipher(algorithms.TripleDES(key), mode=modes.CBC(iv), backend=backend)
            hybrid = self.rsa.encrypt(pkey, iv + salt + password)
            encryptor = cipher.encryptor()
            padder = padding.PKCS7(64).padder()
            padded_data = padder.update(msg)
            padded_data += padder.finalize()
            ct = encryptor.update(padded_data)
            ct += encryptor.finalize()
            return base64.b64encode(hybrid + ct)

        # CHACHA20
        elif algorithm == 3:
            nonce = os.urandom(16)

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=backend)
            hybrid = self.rsa.encrypt(pkey, nonce + salt + password)
            encryptor = cipher.encryptor()
            ct = encryptor.update(msg)
            ct += encryptor.finalize()
            return base64.b64encode(hybrid + ct)

        return None

    """
    Generic symmetric decrypt method 
    :param algorithm accepts 
            1 - AES
            2 - TriplesDES
            3 - ChaCha20
    :param hasht accepts
            1 - SHA256
            2 - SHA512
    :param block only used for AES
            1 - CBC
            2 - CTR 
    :param msg content to decrypt
    :param privKey local Private Key
    :return decrypt content as bytes
    """

    def decrypt(self, algorithm, msg, hasht, block, privkey):
        backend = default_backend()
        msg = base64.b64decode(msg)
        hybrid = self.rsa.decrypt(privkey, msg[0:256])
        msg = msg[256:]
        if hasht == 1:
            alg = hashes.SHA256()
        elif hasht == 2:
            alg = hashes.SHA512()
        else:
            return None

        # AES128
        if algorithm == 1:
            iv = hybrid[:16]
            salt = hybrid[16:32]
            password = hybrid[32:]

            if block == 1:
                m = modes.CBC(iv)
            elif block == 2:
                m = modes.CTR(iv)
            else:
                return None

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.AES(key), mode=m, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)
            dec += decryptor.finalize()
            if block == 1:
                unpadder = padding.PKCS7(128).unpadder()
                data = unpadder.update(dec)
                data += unpadder.finalize()
                return data
            else:
                return dec

        elif algorithm == 2:
            iv = hybrid[:8]
            salt = hybrid[8:24]
            password = hybrid[24:]

            kdf = PBKDF2HMAC(algorithm=alg, length=16, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.TripleDES(key), mode=modes.CBC(iv), backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)
            dec += decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            data = unpadder.update(dec)
            data += unpadder.finalize()
            return data

        # CHACHA20
        elif algorithm == 3:
            nonce = hybrid[:16]
            salt = hybrid[16:32]
            password = hybrid[32:]

            kdf = PBKDF2HMAC(algorithm=alg, length=32, salt=salt, iterations=100000, backend=backend)
            key = kdf.derive(password)

            decipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None, backend=default_backend())
            decryptor = decipher.decryptor()
            dec = decryptor.update(msg)
            dec += decryptor.finalize()
            return dec

        return None

    """
    Method to encrypt the first message sent from client/server
    """

    def handshake_encrypt(self, message):
        backend = default_backend()
        iv = os.urandom(16)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
        key = kdf.derive(b'hs')

        cipher = Cipher(algorithms.AES(key), mode=modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(128).padder()

        padded_data = padder.update(message)
        padded_data += padder.finalize()

        ct = encryptor.update(padded_data)
        return iv + salt + ct

    """
    Method to decrypt the first message sent to client/server
    """

    def handshake_decrypt(self, message):
        backend = default_backend()
        iv = message[0:16]
        salt = message[16:32]
        message = message[32:]

        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)
        key = kdf.derive(b'hs')

        decipher = Cipher(algorithms.AES(key), mode=modes.CBC(iv), backend=default_backend())
        decryptor = decipher.decryptor()
        dec = decryptor.update(message)
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(dec)
        data += unpadder.finalize()
        return data


class OTP:
    def generate(self):
        with open("otp", "rb") as f:
            key = f.read()
            totp = TOTP(key, 8, hashes.SHA1(), 30, backend=default_backend())
            tval = time.time()
            return totp.generate(tval)

    def verify(self, otp_client):
        with open("otp", "rb") as f:
            key = f.read()
            totp = TOTP(key, 8, hashes.SHA1(), 30, backend=default_backend())
            tval = time.time()
            otp_server = totp.generate(tval)
            return otp_server == otp_client
