import binascii

import ctypes
import ctypes.util

import os


__all__ = [
    'XCHACHA20_BEFORENMBYTES',
    'XCHACHA20_MACBYTES',
    'XCHACHA20_NONCEBYTES',
    'XChaCha20Box',

    'XSALSA20_BEFORENMBYTES',
    'XSALSA20_MACBYTES',
    'XSALSA20_NONCEBYTES',
    'XSalsa20Box',

    'CURVE25519_PUBLICKEYBYTES',
    'CURVE25519_SECRETKEYBYTES',
    'CURVE25519_BYTES',
    
    'Curve25519PublicKey',
    'Curve25519SecretKey',
    'Ed25519VerifyKey',

    'RawEncoder',
    'HexEncoder',

    'Encoder',
    'Key',

    'random',
]

random = os.urandom

_sodium = ctypes.cdll.LoadLibrary(ctypes.util.find_library('sodium') or
                                  ctypes.util.find_library('libsodium'))

box_xchacha20p1305_beforenm = _sodium.crypto_box_curve25519xchacha20poly1305_beforenm
box_xchacha20p1305_afternm = _sodium.crypto_box_curve25519xchacha20poly1305_easy_afternm
box_xchacha20p1305_open_afternm = _sodium.crypto_box_curve25519xchacha20poly1305_open_easy_afternm

box_xsalsa20p1305_beforenm = _sodium.crypto_box_curve25519xsalsa20poly1305_beforenm
box_xsalsa20p1305_afternm = _sodium.crypto_box_curve25519xsalsa20poly1305_afternm
box_xsalsa20p1305_open_afternm = _sodium.crypto_box_curve25519xsalsa20poly1305_open_afternm

scalarmult_curve25519_base = _sodium.crypto_scalarmult_curve25519_base

ed25519_sign_open = _sodium.crypto_sign_ed25519_open

safe_memcmp = _sodium.sodium_memcmp

XCHACHA20_BEFORENMBYTES = _sodium.crypto_box_curve25519xchacha20poly1305_beforenmbytes()
XCHACHA20_NONCEBYTES = _sodium.crypto_secretbox_xchacha20poly1305_noncebytes()
XCHACHA20_MACBYTES = _sodium.crypto_box_curve25519xchacha20poly1305_macbytes()

XSALSA20_BEFORENMBYTES = _sodium.crypto_box_curve25519xsalsa20poly1305_beforenmbytes()
XSALSA20_NONCEBYTES = _sodium.crypto_secretbox_xsalsa20poly1305_noncebytes()
XSALSA20_MACBYTES = _sodium.crypto_box_curve25519xsalsa20poly1305_macbytes()
XSALSA20_BOXZEROBYTES = _sodium.crypto_secretbox_xsalsa20poly1305_boxzerobytes()
XSALSA20_ZEROBYTES = _sodium.crypto_secretbox_xsalsa20poly1305_zerobytes()

CURVE25519_PUBLICKEYBYTES = _sodium.crypto_box_curve25519xsalsa20poly1305_publickeybytes()
CURVE25519_SECRETKEYBYTES = _sodium.crypto_box_curve25519xsalsa20poly1305_secretkeybytes()
CURVE25519_BYTES = _sodium.crypto_scalarmult_curve25519_bytes()

ED25519_PUBLICKEYBYTES = _sodium.crypto_sign_ed25519_publickeybytes()


class CryptoError(Exception):
    pass


def crypto_box_curve25519xchacha20poly1305_beforenm(pk, sk):
    if len(pk) != CURVE25519_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != CURVE25519_SECRETKEYBYTES:
        raise ValueError('Invalid private key')

    shared_key = ctypes.create_string_buffer(XCHACHA20_BEFORENMBYTES)

    res = box_xchacha20p1305_beforenm(shared_key, pk, sk)
    if res != 0:
        raise RuntimeError('Unexpected library error')
    return shared_key.raw


def crypto_box_curve25519xchacha20poly1305_afternm(message, nonce, k):
    if len(nonce) != XCHACHA20_NONCEBYTES:
        raise ValueError('Invalid nonce')
    if len(k) != XCHACHA20_BEFORENMBYTES:
        raise ValueError('Invalid shared key')

    # No need to prepend zero bytes to the message since this is already done
    # in libsodium's `easy` wrapper
    message_len = ctypes.c_ulonglong(len(message))
    cipher = ctypes.create_string_buffer(len(message) + XCHACHA20_MACBYTES)

    res = box_xchacha20p1305_afternm(cipher, message, message_len, nonce, k)
    if res != 0:
        raise RuntimeError('Unexpected library error')

    # no prepended bytes to remove
    return cipher.raw


def crypto_box_curve25519xchacha20poly1305_open_afternm(cipher, nonce, k):
    if len(nonce) != XCHACHA20_NONCEBYTES:
        raise ValueError('Trunacted nonce')
    if len(k) != XCHACHA20_BEFORENMBYTES:
        raise ValueError('Truncated key')

    # No need to prepend zero bytes to the message since this is already done
    # in libsodium's `easy` wrapper
    cipher_len = ctypes.c_ulonglong(len(cipher))
    message = ctypes.create_string_buffer(len(cipher) - XCHACHA20_MACBYTES)

    res = box_xchacha20p1305_open_afternm(message, cipher, cipher_len, nonce, k)
    if res != 0:
        raise CryptoError('An error occuurred trying to decrypt the message')

    # no prepended bytes to remove
    return message.raw


def crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk):
    if len(pk) != CURVE25519_PUBLICKEYBYTES:
        raise ValueError('Invalid public key')
    if len(sk) != CURVE25519_SECRETKEYBYTES:
        raise ValueError('Invalid private key')

    shared_key = ctypes.create_string_buffer(XSALSA20_BEFORENMBYTES)

    res = box_xsalsa20p1305_beforenm(shared_key, pk, sk)
    if res != 0:
        raise RuntimeError('Unexpected library error')
    return shared_key.raw


def crypto_box_curve25519xsalsa20poly1305_afternm(message, nonce, k):
    if len(nonce) != XCHACHA20_NONCEBYTES:
        raise ValueError('Invalid nonce')
    if len(k) != XCHACHA20_BEFORENMBYTES:
        raise ValueError('Invalid shared key')

    # See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption
    #
    # Prepend zero bytes to the ciphertext as required by libsodium's API.
    # As opposed to libsodium's implementation of Curve25519-XChaCha20-Poly1305,
    # there is no `easy` implementation dedicated to XSalsa20 explicitly. Although
    # libsodium's crypto box implementation contains an `easy` wrapper, which calls
    # XSalsa20 behind the scenes, we decided against using the crypto box wrapper
    # in case the crypto box implementation will be 'upgraded' to XChaCha20.
    padded_message = b'\x00' * XSALSA20_ZEROBYTES + message
    message_len = ctypes.c_ulonglong(len(padded_message))
    cipher = ctypes.create_string_buffer(len(message) + XSALSA20_ZEROBYTES)

    res = box_xsalsa20p1305_afternm(cipher, padded_message, message_len, nonce, k)
    if res != 0:
        raise RuntimeError('Unexpected library error')

    # Remove the initial zero bytes
    return cipher.raw[XSALSA20_BOXZEROBYTES:]


def crypto_box_curve25519xsalsa20poly1305_open_afternm(cipher, nonce, k):
    if len(nonce) != XCHACHA20_NONCEBYTES:
        raise ValueError('Trunacted nonce')
    if len(k) != XCHACHA20_BEFORENMBYTES:
        raise ValueError('Truncated key')

    # See: https://download.libsodium.org/doc/public-key_cryptography/authenticated_encryption
    #
    # Prepend zero bytes to the ciphertext as required by libsodium's API.
    # As opposed to libsodium's implementation of Curve25519-XChaCha20-Poly1305,
    # there is no `easy` implementation dedicated to XSalsa20 explicitly. Although
    # libsodium's crypto box implementation contains an `easy` wrapper, which calls
    # XSalsa20 behind the scenes, we decided against using the crypto box wrapper
    # in case the crypto box implementation will be 'upgraded' to XChaCha20.
    padded_cipher = b'\x00' * XSALSA20_BOXZEROBYTES + cipher
    cipher_len = ctypes.c_ulonglong(len(padded_cipher))
    message = ctypes.create_string_buffer(len(padded_cipher))

    res = box_xsalsa20p1305_open_afternm(message, padded_cipher, cipher_len, nonce, k)
    if res != 0:
        raise CryptoError('An error occuurred trying to decrypt the message')

    # Remove the initial zero bytes
    return message.raw[XSALSA20_ZEROBYTES:]


def crypto_scalarmult_curve25519(n):
    q = ctypes.create_string_buffer(CURVE25519_BYTES)

    res = scalarmult_curve25519_base(q, n)
    if res != 0:
        raise RuntimeError('Unexpected library error')
    return q.raw


def crypto_ed25519_sign_open(signed_message, pk):
    if len(pk) != ED25519_PUBLICKEYBYTES:
        raise ValueError('Truncated public key')

    message = ctypes.create_string_buffer(len(signed_message))
    message_len = ctypes.c_ulonglong()
    signed_len = ctypes.c_ulonglong(len(signed_message))

    res = ed25519_sign_open(message, ctypes.byref(message_len), signed_message, signed_len, pk)
    if res != 0:
        raise CryptoError('Bad signature')
    return message.raw[:message_len.value]


def sodium_memcmp(data1, data2):
    if not isinstance(data1, bytes) or not isinstance(data2, bytes):
        raise TypeError('Input data must be bytes')
    l = ctypes.c_size_t(len(data1))
    eq_len = len(data1) == len(data2)
    eq_mem = safe_memcmp(data1, data2, l) == 0

    return eq_len and eq_mem


class Encoder:
    @staticmethod
    def encode(data):
        raise NotImplementedError()

    @staticmethod
    def decode(data):
        raise NotImplementedError()


class RawEncoder(Encoder):
    @staticmethod
    def encode(data):
        return data

    @staticmethod
    def decode(data):
        return data


class HexEncoder(Encoder):
    @staticmethod
    def encode(data):
        return binascii.hexlify(data)

    @staticmethod
    def decode(data):
        return binascii.unhexlify(data)    


class Key:
    SIZE = 0

    __slots__ = ('_key',)

    def __init__(self, key, encoder=RawEncoder):
        self._key = encoder.decode(key)
        if not isinstance(self._key, bytes):
            raise TypeError(f'{type(self).__name__} must be created from bytes')

        if len(self._key) != self.SIZE:
            raise ValueError(f'{type(self).__name__} must be exactly {self.SIZE} bytes long')

    def encode(self, encoder=RawEncoder):
        return encoder.encode(bytes(self))

    def __bytes__(self):
        return self._key

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        # use comparison method that cannot be abused for time sidechannel attacks
        return isinstance(other, type(self)) and sodium_memcmp(bytes(self), bytes(other))

    @classmethod
    def generate(cls):
        return cls(os.urandom(cls.SIZE))


class Ed25519VerifyKey(Key):
    SIZE = ED25519_PUBLICKEYBYTES

    __slots__ = ()

    def verify(self, signed_message, signature=None):
        if signature is not None:
            signed_message = signature + signed_message

        return crypto_ed25519_sign_open(signed_message, self._key)


class Curve25519PublicKey(Key):
    SIZE = CURVE25519_PUBLICKEYBYTES

    __slots__ = ()

    
class Curve25519SecretKey(Key):
    SIZE = CURVE25519_SECRETKEYBYTES

    __slots__ = ('public_key',)

    def __init__(self, key, encoder=RawEncoder):
        super().__init__(key, encoder=encoder)

        self.public_key = Curve25519PublicKey(crypto_scalarmult_curve25519(self._key))


class Curve25519Box:
    NONCE_SIZE = 0

    __slots__ = ('_shared_key',)

    def __init__(self, private_key, public_key):
        if private_key and public_key:
            if (not isinstance(private_key, Curve25519SecretKey)
                or not isinstance(public_key, Curve25519PublicKey)):
                raise TypeError('Box must be created from Curve25519 keys')

            # precompute shared key
            self._shared_key = self._crypto_box_beforenm(
                bytes(public_key),
                bytes(private_key)
            )
        else:
            self._shared_key = None

    def __bytes__(self):
        return self._shared_key

    @classmethod
    def decode(cls, encoded, encoder=RawEncoder):
        box = cls(None, None)
        box._shared_key = encoder.decode(encoded)

        if not isinstance(box._shared_key, bytes):
            raise ValueError(f'{cls.__name__} must be decoded from bytes')

        if len(box._shared_key) != cls.BEFORENMBYTES:
            raise ValueError(f'{cls.__name__} must exactly {cls.BEFORENMBYTES} bytes long')

        return box

    def encrypt(self, plaintext, nonce=None, encoder=RawEncoder):
        if nonce is None:
            nonce = os.urandom(self.NONCE_SIZE)

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f'Nonce must be exactly {self.NONCE_SIZE} bytes long')

        ciphertext = self._crypto_box_afternm(plaintext, nonce, self._shared_key)

        encoded_nonce = encoder.encode(nonce)
        encoded_cipher = encoder.encode(ciphertext)

        return encoded_nonce + encoded_cipher

    def decrypt(self, ciphertext, nonce=None, encoder=RawEncoder):
        ciphertext = encoder.decode(ciphertext)

        if nonce is None:
            nonce = ciphertext[:self.NONCE_SIZE]
            ciphertext = ciphertext[self.NONCE_SIZE:]

        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f'Nonce must be exactly {self.NONCE_SIZE} bytes long')

        return self._crypto_box_open_afternm(ciphertext, nonce, self._shared_key)

    def shared_key(self):
        return self._shared_key

    @staticmethod
    def _crypto_box_beforenm(pk, sk):
        raise NotImplementedError()

    @staticmethod
    def _crypto_box_afternm(plaintext, nonce, k):
        raise NotImplementedError()

    @staticmethod
    def _crypto_box_open_afternm(ciphertext, nonce, k):
        raise NotImplementedError()


class XChaCha20Box(Curve25519Box):
    NONCE_SIZE = XCHACHA20_NONCEBYTES

    __slots__ = ()

    @staticmethod
    def _crypto_box_beforenm(pk, sk):
        return crypto_box_curve25519xchacha20poly1305_beforenm(pk, sk)

    @staticmethod
    def _crypto_box_afternm(plaintext, nonce, k):
        return crypto_box_curve25519xchacha20poly1305_afternm(plaintext, nonce, k)

    @staticmethod
    def _crypto_box_open_afternm(ciphertext, nonce, k):
        return crypto_box_curve25519xchacha20poly1305_open_afternm(ciphertext, nonce, k)


class XSalsa20Box(Curve25519Box):
    NONCE_SIZE = XSALSA20_NONCEBYTES

    __slots__ = ()

    @staticmethod
    def _crypto_box_beforenm(pk, sk):
        return crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk)

    @staticmethod
    def _crypto_box_afternm(plaintext, nonce, k):
        return crypto_box_curve25519xsalsa20poly1305_afternm(plaintext, nonce, k)

    @staticmethod
    def _crypto_box_open_afternm(ciphertext, nonce, k):
        return crypto_box_curve25519xsalsa20poly1305_open_afternm(ciphertext, nonce, k)
