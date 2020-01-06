import binascii

from os import urandom as random

import sodium_bindings as sodium_lib
from sodium_bindings import CryptoError


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


class GroupedHexEncoder(Encoder):
    @staticmethod
    def encode(data, separator=b':', group_size=2):
        hex_data = HexEncoder.encode(data)
        return separator.join(hex_data[i:i+group_size] for i in range(0, len(hex_data), group_size))

    @staticmethod
    def decode(data, separator=b':'):
        return HexEncoder.decode(data.replace(separator, b''))


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
        return (
            isinstance(other, type(self))
            and sodium_lib.sodium_memcmp(bytes(self), bytes(other))
        )

    @classmethod
    def generate(cls):
        return cls(random(cls.SIZE))


class Ed25519VerifyKey(Key):
    SIZE = sodium_lib.ED25519_PUBLICKEYBYTES

    __slots__ = ()

    def verify(self, signed_message, signature=None):
        if signature is not None:
            signed_message = signature + signed_message

        return sodium_lib.crypto_ed25519_sign_open(signed_message, self._key)


class Curve25519PublicKey(Key):
    SIZE = sodium_lib.CURVE25519_PUBLICKEYBYTES

    __slots__ = ()

    
class Curve25519SecretKey(Key):
    SIZE = sodium_lib.CURVE25519_SECRETKEYBYTES

    __slots__ = ('public_key',)

    def __init__(self, key, encoder=RawEncoder):
        super().__init__(key, encoder=encoder)

        raw_public_key = sodium_lib.crypto_scalarmult_curve25519(self._key)
        self.public_key = Curve25519PublicKey(raw_public_key)


class Curve25519Box:
    NONCE_SIZE = 0
    MAC_SIZE = 0

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
            nonce = random(self.NONCE_SIZE)

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
    NONCE_SIZE = sodium_lib.XCHACHA20_NONCEBYTES
    MAC_SIZE = sodium_lib.XCHACHA20_MACBYTES

    __slots__ = ()

    @staticmethod
    def _crypto_box_beforenm(pk, sk):
        return sodium_lib.crypto_box_curve25519xchacha20poly1305_beforenm(pk, sk)

    @staticmethod
    def _crypto_box_afternm(plaintext, nonce, k):
        return sodium_lib.crypto_box_curve25519xchacha20poly1305_afternm(plaintext, nonce, k)

    @staticmethod
    def _crypto_box_open_afternm(ciphertext, nonce, k):
        return sodium_lib.crypto_box_curve25519xchacha20poly1305_open_afternm(ciphertext, nonce, k)


class XSalsa20Box(Curve25519Box):
    NONCE_SIZE = sodium_lib.XSALSA20_NONCEBYTES
    MAC_SIZE = sodium_lib.XSALSA20_MACBYTES

    __slots__ = ()

    @staticmethod
    def _crypto_box_beforenm(pk, sk):
        return sodium_lib.crypto_box_curve25519xsalsa20poly1305_beforenm(pk, sk)

    @staticmethod
    def _crypto_box_afternm(plaintext, nonce, k):
        return sodium_lib.crypto_box_curve25519xsalsa20poly1305_afternm(plaintext, nonce, k)

    @staticmethod
    def _crypto_box_open_afternm(ciphertext, nonce, k):
        return sodium_lib.crypto_box_curve25519xsalsa20poly1305_open_afternm(ciphertext, nonce, k)
