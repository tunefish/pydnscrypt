import ctypes
import ctypes.util


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

memcmp = _sodium.sodium_memcmp

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
    eq_mem = memcmp(data1, data2, l) == 0

    return eq_len and eq_mem
