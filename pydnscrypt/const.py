import sodium_wrapper


DNSCRYPT_PORT_DEFAULT = 443
DNSCRYPT_RELAY_PORT_DEFAULT = 443

CERT_MAGIC = b'DNSC'
RESOLVER_MAGIC = b'r6fnvWj8'
ANON_MAGIC = b'\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00'

MIN_CERT_LEN = 124

MAX_UDP_DNSPACKET_SIZE = 4096
INITIAL_MIN_QUERY_LEN = 256
QUERY_MODULO_SIZE = 64

DNSCRYPT_QUERY_OVERHEAD = (
    len(RESOLVER_MAGIC)
    + sodium_wrapper.Curve25519PublicKey.SIZE
    + sodium_wrapper.XChaCha20Box.NONCE_SIZE//2
    + sodium_wrapper.XChaCha20Box.MAC_SIZE
)
