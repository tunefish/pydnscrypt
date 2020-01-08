import struct
import time
import threading
import warnings

from functools import partial

import dns.flags
import dns.message
import dns.resolver
import dns.exception

import dnsstamps

try:
    import pydnscrypt.sodium_wrapper as crypto
except (OSError, AttributeError):
    raise RuntimeError('Please install libsodium on your system')

import pydnscrypt.const as const
import pydnscrypt.utils as utils


class DNSCryptCertificate:
    """
    Provides a model and parsing capabilities for DNSCrypt certificates.
    """

    __slots__ = (
        'minor',
        'serial',
        'es_version',
        'client_magic',
        'public_key',
        'valid_from',
        'valid_until',
    )

    def __init__(self,
                 minor,
                 serial,
                 client_magic,
                 es_version,
                 public_key,
                 valid_from,
                 valid_until):
        self.minor = minor
        self.serial = serial
        self.client_magic = client_magic
        self.es_version = es_version
        self.public_key = public_key
        self.valid_from = valid_from
        self.valid_until = valid_until

    @classmethod
    def decode(cls, cert, verify_key):
        """
        Parses a DNSCrypt certificate and returns a new instance

        Arguments:
            cert: the serialized certificate, as obtained through
                the initial query to the DNSCrypt server
            verify_key: an instance of nacl.signing.VerifyKey holding the public
                key known from e.g. the DNSCrypt stamp

        Raises:
            dns.exception.DNSException: If the certificate cannot be parsed or
                the payload's signature cannot be verified
        """
        if len(cert) < const.MIN_CERT_LEN:
            raise dns.exception.DNSException(
                f'Message too short: {len(cert)} bytes given, '
                f'{const.MIN_CERT_LEN} bytes needed'
            )

        cert_magic, es_version, minor = struct.unpack_from('!4sHH', cert)
        signed_payload = cert[8:]
        if cert_magic != const.CERT_MAGIC:
            raise dns.exception.DNSException(
                f'Invalid certificate magic: {cert[:4]}'
            )

        payload = verify_key.verify(signed_payload)

        unpacked = struct.unpack_from('!32s8sIII', payload)
        public_key, client_magic, serial, ts_start, ts_end = unpacked

        return cls(
            minor=minor,
            serial=serial,
            client_magic=client_magic,
            es_version=es_version,
            public_key=public_key,
            valid_from=ts_start,
            valid_until=ts_end
        )

    def is_valid(self):
        """Checks whether the certificate is currently valid"""
        return self.valid_from <= time.time() < self.valid_until

    def get_encryption_system(self, raise_exception=False):
        """
        Returns the nacl.public.Box implementation matching the encryption scheme
        required by the certificate for all future encrypted traffic.

        Arguments:
            raise_exception: Whether to raise an exception of the encryption is
                unknown or not supported

        Raises:
            dns.exception.DNSException: If the requested encryption scheme is
                unnown (es_version > 2) and raise_Exception is True
        """
        if self.es_version == 1:
            return crypto.XSalsa20Box
        if self.es_version == 2:
            return crypto.XChaCha20Box
        if raise_exception:
            raise dns.exception.DNSException(
                f'Unsupported encryption system (es-version = {self.es_version})'
            )
        return None

    def get_public_key(self):
        return crypto.Curve25519PublicKey(self.public_key)


class DNSCryptClient:
    """
    Wrapper around dnspython for issuing DNSCrypt requests. This implementation
    supports DNSCrypt Version 2 using Curve25519-XSalsa20-Poly1305 or
    Curve25519-XChaCha20-Poly1305 (encryption system 1 and 2, respectively)
    for authenticated encryption between the client and the DNSCrypt server.
    """

    __slots__ = (
        'ip',
        'port',
        'provider_name',
        'provider_pk',
        'timeout',
        'ephemeral_keys',
        '_cert_lock',
        '_cert',
        '_box',
        '_private_key',
        '_min_query_len_estimator',
    )

    def __init__(self,
                 ip,
                 provider_name,
                 provider_pk,
                 provider_pk_encoder=crypto.RawEncoder,
                 port=const.DNSCRYPT_PORT_DEFAULT,
                 timeout=5,
                 private_key=None,
                 private_key_encoder=crypto.RawEncoder,
                 ephemeral_keys=False,
                 obtain_certificate=True,
                 raise_invalid_provider_name=False,
                 tcp=False):
        if not utils.validate_provider_name(provider_name, ('2',)):
            msg = (
                f'Provider name {provider_name} does not conform to DNSCrypt'
                'specification: <protocol-major-version>.dnscrypt-cert.<zone>'
            )

            if raise_invalid_provider_name:
                raise ValueError(msg)
            warnings.warn(msg, category=UserWarning)

        if private_key:
            try:
                self._private_key = crypto.Curve25519SecretKey(
                    private_key,
                    encoder=private_key_encoder
                )
            except (TypeError, ValueError) as ex:
                raise ValueError(f'Invalid private key {private_key}: {ex}')
        else:
            self._private_key = crypto.Curve25519SecretKey.generate()

        try:
            self.provider_pk = crypto.Ed25519VerifyKey(
                provider_pk,
                encoder=provider_pk_encoder
            )
        except (TypeError, ValueError) as ex:
            raise ValueError(f'Invalid public key {provider_pk}: {ex}')

        self.ip = ip
        self.port = port
        self.provider_name = provider_name
        self.provider_pk = None

        self.timeout = timeout
        self.ephemeral_keys = ephemeral_keys

        self._cert_lock = threading.Lock()
        self._cert = None
        self._box = None
        self._min_query_len_estimator = utils.MinQuestionSizeEstimator()

        if obtain_certificate:
            self.refresh_certificate(tcp=tcp)

    @classmethod
    def from_stamp(cls, stamp, *args, **kwargs):
        stamp = utils.prepare_stamp(stamp)

        if stamp.protocol != dnsstamps.Protocol.DNSCRYPT:
            raise ValueError('Not a DNSCRYPT server')

        args = {
            'provider_name': stamp.provider_name,
            'provider_pk': stamp.public_key,
            'provider_pk_encoder': crypto.HexEncoder
        }

        args['ip'], args['port'] = utils.parse_dnsstamp_address(
            stamp.address,
            default_port=const.DNSCRYPT_PORT_DEFAULT
        )

        args.update(kwargs)
        return cls(**args)

    def refresh_certificate(self, tcp=False):
        with self._cert_lock:
            if self._cert is None or not self._cert.is_valid():
                self._get_new_certificate(tcp=tcp)

    def _get_new_certificate(self, tcp=False):
        """Must hold self._cert_lock when calling _get_new_certificate"""

        query_certs = dns.message.make_query(self.provider_name,
                                             rdtype=dns.rdatatype.TXT)

        answer = None
        if not tcp:
            try:
                answer = self._query_certificate_udp(query_certs,
                                                     timeout=self.timeout,
                                                     ignore_unexpected=True)
                if answer.flags & dns.flags.TC:
                    tcp = True
            except dns.exception.Timeout:
                tcp = True

        if tcp:
            try:
                answer = self._query_certificate_udp(query_certs,
                                                     timeout=self.timeout)
            except dns.exception.Timeout:
                pass

        if not answer or len(answer.answer) == 0:
            raise dns.exception.DNSException(
                f'No reply from {self.provider_name} ({self.ip}:{self.port})'
            )

        selected_cert = None
        for cert in answer.answer[0]:
            cert_encoded = b''.join(cert.strings)
            try:
                cert = DNSCryptCertificate.decode(cert_encoded, self.provider_pk)
            except dns.exception.DNSException:
                continue

            encryption_system = cert.get_encryption_system()
            if encryption_system is None or not cert.is_valid():
                continue

            if selected_cert is None or selected_cert.serial < cert.serial:
                selected_cert = cert

        if not selected_cert:
            raise dns.exception.DNSException(
                'No valid certificate received from '
                f'{self.provider_name} ({self.ip}:{self.port})'
            )

        self._cert = selected_cert
        encryption_system = selected_cert.get_encryption_system()
        self._box = encryption_system(self._private_key,
                                      selected_cert.get_public_key())

    def query(self,
              qname,
              rdtype=dns.rdatatype.A,
              rdclass=dns.rdataclass.IN,
              source=None,
              source_port=0,
              lifetime=None,
              tcp=False,
              raise_on_no_answer=True):
        if isinstance(qname, (str, bytes)):
            qname = dns.name.from_text(qname)
        if not qname.is_absolute():
            qname = qname.concatenate(dns.name.root)

        if isinstance(rdtype, (str, bytes)):
            rdtype = dns.rdatatype.from_text(rdtype)
        if isinstance(rdclass, (str, bytes)):
            rdclass = dns.rdataclass.from_text(rdclass)

        # Not supported by dnspython, also some nameservers dropped support for
        # ANY requests, most notably Cloudflare
        if (dns.rdatatype.is_metatype(rdtype)
                or dns.rdataclass.is_metaclass(rdclass)):
            raise dns.resolver.NoMetaqueries()

        self.refresh_certificate(tcp=tcp)

        query = dns.message.make_query(qname, rdtype=rdtype, rdclass=rdclass)

        response = None
        exceptions = []
        timeout = lifetime or self.timeout
        if not tcp:
            try:
                response = self._query_encrypted_udp(query,
                                                     source=source,
                                                     source_port=source_port,
                                                     timeout=timeout,
                                                     ignore_unexpected=True)
                if response.flags & dns.flags.TC:
                    self._min_query_len_estimator.update_tc_flag()
                    tcp = True
                else:
                    total_query_len = (len(query.to_wire())
                                       + const.DNSCRYPT_QUERY_OVERHEAD)
                    self._min_query_len_estimator.update(total_query_len)
            except Exception as ex:
                exceptions.append((self.ip, False, self.port, ex, response))
                tcp = True

        if tcp:
            try:
                response = self._query_encrypted_tcp(query,
                                                     source=source,
                                                     source_port=source_port,
                                                     timeout=timeout)
            except Exception as ex:
                exceptions.append((self.ip, False, self.port, ex, response))

        if not response:
            raise dns.resolver.NoNameservers(request=query, errors=exceptions)

        rcode = response.rcode()
        if rcode == dns.rcode.YXDOMAIN:
            raise dns.resolver.YXDOMAIN()
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN(qnames=[qname], responses=[response])

        return dns.resolver.Answer(qname,
                                   rdtype,
                                   rdclass,
                                   response,
                                   raise_on_no_answer=raise_on_no_answer)

    def _compute_padded_len_udp(self, message):
        # Account for the b'\x80' padding byte that is always added
        min_query_size = const.DNSCRYPT_QUERY_OVERHEAD + len(message) + 1

        min_query_size = max(min_query_size,
                             self._min_query_len_estimator.get_min_size())
        return utils.ceil_to_power_of_2(min_query_size, const.QUERY_MODULO_SIZE)

    def _compute_padded_len_tcp(self, message):
        # Append between (1, 256) bytes of padding such that the total
        # message length is a multiple of const.QUERY_MODULO_SIZE
        min_query_size = len(message) + (crypto.random(1)[0] or 1)
        return utils.ceil_to_power_of_2(min_query_size, const.QUERY_MODULO_SIZE)

    def _encrypt_query(self, query, compute_padded_len):
        message = query.to_wire()

        padding_len = compute_padded_len(message)
        padding_len = min(padding_len, const.MAX_UDP_DNSPACKET_SIZE)
        if padding_len <= len(message):
            raise dns.exception.DNSException('Query too long')

        box = self._box
        public_key = self._private_key.public_key
        if self.ephemeral_keys:
            ephemeral_key = crypto.Curve25519SecretKey.generate()
            box = type(box)(ephemeral_key, self._cert.get_public_key())
            public_key = ephemeral_key.public_key
        nonce = crypto.random(box.NONCE_SIZE//2).ljust(box.NONCE_SIZE, b'\x00')

        message = utils.iso7816_4_pad(message, padding_len)
        cipher = box.encrypt(message, nonce=nonce)
        cipher = cipher[:box.NONCE_SIZE//2] + cipher[box.NONCE_SIZE:]
        final_cipher = self._cert.client_magic + public_key.encode() + cipher
        return final_cipher, (nonce, box)

    def _decrypt_response(self, response, args, **kwargs):
        expected_nonce, box = args
        magic = response[:8]
        cipher = response[8:]

        if magic != const.RESOLVER_MAGIC:
            raise TypeError(f'Invalid RESOLVER MAGIC {magic}')

        if cipher[:box.NONCE_SIZE//2] != expected_nonce[:box.NONCE_SIZE//2]:
            raise dns.exception.DNSException('Invalid nonce in response')

        message = utils.iso7816_4_unpad(box.decrypt(cipher))
        return dns.message.from_wire(message, **kwargs)

    def _query_certificate_udp(self, query, **kwargs):
        return utils.query_udp(self.ip,
                               self.port,
                               query,
                               utils.PlainQueryEncoder,
                               **kwargs)

    def _query_certificate_tcp(self, query, **kwargs):
        return utils.query_tcp(self.ip,
                               self.port,
                               query,
                               utils.PlainQueryEncoder,
                               **kwargs)

    def _query_encrypted_udp(self, query, **kwargs):
        encoder = utils.QueryEncoder(
            partial(self._encrypt_query, self._compute_padded_len_udp),
            self._decrypt_response
        )
        return utils.query_udp(self.ip,
                               self.port,
                               query,
                               encoder,
                               **kwargs)

    def _query_encrypted_tcp(self, query, **kwargs):
        encoder = utils.QueryEncoder(
            partial(self._encrypt_query, self._compute_padded_len_tcp),
            self._decrypt_response
        )
        return utils.query_tcp(self.ip,
                               self.port,
                               query,
                               encoder,
                               **kwargs)


class AnonymousDNSCryptClient(DNSCryptClient):
    __slots__ = ('relay_ip', 'relay_port')

    def __init__(self,
                 *args,
                 relay_ip=None,
                 relay_port=const.DNSCRYPT_RELAY_PORT_DEFAULT,
                 ephemeral_keys=True,
                 obtain_certificate=False,
                 **kwargs):
        # obtain certifiate later when relay IP and port are initialized
        super().__init__(*args,
                         ephemeral_keys=ephemeral_keys,
                         obtain_certificate=False,
                         **kwargs)

        self.relay_ip = relay_ip
        self.relay_port = relay_port

        if obtain_certificate:
            self.refresh_certificate(tcp=kwargs.get('tcp', False))

    @classmethod
    def from_stamps(cls, relay_stamp, stamp, **kwargs):
        relay_stamp = utils.prepare_stamp(relay_stamp)

        if relay_stamp.protocol != dnsstamps.Protocol.DNSCRYPT_RELAY:
            raise ValueError('Not a DNSCRYPT relay server')

        kwargs['relay_ip'], kwargs['relay_port'] = utils.parse_dnsstamp_address(
            relay_stamp.address,
            default_port=const.DNSCRYPT_RELAY_PORT_DEFAULT
        )

        if 'relay_port' in kwargs:
            kwargs['relay_port'] = kwargs['relay_port']

        return super(AnonymousDNSCryptClient, cls).from_stamp(stamp, **kwargs)

    def _relay_packet(self, packet):
        return (const.ANON_MAGIC
                + utils.serialize_ip(self.ip)
                + utils.serialize_port(self.port)
                + packet)

    def _query_certificate_udp(self, query, **kwargs):
        encoder = utils.QueryEncoder(
            lambda q: (self._relay_packet(q.to_wire()), None),
            utils.PlainQueryEncoder.decode
        )
        return utils.query_udp(self.relay_ip,
                               self.relay_port,
                               query,
                               encoder,
                               **kwargs)

    def _query_certificate_tcp(self, query, **kwargs):
        encoder = utils.QueryEncoder(
            lambda q: (self._relay_packet(q.to_wire()), None),
            utils.PlainQueryEncoder.decode
        )
        return utils.query_tcp(self.relay_ip,
                               self.relay_port,
                               query,
                               encoder,
                               **kwargs)

    def _query_encrypted_udp(self, query, **kwargs):
        def _encode(query):
            wire, args = self._encrypt_query(query, self._compute_padded_len_udp)
            return self._relay_packet(wire), args

        encoder = utils.QueryEncoder(_encode, self._decrypt_response)
        return utils.query_udp(self.relay_ip,
                               self.relay_port,
                               query,
                               encoder,
                               **kwargs)

    def _query_encrypted_tcp(self, query, **kwargs):
        def _encode(query):
            wire, args = self._encrypt_query(query, self._compute_padded_len_tcp)
            return self._relay_packet(wire), args

        encoder = utils.QueryEncoder(_encode, self._decrypt_response)
        return utils.query_tcp(self.relay_ip,
                               self.relay_port,
                               query,
                               encoder,
                               **kwargs)


class AnonymousDNSCryptClientFactory:
    __slots__ = ('relay_stamp',)

    def __init__(self, relay_stamp):
        self.relay_stamp = relay_stamp

    @classmethod
    def from_relay_stamp(cls, relay_stamp):
        relay_stamp = utils.prepare_stamp(relay_stamp)
        if relay_stamp.protocol != dnsstamps.Protocol.DNSCRYPT_RELAY:
            raise ValueError('Not a DNSCRYPT relay server')

        return cls(relay_stamp)

    def from_stamp(self, stamp, **kwargs):
        return AnonymousDNSCryptClient.from_stamps(self.relay_stamp,
                                                   stamp,
                                                   **kwargs)
