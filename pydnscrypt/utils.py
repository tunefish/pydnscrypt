import ipaddress
import socket
import struct
import time

from collections import namedtuple
from enum import Flag

import dns.inet
import dns.query
import dnsstamps

from const import INITIAL_MIN_QUERY_LEN, QUERY_MODULO_SIZE, MAX_UDP_DNSPACKET_SIZE


class TransportProto(Flag):
  NONE = 0
  UDP = 1
  TCP = 2
  BOTH = 3


class VariableEWMA:
    """Simple implementation for Exponentially Weighted Moving Average"""

    WARMUP_SAMPLES = 8

    __slots__ = ('value', 'count', 'decay')

    def __init__(self, decay):
        self.value = 0
        self.count = 0
        self.decay = 2 / (decay + 1)

    def set(self, value):
        """Resets the average to given value"""

        self.value = value
        if self.count < self.WARMUP_SAMPLES:
            self.count = self.WARMUP_SAMPLES + 1

    def add(self, value):
        """Adds a new value to the moving average"""

        if self.count < self.WARMUP_SAMPLES:
            self.count += 1
            self.value += value
        else:
            if self.count == self.WARMUP_SAMPLES:
                self.count += 1
                self.value = self.value / self.WARMUP_SAMPLES
            self.value = (value * self.decay) + (self.value * (1 - self.decay))

    def get(self):
        """Returns the current average, if enough samples have been collected, otherwise None."""
        if self.count < self.WARMUP_SAMPLES:
            return 0
        return self.value


class MinQuestionSizeEstimator:
    """
    Simple minimum size estimator for UDP DNSCrypt queries based on the
    requirements mentioned in the specification:
     - Increase minimum query size by 64 bytes if a UDP query is answered with TC flag
     - Decrease minimum query size at will, but must always be a multiple of 64 bytes
     - Upper limit given by maximum packet size of transport protocol
    Under the hood, it uses EWMA to calculate the weighted average of previously
    sent DNSCrypt queries.
    """

    EWMA_DECAY = 100

    __slots__ = ('ewma', 'min_size', 'max_size')

    def __init__(self, decay=None):
        self.ewma = VariableEWMA(decay or self.EWMA_DECAY)
        self.min_size = INITIAL_MIN_QUERY_LEN

    def get_min_size(self):
        """Returns the minimum size for the next query"""
        return self.min_size

    def update_tc_flag(self):
        """Updates the estimator when a UDP packet was answered with TC flag set"""
        self.min_size = min(self.min_size + QUERY_MODULO_SIZE, MAX_UDP_DNSPACKET_SIZE)
        self.ewma.set(self.min_size)

    def update(self, packet_size):
        """
        Adds a new packet size to the average of the underlying EWMA and, if
        the moving average has dropped enough, reduces the minimum size
        """
        self.ewma.add(packet_size)
        if QUERY_MODULO_SIZE < self.ewma.get() < self.min_size - QUERY_MODULO_SIZE:
            self.min_size = max(QUERY_MODULO_SIZE, self.min_size - QUERY_MODULO_SIZE)


def validate_provider_name(name, supported_majors):
    """
    Validates the provider name against the format in the specification:
    <protocol-version>.dnscrypt-cert.<zone>
    """
    try:
        version, cert, _ = name.split('.', 2)
        return version in supported_majors and cert in ('dnscrypt-cert', 'dnscrypt')
    except (AttributeError, TypeError):
        return False


def ensure_bytes(data):
    if isinstance(data, str):
        data = data.encode()

    if not isinstance(data, bytes):
        raise TypeError('Input must be bytes')
    return data


def ceil_to_power_of_2(number, round_to):
    """Rounds up any integer to the next higher (or equal) multiple of a given power of 2"""

    if number % round_to:
        return (number + round_to) & (~(round_to-1))
    return number


def iso7816_4_pad(message, total_len):
    """
    Pads a message according as specified in ISO 7816-4:
     - Append byte 0x80
     - Pad the message to requested length with NULL bytes
    """

    if len(message) >= total_len:
        raise ValueError(f'Padded message is at least {len(message) + 1} bytes long')
    return (message + b'\x80').ljust(total_len, b'\x00')


def iso7816_4_unpad(padded):
    """Removes ISO 7816-4 padding"""

    msg_end = padded.rfind(b'\x80')
    if msg_end == -1 or any(x for x in padded[msg_end+1:]):
        raise ValueError(f'Invalid padding')
    return padded[:msg_end]


def udp_send_receive(ip, port, wire, af=None, source=None, source_port=0, ignore_unexpected=False, timeout=None):
    af, destination, source = dns.query._destination_and_source(af, ip, port, source, source_port)
    sock = dns.query.socket_factory(af, socket.SOCK_DGRAM)

    sent_time = None
    received_time = None
    try:
        expiration = dns.query._compute_expiration(timeout)
        sock.setblocking(0)
        ts_start = time.time()
        if source is not None:
            sock.bind(source)
        _, sent_time = dns.query.send_udp(sock, wire, destination, expiration)
        wire, received_time = receive_udp_raw(sock, destination, expiration=expiration, ignore_unexpected=ignore_unexpected)
    finally:
        if sent_time is None or received_time is None:
            response_time = 0
            wire = b''
        else:
            response_time = received_time - sent_time
        sock.close()
        return wire, response_time


def tcp_send_receive(ip, port, wire, af=None, source=None, source_port=0, timeout=None):
    af, destination, source = dns.query._destination_and_source(af, ip, port, source, source_port)
    sock = dns.query.socket_factory(af, socket.SOCK_STREAM)

    sent_time = None
    received_time = None
    try:
        expiration = dns.query._compute_expiration(timeout)
        sock.setblocking(0)
        sent_time = time.time()
        if source is not None:
            sock.bind(source)
        dns.query._connect(sock, destination)
        dns.query.send_tcp(sock, wire, expiration)
        wire, received_time = receive_tcp_raw(sock, expiration=expiration)
    finally:
        if sent_time is None or received_time is None:
            response_time = 0
            wire = b''
        else:
            response_time = received_time - sent_time
        sock.close()
        return wire, response_time


def receive_udp_raw(sock, destination, expiration=None, ignore_unexpected=False):
    """
    Receives a raw UDP message using internal functions of dnspython.

    Arguments:
        sock: The socket on which to listen for the response
        destination: The destination IP address
            from which to expect a response
        expiration: If specified, timestamp of when the request expires
        ignore_unexpected: Whether to ignore responses from other IPs than
            the expected one

    Returns:
        A tuple (response, response_time) consisting of the raw response
        in bytes and the timestamp of when the response was received
    """

    while 1:
        dns.query._wait_for_readable(sock, expiration)
        wire, source = sock.recvfrom(65535)
        if (dns.query._addresses_equal(sock.family, source, destination)
                or (dns.inet.is_multicast(destination[0]) and source[1:] == destination[1:])):
            break
        if not ignore_unexpected:
            raise dns.query.UnexpectedSource(
                f'Received response from {source} instead of {destination}'
            )

    received_time = time.time()
    return wire, received_time


def receive_tcp_raw(sock, expiration=None):
    """
    Receives a raw TCP message using internal functions of dnspython.

    Arguments:
        sock: The socket on which to listen for the response
        expiration: If specified, timestamp of when the request expires

    Returns:
        A tuple (response, response_time) consisting of the raw response
        in bytes and the timestamp of when the response was received
    """

    wire_len = dns.query._net_read(sock, 2, expiration)
    wire_len = struct.unpack('!H', wire_len)[0]
    wire = dns.query._net_read(sock, wire_len, expiration)

    received_time = time.time()
    return wire, received_time


QueryEncoder = namedtuple('QueryEncoder', 'encode decode')

PlainQueryEncoder = QueryEncoder(
    lambda q: (q.to_wire(), None),
    lambda q, _, **kwargs: dns.message.from_wire(q, **kwargs)
)


def query_udp(ip, port, query, query_encoder, one_rr_per_rrset=False, **kwargs):
    wire, decode_args = query_encoder.encode(query)

    response_wire, response_time = udp_send_receive(
        ip,
        port,
        wire,
        **kwargs
    )

    try:
        response = query_encoder.decode(response_wire, decode_args, keyring=query.keyring, request_mac=query.mac, one_rr_per_rrset=one_rr_per_rrset)
    except Exception as e:
        print(response_wire)
        raise e
    response.time = response_time
    if not query.is_response(response):
        raise dns.query.BadResponse()
    return response


def query_tcp(ip, port, query, query_encoder, one_rr_per_rrset=False, **kwargs):
    wire, decode_args = query_encoder.encode(query)

    response_wire, response_time = tcp_send_receive(
        ip,
        port,
        wire,
        **kwargs
    )

    try:
        response = query_encoder.decode(response_wire, decode_args, keyring=query.keyring, request_mac=query.mac, one_rr_per_rrset=one_rr_per_rrset)
    except Exception as e:
        print(response_wire)
        raise e
    response.time = response_time
    if not query.is_response(response):
        raise dns.query.BadResponse()
    return response



def prepare_stamp(stamp):
    if isinstance(stamp, bytes):
        stamp = stamp.decode()
    if isinstance(stamp, str):
        stamp = dnsstamps.parse(stamp)
    if not isinstance(stamp, dnsstamps.parameter.Parameter):
        raise ValueError('Invalid stamp type, must be one of: str, bytes, dnsstamps.parameter.Parameter')
    return stamp


def parse_dnsstamp_address(address, default_port=None):
    ip = address
    port = default_port

    if address.startswith('['):
        if ']' not in address:
            raise ValueError('Invalid address')

        ip, rest = address[1:].split(']')

        if rest:
            port = int(rest[1:])
    elif ':' in address:
        ip, port = address.split(':')
        port = int(port)

    return ip, port


def serialize_ip(ip):
    packed = ipaddress.ip_address(ip).packed
    if len(packed) == 16:
        return packed
    elif len(packed) == 4:
        return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + packed
    raise ValueError('Invalid IP')


def serialize_port(port):
    return struct.pack('!H', port)
