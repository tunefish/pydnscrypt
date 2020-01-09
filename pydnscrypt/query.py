import socket
import struct
import time

from collections import namedtuple

import dns.inet
import dns.query
import dns.message


class QueryEncoder(namedtuple('QueryEncoder', 'encode decode')):
    """
    A simple Encoder object for encoding/decoding DNS queries. Instances of this
    tuple contain two properties defining an encoding and decoding function (or
    method). The functions are defined as follows:

    encode(query):
        Accepts a dnspython message object and encodes it into a byte sequence

        Returns:
            A tuple (byte_sequence, args) containing the serialized DNS message
            and an arbitrary object that allows to transfer state between the
            encoder and the decoder.

    decode(encoded_query, args, **kwargs):
        Parses an encoded DNS message into its dnspython representation

        Arguments:
            encoded_query: the encoded query
            args: the state object returned by the encoder (2nd return value)
            **kwargs: all other arguments must be passed on to dnspython's
                internal message parser by the decoder implementation
    """
    __slots__ = ()


"""PlainQueryEncoder is a wrapper of the encoder/decoder in dnspython"""
PlainQueryEncoder = QueryEncoder(
    lambda q: (q.to_wire(), None),
    lambda q, _, **kwargs: dns.message.from_wire(q, **kwargs)
)


def is_expected_address(af, source, expected_source):
    """Checks whether the source IP address matches the expected source IP"""
    return (dns.query._addresses_equal(af, source, expected_source)
            or (dns.inet.is_multicast(expected_source[0])
                and source[1:] == expected_source[1:]))


def query_udp(ip, port, query,
              query_encoder=PlainQueryEncoder,
              one_rr_per_rrset=False,
              **kwargs):
    """
    Sends a DNS query via UDP and returns the decoded response.

    Arguments:
        ip: The destination IP
        port: The destination port
        query: The query to send
        query_encoder: A `QueryEncoder` instance used for encoding the query and
            decoding the response
        one_rr_per_rrset: whether to use only the first RRset for each section
            (defaults to False)
        **kwargs: passed to udp_send_receive()

    Returns:
        dns.message.Message
    """

    wire, decode_args = query_encoder.encode(query)

    response_wire, response_time = udp_send_receive(ip, port, wire, **kwargs)

    response = query_encoder.decode(response_wire,
                                    decode_args,
                                    keyring=query.keyring,
                                    request_mac=query.mac,
                                    one_rr_per_rrset=one_rr_per_rrset)

    response.time = response_time
    if not query.is_response(response):
        raise dns.query.BadResponse()
    return response


def query_tcp(ip, port, query,
              query_encoder=PlainQueryEncoder,
              one_rr_per_rrset=False,
              **kwargs):
    """
    Sends a DNS query via TCP and returns the decoded response.

    Arguments:
        ip: The destination IP
        port: The destination port
        query: The query to send
        query_encoder: A `QueryEncoder` instance used for encoding the query and
            decoding the response (defaults to the PlainQueryEncoder)
        one_rr_per_rrset: whether to use only the first RRset for each section
            (defaults to False)
        **kwargs: passed to tcp_send_receive()

    Returns:
        dns.message.Message
    """

    wire, decode_args = query_encoder.encode(query)

    response_wire, response_time = tcp_send_receive(ip, port, wire, **kwargs)

    response = query_encoder.decode(response_wire,
                                    decode_args,
                                    keyring=query.keyring,
                                    request_mac=query.mac,
                                    one_rr_per_rrset=one_rr_per_rrset)

    response.time = response_time
    if not query.is_response(response):
        raise dns.query.BadResponse()
    return response


def udp_send_receive(ip, port, wire,
                     af=None,
                     source=None,
                     source_port=0,
                     ignore_unexpected=False,
                     timeout=None):
    """
    Sends a UDP packet to the specified IP and waits for a reply.

    Arguments:
        ip: The destination IP
        port: The destination port
        wire: the payload
        af: address family (optional)
        source: source IP (optional)
        source_port: source port (optional)
        ignore_unexpected: ignore packets arriving at the right port but from
            the wrong IP/port combination
        timeout: if specified, wait until this timestamp for a reply

    Returns:
        A tuple (response, response_time) consisting of the raw response
        in bytes and the timestamp of when the response was received
    """

    af, destination, source = dns.query._destination_and_source(af,
                                                                ip,
                                                                port,
                                                                source,
                                                                source_port)
    sock = dns.query.socket_factory(af, socket.SOCK_DGRAM)

    sent_time = None
    received_time = None
    try:
        expiration = dns.query._compute_expiration(timeout)
        sock.setblocking(0)
        sent_time = time.time()

        if source is not None:
            sock.bind(source)

        dns.query.send_udp(sock, wire, destination, expiration)
        wire, received_time = receive_udp_raw(
            sock,
            destination,
            expiration=expiration,
            ignore_unexpected=ignore_unexpected
        )
    finally:
        sock.close()
    response_time = received_time - sent_time
    return wire, response_time


def tcp_send_receive(ip, port, wire,
                     af=None,
                     source=None,
                     source_port=0,
                     timeout=None):
    """
    Sends a TCP packet to the specified IP and waits for a reply.

    Arguments:
        ip: The destination IP
        port: The destination port
        wire: the payload
        af: address family (optional)
        source: source IP (optional)
        source_port: source port (optional)
        timeout: if specified, wait until this timestamp for a reply

    Returns:
        A tuple (response, response_time) consisting of the raw response
        in bytes and the timestamp of when the response was received
    """

    af, destination, source = dns.query._destination_and_source(af,
                                                                ip,
                                                                port,
                                                                source,
                                                                source_port)
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
        sock.close()
    response_time = received_time - sent_time
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
        if is_expected_address(sock.family, source, destination):
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
