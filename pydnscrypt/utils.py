import ipaddress
import struct

import dnsstamps

from pydnscrypt.const import (
    INITIAL_MIN_QUERY_LEN,
    QUERY_MODULO_SIZE,
    MAX_UDP_DNSPACKET_SIZE
)


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
        """
        Returns the current average, if enough samples have been collected,
        otherwise None.
        """

        if self.count < self.WARMUP_SAMPLES:
            return 0
        return self.value


class MinQuestionSizeEstimator:
    """
    Simple minimum size estimator for UDP DNSCrypt queries based on the
    requirements mentioned in the specification:
     - Increase minimum query size by 64 bytes if a UDP query is answered
        with TC flag set
     - Decrease minimum query size at will, but must always be a multiple
        of 64 bytes
     - Upper limit given by maximum packet size of transport protocol
    Under the hood, it uses EWMA to calculate the weighted average length
    of previously sent DNSCrypt queries.
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
        """
        Updates the estimator after a UDP packet was answered with TC flag set
        """

        self.min_size = min(self.min_size + QUERY_MODULO_SIZE,
                            MAX_UDP_DNSPACKET_SIZE)
        self.ewma.set(self.min_size)

    def update(self, packet_size):
        """
        Adds a new packet size to the average of the underlying EWMA and, if
        the moving average has dropped enough, reduces the minimum size
        """

        self.ewma.add(packet_size)
        if QUERY_MODULO_SIZE < self.ewma.get() < self.min_size - QUERY_MODULO_SIZE:
            self.min_size = max(QUERY_MODULO_SIZE,
                                self.min_size - QUERY_MODULO_SIZE)


def validate_provider_name(name, supported_majors):
    """
    Validates the provider name against the format in the specification:
    <protocol-version>.dnscrypt-cert.<zone>
    """

    try:
        version, cert, _ = name.split('.', 2)
        return version in supported_majors and cert == 'dnscrypt-cert'
    except (AttributeError, TypeError, ValueError):
        return False


def ceil_to_power_of_2(number, round_to):
    """
    Rounds up any integer to the next higher (or equal) multiple
    of a given power of 2
    """

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
        raise ValueError(
            f'Padded message is at least {len(message) + 1} bytes long'
        )
    return (message + b'\x80').ljust(total_len, b'\x00')


def iso7816_4_unpad(padded):
    """Removes ISO 7816-4 padding"""

    msg_end = padded.rfind(b'\x80')
    if msg_end == -1 or any(x for x in padded[msg_end+1:]):
        raise ValueError(f'Invalid padding')
    return padded[:msg_end]


def prepare_stamp(stamp):
    """
    Takes a bytes ir string object containing a DNS stamp or a parsed DNS stamp
    and returns the parsed DNS stamp
    """

    if isinstance(stamp, bytes):
        stamp = stamp.decode()
    if isinstance(stamp, str):
        stamp = dnsstamps.parse(stamp)
    if not isinstance(stamp, dnsstamps.parameter.Parameter):
        raise TypeError(
            'Invalid stamp type, must be one of: str, bytes, dnsstamps.Parameter'
        )
    return stamp


def parse_dnsstamp_address(address, default_port=None):
    """
    Parses an address from a DNS stamp according to the specification:
     - unwraps IPv6 addresses from the enclosing brackets
     - separates address string into IP(v4/v6) address and port number,
        if specified in the stamp address
    """

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
    """
    Serializes an IP(v4/v6) address into the format required by DNSCrypt:
     - IPv6: the 16 bytes of the IPv6 address
     - IPv4: 10 zero bytes + 2 0xff bytes + the IPv4 address bytes
    """
    packed = ipaddress.ip_address(ip).packed
    if len(packed) == 16:
        return packed
    if len(packed) == 4:
        return b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff' + packed
    raise ValueError('Invalid IP')


def serialize_port(port):
    """Serializes a port number according to the DNSCrypt specification"""
    return struct.pack('!H', port)
