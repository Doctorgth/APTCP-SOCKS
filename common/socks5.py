import socket
import struct
import ipaddress
from typing import Tuple, Callable, Awaitable

SOCKS_VERSION = 0x05

METHOD_NO_AUTH = 0x00
METHOD_USER_PASS = 0x02
METHOD_NO_ACCEPTABLE = 0xFF

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONN_NOT_ALLOWED = 0x02
REP_NET_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONN_REFUSED = 0x05
REP_CMD_NOT_SUPPORTED = 0x07
REP_ATYP_NOT_SUPPORTED = 0x08


def pack_socks_address(host: str, port: int) -> bytes:
    """Packs host and port into SOCKS5 ATYP + ADDR + PORT format."""
    try:
        ip = ipaddress.ip_address(host)
        if ip.version == 4:
            return struct.pack('!B', ATYP_IPV4) + ip.packed + struct.pack('!H', port)
        else:
            return struct.pack('!B', ATYP_IPV6) + ip.packed + struct.pack('!H', port)
    except ValueError:
        encoded = host.encode('utf-8')
        if len(encoded) > 255:
            raise ValueError("Domain name exceeds 255 bytes limit")
        return struct.pack('!BB', ATYP_DOMAIN, len(encoded)) + encoded + struct.pack('!H', port)


async def read_socks_address(read_exact_func: Callable[[int], Awaitable[bytes]]) -> Tuple[int, str, int, bytes]:
    """
    Reads SOCKS5 address structure from a stream function read_exact_func(n).
    Returns (atyp, host_str, port_int, raw_bytes).
    """
    atyp_bytes = await read_exact_func(1)
    atyp = atyp_bytes[0]
    raw_acc = bytearray(atyp_bytes)

    if atyp == ATYP_IPV4:
        addr_bytes = await read_exact_func(4)
        raw_acc.extend(addr_bytes)
        host = socket.inet_ntoa(addr_bytes)
    elif atyp == ATYP_DOMAIN:
        len_byte = await read_exact_func(1)
        raw_acc.extend(len_byte)
        domain_len = len_byte[0]
        domain_bytes = await read_exact_func(domain_len)
        raw_acc.extend(domain_bytes)
        host = domain_bytes.decode('utf-8', errors='ignore')
    elif atyp == ATYP_IPV6:
        addr_bytes = await read_exact_func(16)
        raw_acc.extend(addr_bytes)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise ValueError(f"Unsupported SOCKS5 ATYP: {atyp}")

    port_bytes = await read_exact_func(2)
    raw_acc.extend(port_bytes)
    port = struct.unpack('!H', port_bytes)[0]

    return atyp, host, port, bytes(raw_acc)


def parse_udp_packet(data: bytes) -> Tuple[int, int, int, str, int, bytes]:
    """
    Parses SOCKS5 UDP datagram header (RFC 1928 Section 7):
    +----+------+------+----------+----------+----------+
    |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
    +----+------+------+----------+----------+----------+
    Returns (rsv, frag, atyp, dst_host, dst_port, payload).
    """
    if len(data) < 10:
        raise ValueError("UDP packet too short for SOCKS5 header")
    rsv, frag, atyp = struct.unpack('!HBB', data[:4])
    idx = 4
    if atyp == ATYP_IPV4:
        dst_host = socket.inet_ntoa(data[idx:idx+4])
        idx += 4
    elif atyp == ATYP_DOMAIN:
        domain_len = data[idx]
        idx += 1
        dst_host = data[idx:idx+domain_len].decode('utf-8', errors='ignore')
        idx += domain_len
    elif atyp == ATYP_IPV6:
        dst_host = socket.inet_ntop(socket.AF_INET6, data[idx:idx+16])
        idx += 16
    else:
        raise ValueError(f"Invalid SOCKS5 UDP ATYP: {atyp}")

    dst_port = struct.unpack('!H', data[idx:idx+2])[0]
    idx += 2
    payload = data[idx:]
    return rsv, frag, atyp, dst_host, dst_port, payload


def pack_udp_packet(dst_host: str, dst_port: int, payload: bytes, frag: int = 0) -> bytes:
    """
    Packs SOCKS5 UDP datagram header + payload.
    """
    header_prefix = struct.pack('!HB', 0, frag)
    addr_bytes = pack_socks_address(dst_host, dst_port)
    return header_prefix + addr_bytes + payload