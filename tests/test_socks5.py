import pytest
import asyncio

from common.socks5 import (
    pack_socks_address, read_socks_address,
    parse_udp_packet, pack_udp_packet,
    ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6
)

@pytest.mark.asyncio
async def test_socks_address_ipv4():
    host = "192.168.1.1"
    port = 8080
    packed = pack_socks_address(host, port)

    idx = 0
    async def mock_read(n):
        nonlocal idx
        res = packed[idx:idx+n]
        idx += n
        return res

    atyp, r_host, r_port, raw = await read_socks_address(mock_read)
    assert atyp == ATYP_IPV4
    assert r_host == host
    assert r_port == port
    assert raw == packed


@pytest.mark.asyncio
async def test_socks_address_domain():
    host = "example.com"
    port = 443
    packed = pack_socks_address(host, port)

    idx = 0
    async def mock_read(n):
        nonlocal idx
        res = packed[idx:idx+n]
        idx += n
        return res

    atyp, r_host, r_port, raw = await read_socks_address(mock_read)
    assert atyp == ATYP_DOMAIN
    assert r_host == host
    assert r_port == port
    assert raw == packed


@pytest.mark.asyncio
async def test_socks_address_ipv6():
    host = "2001:db8::1"
    port = 9000
    packed = pack_socks_address(host, port)

    idx = 0
    async def mock_read(n):
        nonlocal idx
        res = packed[idx:idx+n]
        idx += n
        return res

    atyp, r_host, r_port, raw = await read_socks_address(mock_read)
    assert atyp == ATYP_IPV6
    assert r_host == "2001:db8::1"
    assert r_port == port
    assert raw == packed


def test_udp_packet_packing_and_parsing():
    dst_host = "8.8.8.8"
    dst_port = 53
    payload = b"hello udp world"

    pkt = pack_udp_packet(dst_host, dst_port, payload)
    rsv, frag, atyp, r_host, r_port, r_payload = parse_udp_packet(pkt)

    assert rsv == 0
    assert frag == 0
    assert atyp == ATYP_IPV4
    assert r_host == dst_host
    assert r_port == dst_port
    assert r_payload == payload


def test_udp_packet_malformed():
    with pytest.raises(ValueError):
        parse_udp_packet(b"short")