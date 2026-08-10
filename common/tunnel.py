import struct
import asyncio
from typing import Tuple, Any
from common.socks5 import read_socks_address, pack_socks_address

TUNNEL_VERSION = 0x01

TUNNEL_AUTH_NONE = 0x00
TUNNEL_AUTH_USER_PASS = 0x02

TUNNEL_AUTH_SUCCESS = 0x00
TUNNEL_AUTH_FAIL = 0x01


class PTCPStream:
    """
    Stream adapter wrapping a PTCPSocket or custom socket object
    to support byte-level readexactly and send methods.
    """
    def __init__(self, ptcp_socket: Any):
        self.socket = ptcp_socket
        self._buffer = bytearray()

    async def readexactly(self, n: int) -> bytes:
        while len(self._buffer) < n:
            chunk = await self.socket.recv(65536)
            if not chunk:
                raise asyncio.IncompleteReadError(bytes(self._buffer), n)
            self._buffer.extend(chunk)
        res = bytes(self._buffer[:n])
        del self._buffer[:n]
        return res

    async def read(self, max_bytes: int = 65536) -> bytes:
        if self._buffer:
            res = bytes(self._buffer[:max_bytes])
            del self._buffer[:max_bytes]
            return res
        return await self.socket.recv(max_bytes)

    async def send(self, data: bytes) -> bool:
        return await self.socket.send(data)

    async def close(self):
        await self.socket.close()


async def send_tunnel_auth_request(stream: PTCPStream, username: str = "", password: str = "", auth_type: int = TUNNEL_AUTH_NONE):
    if auth_type == TUNNEL_AUTH_NONE:
        header = struct.pack('!BB', TUNNEL_VERSION, TUNNEL_AUTH_NONE)
        await stream.send(header)
    elif auth_type == TUNNEL_AUTH_USER_PASS:
        u_bytes = username.encode('utf-8')
        p_bytes = password.encode('utf-8')
        header = struct.pack('!BBB', TUNNEL_VERSION, TUNNEL_AUTH_USER_PASS, len(u_bytes)) + u_bytes + struct.pack('!B', len(p_bytes)) + p_bytes
        await stream.send(header)


async def read_tunnel_auth_request(stream: PTCPStream) -> Tuple[int, str, str]:
    ver_auth = await stream.readexactly(2)
    ver, auth_type = ver_auth[0], ver_auth[1]
    if ver != TUNNEL_VERSION:
        raise ValueError(f"Unsupported Tunnel Protocol Version: {ver}")

    if auth_type == TUNNEL_AUTH_NONE:
        return auth_type, "", ""
    elif auth_type == TUNNEL_AUTH_USER_PASS:
        u_len = (await stream.readexactly(1))[0]
        u_bytes = await stream.readexactly(u_len)
        p_len = (await stream.readexactly(1))[0]
        p_bytes = await stream.readexactly(p_len)
        return auth_type, u_bytes.decode('utf-8', errors='ignore'), p_bytes.decode('utf-8', errors='ignore')
    else:
        raise ValueError(f"Unknown Tunnel Auth Type: {auth_type}")


async def send_tunnel_auth_response(stream: PTCPStream, status: int):
    await stream.send(struct.pack('!B', status))


async def read_tunnel_auth_response(stream: PTCPStream) -> int:
    b = await stream.readexactly(1)
    return b[0]


async def send_tunnel_cmd_request(stream: PTCPStream, cmd: int, host: str, port: int):
    addr_bytes = pack_socks_address(host, port)
    data = struct.pack('!B', cmd) + addr_bytes
    await stream.send(data)


async def read_tunnel_cmd_request(stream: PTCPStream) -> Tuple[int, int, str, int]:
    cmd_byte = await stream.readexactly(1)
    cmd = cmd_byte[0]
    atyp, host, port, _ = await read_socks_address(stream.readexactly)
    return cmd, atyp, host, port


async def send_tunnel_cmd_response(stream: PTCPStream, rep: int, bound_host: str = "0.0.0.0", bound_port: int = 0):
    addr_bytes = pack_socks_address(bound_host, bound_port)
    data = struct.pack('!B', rep) + addr_bytes
    await stream.send(data)


async def read_tunnel_cmd_response(stream: PTCPStream) -> Tuple[int, int, str, int]:
    rep_byte = await stream.readexactly(1)
    rep = rep_byte[0]
    atyp, host, port, _ = await read_socks_address(stream.readexactly)
    return rep, atyp, host, port


async def send_udp_frame(stream: PTCPStream, payload: bytes):
    """Sends a length-prefixed UDP frame over APTCP stream."""
    length = len(payload)
    if length > 65535:
        raise ValueError("UDP payload too large for single frame")
    header = struct.pack('!H', length)
    await stream.send(header + payload)


async def read_udp_frame(stream: PTCPStream) -> bytes:
    """Reads a length-prefixed UDP frame from APTCP stream."""
    length_bytes = await stream.readexactly(2)
    length = struct.unpack('!H', length_bytes)[0]
    return await stream.readexactly(length)