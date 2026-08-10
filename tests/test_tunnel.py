import pytest
import asyncio

from common.tunnel import (
    PTCPStream, send_tunnel_auth_request, read_tunnel_auth_request,
    send_tunnel_auth_response, read_tunnel_auth_response,
    send_tunnel_cmd_request, read_tunnel_cmd_request,
    send_tunnel_cmd_response, read_tunnel_cmd_response,
    send_udp_frame, read_udp_frame,
    TUNNEL_AUTH_USER_PASS, TUNNEL_AUTH_NONE, TUNNEL_AUTH_SUCCESS
)

class MockPTCPSocket:
    def __init__(self):
        self.sent_data = bytearray()
        self.recv_queue = asyncio.Queue()

    async def send(self, data: bytes) -> bool:
        self.sent_data.extend(data)
        await self.recv_queue.put(data)
        return True

    async def recv(self, size: int) -> bytes:
        if not hasattr(self, '_current_chunk') or not self._current_chunk:
            self._current_chunk = await self.recv_queue.get()
        res = self._current_chunk[:size]
        self._current_chunk = self._current_chunk[size:]
        return res

    async def close(self):
        pass


@pytest.mark.asyncio
async def test_tunnel_auth_framing():
    sock = MockPTCPSocket()
    stream = PTCPStream(sock)

    await send_tunnel_auth_request(stream, "myuser", "mypass", auth_type=TUNNEL_AUTH_USER_PASS)
    auth_type, user, password = await read_tunnel_auth_request(stream)

    assert auth_type == TUNNEL_AUTH_USER_PASS
    assert user == "myuser"
    assert password == "mypass"

    await send_tunnel_auth_response(stream, TUNNEL_AUTH_SUCCESS)
    status = await read_tunnel_auth_response(stream)
    assert status == TUNNEL_AUTH_SUCCESS


@pytest.mark.asyncio
async def test_tunnel_cmd_framing():
    sock = MockPTCPSocket()
    stream = PTCPStream(sock)

    await send_tunnel_cmd_request(stream, cmd=1, host="127.0.0.1", port=80)
    cmd, atyp, host, port = await read_tunnel_cmd_request(stream)

    assert cmd == 1
    assert host == "127.0.0.1"
    assert port == 80

    await send_tunnel_cmd_response(stream, rep=0, bound_host="0.0.0.0", bound_port=0)
    rep, b_atyp, b_host, b_port = await read_tunnel_cmd_response(stream)

    assert rep == 0
    assert b_host == "0.0.0.0"
    assert b_port == 0


@pytest.mark.asyncio
async def test_udp_frame_framing():
    sock = MockPTCPSocket()
    stream = PTCPStream(sock)

    payload = b"udp payload data 123"
    await send_udp_frame(stream, payload)
    read_payload = await read_udp_frame(stream)

    assert read_payload == payload