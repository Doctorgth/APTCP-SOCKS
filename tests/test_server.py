import pytest
import asyncio
from server.socks_handler import TunnelHandler
from common.tunnel import (
    PTCPStream, send_tunnel_auth_request, read_tunnel_auth_response,
    TUNNEL_AUTH_NONE, TUNNEL_AUTH_SUCCESS
)

class MockPTCPConn:
    def __init__(self):
        self.client_queue = asyncio.Queue()
        self.server_queue = asyncio.Queue()

    class SocketSide:
        def __init__(self, in_q, out_q):
            self.in_q = in_q
            self.out_q = out_q

        async def send(self, data: bytes) -> bool:
            await self.out_q.put(data)
            return True

        async def recv(self, size: int) -> bytes:
            data = await self.in_q.get()
            return data

        async def close(self):
            pass

    def get_client_side(self):
        return self.SocketSide(self.server_queue, self.client_queue)

    def get_server_side(self):
        return self.SocketSide(self.client_queue, self.server_queue)


@pytest.mark.asyncio
async def test_server_tunnel_auth_no_auth_mode():
    config = {"auth_enabled": False}
    handler = TunnelHandler(config)

    mock = MockPTCPConn()
    server_sock = mock.get_server_side()
    client_sock = mock.get_client_side()

    handler_task = asyncio.create_task(handler.handle_connection(server_sock))

    client_stream = PTCPStream(client_sock)
    await send_tunnel_auth_request(client_stream, auth_type=TUNNEL_AUTH_NONE)
    status = await read_tunnel_auth_response(client_stream)

    assert status == TUNNEL_AUTH_SUCCESS

    await client_stream.close()
    handler_task.cancel()