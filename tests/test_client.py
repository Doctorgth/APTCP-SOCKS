import pytest
import asyncio
from client.socks_server import SOCKS5Server
from common.socks5 import SOCKS_VERSION, METHOD_NO_AUTH

@pytest.mark.asyncio
async def test_client_socks5_greeting_no_auth():
    config = {
        "socks_host": "127.0.0.1",
        "socks_port": 10881,
        "auth_enabled": False,
        "aptcp_server_host": "127.0.0.1",
        "aptcp_server_port": 9999,
        "aptcp_auth_enabled": False
    }
    server = SOCKS5Server(config)
    await server.start()

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 10881)
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_NO_AUTH]))
        await writer.drain()

        resp = await reader.readexactly(2)
        assert resp == bytes([SOCKS_VERSION, METHOD_NO_AUTH])

        writer.close()
        await writer.wait_closed()
    finally:
        await server.close()