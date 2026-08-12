import pytest
import asyncio
import time
import os
import tempfile
import json

from server.aptcp_server import APTCPSocksServer
from client.socks_server import SOCKS5Server
from common.socks5 import (
    SOCKS_VERSION, METHOD_USER_PASS,
    CMD_CONNECT, REP_SUCCESS,
    read_socks_address, pack_socks_address
)

_echo_tasks = set()

async def run_tcp_echo_server():
    def _start_handler(r, w):
        task = asyncio.create_task(_tcp_echo_handler(r, w))
        _echo_tasks.add(task)
        task.add_done_callback(_echo_tasks.discard)

    server = await asyncio.start_server(_start_handler, '127.0.0.1', 0)
    port = server.sockets[0].getsockname()[1]
    return server, port

async def _tcp_echo_handler(reader, writer):
    try:
        while True:
            data = await reader.read(1024)
            if not data:
                break
            writer.write(b"ECHO:" + data)
            await writer.drain()
    except Exception:
        pass
    finally:
        writer.close()

@pytest.mark.asyncio
async def test_burst_concurrent_connections():
    """
    Тестирует стандартную параллельную работу нескольких соединений.
    """
    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_client:
        f_client.write(json.dumps({"username": "u", "password": "p"}) + "\n")
        c_users = f_client.name

    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_server:
        f_server.write(json.dumps({"username": "u", "password": "p"}) + "\n")
        s_users = f_server.name

    tcp_echo_srv, tcp_echo_port = await run_tcp_echo_server()

    aptcp_server = APTCPSocksServer({
        "aptcp_host": "127.0.0.1", "aptcp_port": 19095,
        "auth_enabled": True, "users_file": s_users, "timeout": 30
    })
    await aptcp_server.start()

    socks_server = SOCKS5Server({
        "socks_host": "127.0.0.1", "socks_port": 11095,
        "auth_enabled": True, "users_file": c_users,
        "aptcp_server_host": "127.0.0.1", "aptcp_server_port": 19095,
        "aptcp_auth_enabled": True, "aptcp_username": "u", "aptcp_password": "p"
    })
    await socks_server.start()

    await asyncio.sleep(0.3)

    async def single_client_connect(idx: int):
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", 11095)

            # 1. Greeting
            writer.write(bytes([SOCKS_VERSION, 1, METHOD_USER_PASS]))
            await writer.drain()
            await reader.readexactly(2)

            # 2. Auth
            writer.write(bytes([0x01, 1]) + b"u" + bytes([1]) + b"p")
            await writer.drain()
            await reader.readexactly(2)

            # 3. Connect Request
            cmd_req = bytes([SOCKS_VERSION, CMD_CONNECT, 0x00]) + pack_socks_address("127.0.0.1", tcp_echo_port)
            writer.write(cmd_req)
            await writer.drain()

            resp_hdr = await reader.readexactly(3)
            if resp_hdr[1] != REP_SUCCESS:
                writer.close()
                await writer.wait_closed()
                return False

            _, _, _, _ = await read_socks_address(reader.readexactly)

            # 4. Обмен данными
            msg = f"EdgeSocket_{idx}".encode()
            writer.write(msg)
            await writer.drain()

            res = await reader.readexactly(len(b"ECHO:" + msg))
            assert res == b"ECHO:" + msg

            writer.close()
            await writer.wait_closed()
            return True
        except Exception as e:
            print(f"Socket {idx} failed: {e}")
            return False

    try:
        start_time = time.time()
        tasks = [single_client_connect(i) for i in range(5)]
        results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=10.0)
        elapsed = time.time() - start_time

        assert len(results) == 5
        assert all(results)
        print(f"\n[УСПЕХ BENCHMARK] Сокеты обработаны за {elapsed:.2f} сек!")

    finally:
        await socks_server.close()
        tcp_echo_srv.close()
        await tcp_echo_srv.wait_closed()
        os.remove(c_users)
        os.remove(s_users)