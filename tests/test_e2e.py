import pytest
import asyncio
import socket
import os
import tempfile
import json

from server.aptcp_server import APTCPSocksServer
from client.socks_server import SOCKS5Server
from common.socks5 import (
    SOCKS_VERSION, METHOD_USER_PASS,
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_SUCCESS, read_socks_address, pack_socks_address,
    pack_udp_packet, parse_udp_packet
)


async def run_tcp_echo_server():
    server = await asyncio.start_server(
        lambda r, w: asyncio.create_task(_tcp_echo_handler(r, w)),
        '127.0.0.1', 0
    )
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


async def run_udp_echo_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 0))
    sock.setblocking(False)
    port = sock.getsockname()[1]

    async def echo_loop():
        loop = asyncio.get_running_loop()
        try:
            while True:
                data, addr = await loop.sock_recvfrom(sock, 65536)
                await loop.sock_sendto(sock, b"UDPECHO:" + data, addr)
        except Exception:
            pass

    task = asyncio.create_task(echo_loop())
    return sock, task, port


@pytest.mark.asyncio
async def test_e2e_socks5_auth_and_tcp_and_udp():
    # 1. Prepare users files
    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_client:
        f_client.write(json.dumps({"username": "proxuser", "password": "proxpass"}) + "\n")
        client_users_file = f_client.name

    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_server:
        f_server.write(json.dumps({"username": "aptcpuser", "password": "aptcppass"}) + "\n")
        server_users_file = f_server.name

    # 2. Start TCP & UDP Echo Servers
    tcp_echo_srv, tcp_echo_port = await run_tcp_echo_server()
    udp_echo_sock, udp_echo_task, udp_echo_port = await run_udp_echo_server()

    # 3. Start APTCP Server
    aptcp_server_config = {
        "aptcp_host": "127.0.0.1",
        "aptcp_port": 19090,
        "auth_enabled": True,
        "users_file": server_users_file,
        "timeout": 30
    }
    aptcp_server = APTCPSocksServer(aptcp_server_config)
    await aptcp_server.start()

    # 4. Start SOCKS5 Client
    socks_client_config = {
        "socks_host": "127.0.0.1",
        "socks_port": 11080,
        "auth_enabled": True,
        "users_file": client_users_file,
        "aptcp_server_host": "127.0.0.1",
        "aptcp_server_port": 19090,
        "aptcp_auth_enabled": True,
        "aptcp_username": "aptcpuser",
        "aptcp_password": "aptcppass"
    }
    socks_server = SOCKS5Server(socks_client_config)
    await socks_server.start()

    await asyncio.sleep(0.5)

    try:
        # --- TEST 1: Wrong Proxifier Password ---
        reader, writer = await asyncio.open_connection("127.0.0.1", 11080)
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_USER_PASS]))
        await writer.drain()
        resp = await reader.readexactly(2)
        assert resp == bytes([SOCKS_VERSION, METHOD_USER_PASS])

        # Subnegotiation with WRONG password
        writer.write(bytes([0x01, 8]) + b"proxuser" + bytes([8]) + b"wrongpass")
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        assert auth_resp[1] == 0x01 # Auth failed!
        writer.close()
        await writer.wait_closed()


        # --- TEST 2: Correct Auth + TCP CONNECT ---
        reader, writer = await asyncio.open_connection("127.0.0.1", 11080)
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_USER_PASS]))
        await writer.drain()
        await reader.readexactly(2)

        # Subnegotiation with CORRECT password
        writer.write(bytes([0x01, 8]) + b"proxuser" + bytes([8]) + b"proxpass")
        await writer.drain()
        auth_resp = await reader.readexactly(2)
        assert auth_resp[1] == 0x00 # Auth Success!

        # Send CMD_CONNECT to TCP Echo Server
        cmd_req = bytes([SOCKS_VERSION, CMD_CONNECT, 0x00]) + pack_socks_address("127.0.0.1", tcp_echo_port)
        writer.write(cmd_req)
        await writer.drain()

        # Read Response
        resp_hdr = await reader.readexactly(3)
        assert resp_hdr[1] == REP_SUCCESS
        _, _, _, _ = await read_socks_address(reader.readexactly)

        # Send TCP Data
        writer.write(b"Hello APTCP TCP")
        await writer.drain()

        echo_data = await reader.readexactly(len(b"ECHO:Hello APTCP TCP"))
        assert echo_data == b"ECHO:Hello APTCP TCP"

        writer.close()
        await writer.wait_closed()


        # --- TEST 3: Correct Auth + UDP ASSOCIATE ---
        reader, writer = await asyncio.open_connection("127.0.0.1", 11080)
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_USER_PASS]))
        await writer.drain()
        await reader.readexactly(2)

        writer.write(bytes([0x01, 8]) + b"proxuser" + bytes([8]) + b"proxpass")
        await writer.drain()
        await reader.readexactly(2)

        # Send CMD_UDP_ASSOCIATE
        cmd_req = bytes([SOCKS_VERSION, CMD_UDP_ASSOCIATE, 0x00]) + pack_socks_address("0.0.0.0", 0)
        writer.write(cmd_req)
        await writer.drain()

        resp_hdr = await reader.readexactly(3)
        assert resp_hdr[1] == REP_SUCCESS
        _, client_bnd_host, client_bnd_port, _ = await read_socks_address(reader.readexactly)

        # Create Client UDP socket to send datagrams to SOCKS5 UDP relay
        client_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client_udp_sock.bind(('127.0.0.1', 0))
        client_udp_sock.setblocking(False)

        udp_payload = b"Hello APTCP UDP"
        udp_packet = pack_udp_packet("127.0.0.1", udp_echo_port, udp_payload)

        loop = asyncio.get_running_loop()
        await loop.sock_sendto(client_udp_sock, udp_packet, (client_bnd_host, client_bnd_port))

        resp_udp_data, _ = await asyncio.wait_for(loop.sock_recvfrom(client_udp_sock, 65536), timeout=3.0)

        rsv, frag, atyp, resp_host, resp_port, resp_payload = parse_udp_packet(resp_udp_data)
        assert resp_payload == b"UDPECHO:Hello APTCP UDP"

        client_udp_sock.close()
        writer.close()
        await writer.wait_closed()

    finally:
        await socks_server.close()
        tcp_echo_srv.close()
        await tcp_echo_srv.wait_closed()
        udp_echo_task.cancel()
        udp_echo_sock.close()
        os.remove(client_users_file)
        os.remove(server_users_file)


@pytest.mark.asyncio
async def test_e2e_network_disconnect_resilience():
    """
    Simulates abrupt physical TCP connection drops during active SOCKS5 traffic
    to ensure aioptcp automatically restores session without losing proxy state.
    """
    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_client:
        f_client.write(json.dumps({"username": "u", "password": "p"}) + "\n")
        c_users = f_client.name

    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as f_server:
        f_server.write(json.dumps({"username": "u", "password": "p"}) + "\n")
        s_users = f_server.name

    tcp_echo_srv, tcp_echo_port = await run_tcp_echo_server()

    aptcp_server = APTCPSocksServer({
        "aptcp_host": "127.0.0.1", "aptcp_port": 19091,
        "auth_enabled": True, "users_file": s_users, "timeout": 30
    })
    await aptcp_server.start()

    socks_server = SOCKS5Server({
        "socks_host": "127.0.0.1", "socks_port": 11081,
        "auth_enabled": True, "users_file": c_users,
        "aptcp_server_host": "127.0.0.1", "aptcp_server_port": 19091,
        "aptcp_auth_enabled": True, "aptcp_username": "u", "aptcp_password": "p"
    })
    await socks_server.start()

    await asyncio.sleep(0.5)

    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", 11081)
        writer.write(bytes([SOCKS_VERSION, 1, METHOD_USER_PASS]))
        await writer.drain()
        await reader.readexactly(2)

        writer.write(bytes([0x01, 1]) + b"u" + bytes([1]) + b"p")
        await writer.drain()
        await reader.readexactly(2)

        cmd_req = bytes([SOCKS_VERSION, CMD_CONNECT, 0x00]) + pack_socks_address("127.0.0.1", tcp_echo_port)
        writer.write(cmd_req)
        await writer.drain()

        resp_hdr = await reader.readexactly(3)
        assert resp_hdr[1] == REP_SUCCESS
        _, _, _, _ = await read_socks_address(reader.readexactly)

        # 1. First packet before disconnect
        writer.write(b"Message 1")
        await writer.drain()
        res1 = await reader.readexactly(len(b"ECHO:Message 1"))
        assert res1 == b"ECHO:Message 1"

        # 2. Simulate abrupt physical TCP disconnect on server side active PTCP session
        if aptcp_server.ptcp_server.sessions:
            for sid, conn in list(aptcp_server.ptcp_server.sessions.items()):
                if conn.writer:
                    conn.writer.transport.close() # Close physical underlying socket!

        # 3. Immediately send Message 2 while link is down
        writer.write(b"Message 2")
        await writer.drain()

        # aioptcp will perform reconnect in background and deliver Message 2
        res2 = await asyncio.wait_for(reader.readexactly(len(b"ECHO:Message 2")), timeout=10.0)
        assert res2 == b"ECHO:Message 2"

        writer.close()
        await writer.wait_closed()

    finally:
        await socks_server.close()
        tcp_echo_srv.close()
        await tcp_echo_srv.wait_closed()
        os.remove(c_users)
        os.remove(s_users)