import asyncio
import socket
import logging
from typing import Dict, Any

from common.config import load_users_jsonl, validate_credentials
from common.socks5 import (
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_SUCCESS, REP_CONN_REFUSED, REP_CMD_NOT_SUPPORTED,
    parse_udp_packet, pack_udp_packet
)
from common.tunnel import (
    PTCPStream, read_tunnel_auth_request, send_tunnel_auth_response,
    read_tunnel_cmd_request, send_tunnel_cmd_response,
    TUNNEL_AUTH_USER_PASS, TUNNEL_AUTH_SUCCESS, TUNNEL_AUTH_FAIL,
    send_udp_frame, read_udp_frame
)

logger = logging.getLogger("SOCKS5ServerHandler")


class TunnelHandler:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.auth_enabled = config.get("auth_enabled", False)
        self.users_file = config.get("users_file", "server/users.jsonl")
        self.users = load_users_jsonl(self.users_file) if self.auth_enabled else {}

    async def handle_connection(self, ptcp_socket: Any):
        stream = PTCPStream(ptcp_socket)
        try:
            # 1. Tunnel Authentication
            auth_type, username, password = await read_tunnel_auth_request(stream)
            if self.auth_enabled:
                if auth_type != TUNNEL_AUTH_USER_PASS or not validate_credentials(self.users, username, password):
                    logger.warning(f"Server tunnel auth failed for user: {username}")
                    await send_tunnel_auth_response(stream, TUNNEL_AUTH_FAIL)
                    await stream.close()
                    return
                await send_tunnel_auth_response(stream, TUNNEL_AUTH_SUCCESS)
            else:
                await send_tunnel_auth_response(stream, TUNNEL_AUTH_SUCCESS)

            # 2. Command Request
            cmd, atyp, host, port = await read_tunnel_cmd_request(stream)

            if cmd == CMD_CONNECT:
                await self._handle_tcp_connect(stream, host, port)
            elif cmd == CMD_UDP_ASSOCIATE:
                await self._handle_udp_associate(stream, host, port)
            else:
                await send_tunnel_cmd_response(stream, REP_CMD_NOT_SUPPORTED)
                await stream.close()

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"Error handling tunnel connection: {e}")
        finally:
            try:
                await stream.close()
            except Exception:
                pass

    async def _handle_tcp_connect(self, stream: PTCPStream, host: str, port: int):
        try:
            target_reader, target_writer = await asyncio.open_connection(host, port)
        except Exception as e:
            logger.warning(f"Target connection failed to {host}:{port} - {e}")
            await send_tunnel_cmd_response(stream, REP_CONN_REFUSED)
            return

        await send_tunnel_cmd_response(stream, REP_SUCCESS)

        async def ptcp_to_target():
            try:
                while True:
                    data = await stream.read(65536)
                    if not data:
                        break
                    target_writer.write(data)
                    await target_writer.drain()
            except Exception:
                pass

        async def target_to_ptcp():
            try:
                while True:
                    data = await target_reader.read(65536)
                    if not data:
                        break
                    await stream.send(data)
            except Exception:
                pass

        t1 = asyncio.create_task(ptcp_to_target())
        t2 = asyncio.create_task(target_to_ptcp())
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        target_writer.close()

    async def _handle_udp_associate(self, stream: PTCPStream, host: str, port: int):
        loop = asyncio.get_running_loop()
        server_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_udp_sock.bind(('0.0.0.0', 0))
        server_udp_sock.setblocking(False)

        await send_tunnel_cmd_response(stream, REP_SUCCESS)

        async def ptcp_to_target_udp():
            try:
                while True:
                    frame = await read_udp_frame(stream)
                    rsv, frag, atyp, dst_host, dst_port, payload = parse_udp_packet(frame)
                    await loop.sock_sendto(server_udp_sock, payload, (dst_host, dst_port))
            except Exception:
                pass

        async def target_udp_to_ptcp():
            try:
                while True:
                    payload, target_addr = await loop.sock_recvfrom(server_udp_sock, 65536)
                    target_host, target_port = target_addr[0], target_addr[1]
                    resp_frame = pack_udp_packet(target_host, target_port, payload)
                    await send_udp_frame(stream, resp_frame)
            except Exception:
                pass

        t1 = asyncio.create_task(ptcp_to_target_udp())
        t2 = asyncio.create_task(target_udp_to_ptcp())

        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

        for t in (t1, t2):
            t.cancel()

        server_udp_sock.close()