import asyncio
import socket
import logging
import time
from typing import Dict, Any

from common.config import load_users_jsonl, validate_credentials
from common.socks5 import (
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_SUCCESS, REP_CONN_REFUSED, REP_CMD_NOT_SUPPORTED,
    parse_udp_packet, pack_udp_packet, read_socks_address, pack_socks_address
)
from common.tunnel import (
    PTCPStream, read_tunnel_auth_request, send_tunnel_auth_response,
    TUNNEL_AUTH_USER_PASS, TUNNEL_AUTH_SUCCESS, TUNNEL_AUTH_FAIL
)
from common.mux import MuxSession, MuxChannel, FRAME_OPEN_RESP

logger = logging.getLogger("SOCKS5ServerHandler")


class TunnelHandler:
    _dns_cache: Dict[str, tuple[str, float]] = {}  # domain -> (ip, expire_time)
    _dns_futures: Dict[str, asyncio.Future] = {}   # in-flight DNS requests

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.auth_enabled = config.get("auth_enabled", False)
        self.users_file = config.get("users_file", "server/users.jsonl")
        self.users = load_users_jsonl(self.users_file) if self.auth_enabled else {}

    @classmethod
    async def _async_resolve_host(cls, host: str) -> str:
        """Сверхбыстрый асинхронный резолвер DNS с защитой от шторма запросов."""
        try:
            socket.inet_aton(host)
            return host
        except socket.error:
            pass

        now = time.time()
        if host in cls._dns_cache:
            ip, expire = cls._dns_cache[host]
            if now < expire:
                return ip

        if host in cls._dns_futures:
            try:
                return await cls._dns_futures[host]
            except Exception:
                return host

        loop = asyncio.get_running_loop()
        future = loop.create_future()
        cls._dns_futures[host] = future

        try:
            info = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
            resolved_ip = info[0][4][0] if info else host
            cls._dns_cache[host] = (resolved_ip, now + 300.0)
            future.set_result(resolved_ip)
            return resolved_ip
        except Exception as e:
            if not future.done():
                future.set_result(host)
            return host
        finally:
            cls._dns_futures.pop(host, None)

    async def handle_connection(self, ptcp_socket: Any):
        stream = PTCPStream(ptcp_socket)
        try:
            # 1. Tunnel Authentication (выполняется 1 раз при установлении Mux туннеля)
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

            # 2. Переходим в мультиплексированный режим
            mux_session = MuxSession(stream, is_server=True, on_new_stream_cb=self._handle_mux_stream)
            await mux_session._read_loop_task

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"Error handling tunnel connection: {e}")
        finally:
            try:
                await stream.close()
            except Exception:
                pass

    async def _handle_mux_stream(self, channel: MuxChannel, payload: bytes):
        try:
            cmd = payload[0]
            idx = 1
            async def mock_read(n):
                nonlocal idx
                res = payload[idx:idx+n]
                idx += n
                return res

            atyp, host, port, _ = await read_socks_address(mock_read)
            logger.info(f"[MUX] Stream {channel.stream_id} request: cmd={cmd}, host={host}:{port}")

            if cmd == CMD_CONNECT:
                await self._handle_tcp_connect(channel, host, port)
            elif cmd == CMD_UDP_ASSOCIATE:
                await self._handle_udp_associate(channel, host, port)
            else:
                resp_payload = bytes([REP_CMD_NOT_SUPPORTED]) + pack_socks_address("0.0.0.0", 0)
                await channel.session.send_frame(channel.stream_id, FRAME_OPEN_RESP, resp_payload)
                await channel.close()
        except Exception as e:
            logger.error(f"Error in Mux stream handler: {e}")
            await channel.close()

    async def _handle_tcp_connect(self, channel: MuxChannel, host: str, port: int):
        try:
            logger.info(f"[MUX] Stream {channel.stream_id} Resolving DNS for: {host}")
            target_ip = await self._async_resolve_host(host)
            logger.info(f"[MUX] Stream {channel.stream_id} DNS Resolved {host} -> {target_ip}. Connecting to target...")
            
            target_reader, target_writer = await asyncio.open_connection(target_ip, port)
            logger.info(f"[MUX] Stream {channel.stream_id} Connected to target {host}:{port} successfully!")

            sock = target_writer.get_extra_info('socket')
            if sock:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass

        except Exception as e:
            logger.warning(f"Target connection failed to {host}:{port} - {e}")
            resp_payload = bytes([REP_CONN_REFUSED]) + pack_socks_address("0.0.0.0", 0)
            await channel.session.send_frame(channel.stream_id, FRAME_OPEN_RESP, resp_payload)
            await channel.close()
            return

        resp_payload = bytes([REP_SUCCESS]) + pack_socks_address("0.0.0.0", 0)
        await channel.session.send_frame(channel.stream_id, FRAME_OPEN_RESP, resp_payload)

        async def channel_to_target():
            try:
                while True:
                    data = await channel.read()
                    if not data:
                        break
                    target_writer.write(data)
                    await target_writer.drain()
            except Exception:
                pass

        async def target_to_channel():
            try:
                while True:
                    data = await target_reader.read(16384)
                    if not data:
                        break
                    await channel.send(data)
            except Exception:
                pass

        t1 = asyncio.create_task(channel_to_target())
        t2 = asyncio.create_task(target_to_channel())
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        target_writer.close()
        await channel.close()

    async def _handle_udp_associate(self, channel: MuxChannel, host: str, port: int):
        loop = asyncio.get_running_loop()
        server_udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_udp_sock.bind(('0.0.0.0', 0))
        server_udp_sock.setblocking(False)

        resp_payload = bytes([REP_SUCCESS]) + pack_socks_address("0.0.0.0", 0)
        await channel.session.send_frame(channel.stream_id, FRAME_OPEN_RESP, resp_payload)

        async def channel_to_target_udp():
            try:
                while True:
                    frame = await channel.read()
                    if not frame:
                        break
                    rsv, frag, atyp, dst_host, dst_port, payload = parse_udp_packet(frame)
                    await loop.sock_sendto(server_udp_sock, payload, (dst_host, dst_port))
            except Exception:
                pass

        async def target_udp_to_channel():
            try:
                while True:
                    payload, target_addr = await loop.sock_recvfrom(server_udp_sock, 65536)
                    target_host, target_port = target_addr[0], target_addr[1]
                    resp_frame = pack_udp_packet(target_host, target_port, payload)
                    await channel.send(resp_frame)
            except Exception:
                pass

        t1 = asyncio.create_task(channel_to_target_udp())
        t2 = asyncio.create_task(target_udp_to_channel())

        await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

        for t in (t1, t2):
            t.cancel()

        server_udp_sock.close()
        await channel.close()