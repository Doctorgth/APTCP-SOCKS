import asyncio
import socket
import logging
from typing import Dict, Any, Optional

from common.config import load_users_jsonl, validate_credentials
from common.socks5 import (
    SOCKS_VERSION, METHOD_NO_AUTH, METHOD_USER_PASS, METHOD_NO_ACCEPTABLE,
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_SUCCESS, REP_GENERAL_FAILURE, REP_CMD_NOT_SUPPORTED,
    read_socks_address, pack_socks_address,
    parse_udp_packet, pack_udp_packet
)
from client.aptcp_client import APTCPTunnelClient
from common.mux import MuxSession, MuxChannel

logger = logging.getLogger("SOCKS5Client")


class SOCKS5Server:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.socks_host = config.get("socks_host", "127.0.0.1")
        self.socks_port = int(config.get("socks_port", 1080))
        self.auth_enabled = config.get("auth_enabled", False)
        self.users_file = config.get("users_file", "client/users.jsonl")
        self.users = load_users_jsonl(self.users_file) if self.auth_enabled else {}

        self.aptcp_host = config.get("aptcp_server_host", "127.0.0.1")
        self.aptcp_port = int(config.get("aptcp_server_port", 9090))
        self.aptcp_auth_enabled = config.get("aptcp_auth_enabled", False)
        self.aptcp_username = config.get("aptcp_username", "")
        self.aptcp_password = config.get("aptcp_password", "")
        self.aptcp_tls_enabled = config.get("aptcp_tls_enabled", False)
        self.aptcp_tls_ca_cert = config.get("aptcp_tls_ca_cert", None)
        self.timeout = int(config.get("timeout", 30))

        self._server = None
        self._mux_session: Optional[MuxSession] = None
        self._mux_lock = asyncio.Lock()

    async def get_mux_session(self) -> MuxSession:
        async with self._mux_lock:
            if self._mux_session and not self._mux_session.is_closed:
                return self._mux_session

            tunnel_client = APTCPTunnelClient(
                self.aptcp_host,
                self.aptcp_port,
                timeout=self.timeout,
                tls_enabled=self.aptcp_tls_enabled,
                tls_ca_cert=self.aptcp_tls_ca_cert
            )
            ptcp_stream = await tunnel_client.connect_and_authenticate(
                self.aptcp_auth_enabled, self.aptcp_username, self.aptcp_password
            )
            self._mux_session = MuxSession(ptcp_stream, is_server=False)
            return self._mux_session

    async def start(self):
        self._server = await asyncio.start_server(
            self.handle_client, self.socks_host, self.socks_port
        )
        logger.info(f"Local SOCKS5 Server listening on {self.socks_host}:{self.socks_port}")

    async def serve_forever(self):
        if self._server:
            await self._server.serve_forever()

    async def close(self):
        if self._mux_session:
            await self._mux_session.close()
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        sock = writer.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

        try:
            # 1. Greeting & Method Negotiation
            header = await reader.readexactly(2)
            ver, nmethods = header[0], header[1]
            if ver != SOCKS_VERSION:
                writer.close()
                await writer.wait_closed()
                return

            methods = await reader.readexactly(nmethods)

            if self.auth_enabled:
                if METHOD_USER_PASS not in methods:
                    writer.write(bytes([SOCKS_VERSION, METHOD_NO_ACCEPTABLE]))
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                writer.write(bytes([SOCKS_VERSION, METHOD_USER_PASS]))
                await writer.drain()

                auth_ver = (await reader.readexactly(1))[0]
                u_len = (await reader.readexactly(1))[0]
                username = (await reader.readexactly(u_len)).decode('utf-8', errors='ignore')
                p_len = (await reader.readexactly(1))[0]
                password = (await reader.readexactly(p_len)).decode('utf-8', errors='ignore')

                if not validate_credentials(self.users, username, password):
                    logger.warning(f"SOCKS5 auth failed for user: {username}")
                    writer.write(bytes([auth_ver, 0x01]))
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                writer.write(bytes([auth_ver, 0x00]))
                await writer.drain()
            else:
                if METHOD_NO_AUTH not in methods:
                    writer.write(bytes([SOCKS_VERSION, METHOD_NO_ACCEPTABLE]))
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                writer.write(bytes([SOCKS_VERSION, METHOD_NO_AUTH]))
                await writer.drain()

            # 2. Command Request
            req_header = await reader.readexactly(2)
            _, cmd = req_header[0], req_header[1]
            _ = await reader.readexactly(1) # RSV
            atyp, target_host, target_port, _ = await read_socks_address(reader.readexactly)

            if cmd not in (CMD_CONNECT, CMD_UDP_ASSOCIATE):
                rep_bytes = bytes([SOCKS_VERSION, REP_CMD_NOT_SUPPORTED, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # 3. Open Virtual Channel over Multiplexed PTCP Session
            try:
                mux_session = await self.get_mux_session()
                channel, rep, bnd_host, bnd_port = await mux_session.open_stream(cmd, target_host, target_port)
            except Exception as e:
                logger.error(f"Failed to open Mux stream: {e}")
                rep_bytes = bytes([SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if rep != REP_SUCCESS:
                rep_bytes = bytes([SOCKS_VERSION, rep, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()
                await channel.close()
                writer.close()
                await writer.wait_closed()
                return

            # 5. Handle Command Execution
            if cmd == CMD_CONNECT:
                rep_bytes = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()

                await self._relay_tcp(reader, writer, channel)

            elif cmd == CMD_UDP_ASSOCIATE:
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.bind((self.socks_host, 0))
                udp_sock.setblocking(False)
                local_bnd_host, local_bnd_port = udp_sock.getsockname()

                rep_bytes = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00]) + pack_socks_address(local_bnd_host, local_bnd_port)
                writer.write(rep_bytes)
                await writer.drain()

                await self._relay_udp(reader, writer, udp_sock, channel)

        except (asyncio.IncompleteReadError, ConnectionResetError):
            pass
        except Exception as e:
            logger.error(f"Error handling SOCKS client: {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _relay_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, channel: MuxChannel):
        """Relays raw TCP stream between Proxifier and Mux channel."""
        async def client_to_channel():
            try:
                while True:
                    data = await reader.read(16384)
                    if not data:
                        break
                    await channel.send(data)
            except Exception:
                pass

        async def channel_to_client():
            try:
                while True:
                    data = await channel.read()
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass

        t1 = asyncio.create_task(client_to_channel())
        t2 = asyncio.create_task(channel_to_client())
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await channel.close()

    async def _relay_udp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, udp_sock: socket.socket, channel: MuxChannel):
        """Relays UDP datagrams between Proxifier local UDP socket and Mux channel."""
        loop = asyncio.get_running_loop()
        proxifier_udp_addr = None
        addr_event = asyncio.Event()

        async def udp_to_channel():
            nonlocal proxifier_udp_addr
            try:
                while True:
                    data, addr = await loop.sock_recvfrom(udp_sock, 65536)
                    if not proxifier_udp_addr:
                        proxifier_udp_addr = addr
                        addr_event.set()
                    await channel.send(data)
            except Exception:
                pass

        async def channel_to_udp():
            try:
                await addr_event.wait()
                while True:
                    frame = await channel.read()
                    if not frame:
                        break
                    if proxifier_udp_addr:
                        await loop.sock_sendto(udp_sock, frame, proxifier_udp_addr)
            except Exception:
                pass

        async def monitor_tcp_control():
            try:
                while True:
                    data = await reader.read(1)
                    if not data:
                        break
            except Exception:
                pass

        t_udp_in = asyncio.create_task(udp_to_channel())
        t_udp_out = asyncio.create_task(channel_to_udp())
        t_tcp_ctrl = asyncio.create_task(monitor_tcp_control())

        await asyncio.wait([t_udp_in, t_udp_out, t_tcp_ctrl], return_when=asyncio.FIRST_COMPLETED)

        for t in (t_udp_in, t_udp_out, t_tcp_ctrl):
            t.cancel()

        udp_sock.close()
        await channel.close()