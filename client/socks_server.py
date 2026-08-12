import asyncio
import socket
import logging
from typing import Dict, Any, Optional

from common.config import load_users_jsonl, validate_credentials
from common.socks5 import (
    SOCKS_VERSION, METHOD_NO_AUTH, METHOD_USER_PASS, METHOD_NO_ACCEPTABLE,
    CMD_CONNECT, CMD_UDP_ASSOCIATE,
    REP_SUCCESS, REP_GENERAL_FAILURE, REP_CMD_NOT_SUPPORTED,
    read_socks_address, pack_socks_address
)
from common.tunnel import (
    PTCPStream, send_tunnel_auth_request, read_tunnel_auth_response,
    send_tunnel_cmd_request, read_tunnel_cmd_response,
    send_udp_frame, read_udp_frame
)
from client.aptcp_client import APTCPTunnelClient

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

    async def start(self):
        self._server = await asyncio.start_server(
            self.handle_client, self.socks_host, self.socks_port
        )
        logger.info(f"Local SOCKS5 Server listening on {self.socks_host}:{self.socks_port}")

    async def serve_forever(self):
        if self._server:
            await self._server.serve_forever()

    async def close(self):
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

                # Perform RFC 1929 Auth Subnegotiation
                auth_ver = (await reader.readexactly(1))[0]
                u_len = (await reader.readexactly(1))[0]
                username = (await reader.readexactly(u_len)).decode('utf-8', errors='ignore')
                p_len = (await reader.readexactly(1))[0]
                password = (await reader.readexactly(p_len)).decode('utf-8', errors='ignore')

                if not validate_credentials(self.users, username, password):
                    logger.warning(f"SOCKS5 auth failed for user: {username}")
                    # Return Auth Failure status 0x01
                    writer.write(bytes([auth_ver, 0x01]))
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

                # Auth Success status 0x00
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

            # 3. Connect to APTCP Server using standard aioptcp.PTCPClient
            tunnel_client = APTCPTunnelClient(
                self.aptcp_host, 
                self.aptcp_port, 
                timeout=self.timeout,
                tls_enabled=self.aptcp_tls_enabled, 
                tls_ca_cert=self.aptcp_tls_ca_cert
            )
            try:
                ptcp_stream = await tunnel_client.connect_and_authenticate(
                    self.aptcp_auth_enabled, self.aptcp_username, self.aptcp_password
                )
            except Exception as e:
                logger.error(f"Failed to establish APTCP tunnel: {e}")
                rep_bytes = bytes([SOCKS_VERSION, REP_GENERAL_FAILURE, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # 4. Forward SOCKS Command over Tunnel
            await send_tunnel_cmd_request(ptcp_stream, cmd, target_host, target_port)
            rep, bnd_atyp, bnd_host, bnd_port = await read_tunnel_cmd_response(ptcp_stream)

            if rep != REP_SUCCESS:
                rep_bytes = bytes([SOCKS_VERSION, rep, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()
                await ptcp_stream.close()
                writer.close()
                await writer.wait_closed()
                return

            # 5. Handle Command Execution
            if cmd == CMD_CONNECT:
                # Reply Success to Proxifier
                rep_bytes = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00]) + pack_socks_address("0.0.0.0", 0)
                writer.write(rep_bytes)
                await writer.drain()

                # Relay TCP bi-directionally
                await self._relay_tcp(reader, writer, ptcp_stream)

            elif cmd == CMD_UDP_ASSOCIATE:
                # Create local UDP socket for Proxifier to send datagrams to
                udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                udp_sock.bind((self.socks_host, 0))
                udp_sock.setblocking(False)
                local_bnd_host, local_bnd_port = udp_sock.getsockname()

                # Reply Success to Proxifier with local bound UDP address and port
                rep_bytes = bytes([SOCKS_VERSION, REP_SUCCESS, 0x00]) + pack_socks_address(local_bnd_host, local_bnd_port)
                writer.write(rep_bytes)
                await writer.drain()

                # Relay UDP datagrams
                await self._relay_udp(reader, writer, udp_sock, ptcp_stream)

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

    async def _relay_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ptcp_stream: PTCPStream):
        """Relays raw TCP stream between Proxifier and APTCP stream."""
        async def client_to_ptcp():
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await ptcp_stream.send(data)
            except Exception:
                pass

        async def ptcp_to_client():
            try:
                while True:
                    data = await ptcp_stream.read(65536)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            except Exception:
                pass

        t1 = asyncio.create_task(client_to_ptcp())
        t2 = asyncio.create_task(ptcp_to_client())
        done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        await ptcp_stream.close()

    async def _relay_udp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, udp_sock: socket.socket, ptcp_stream: PTCPStream):
        """Relays UDP datagrams between Proxifier local UDP socket and APTCP stream."""
        loop = asyncio.get_running_loop()
        proxifier_udp_addr = None
        addr_event = asyncio.Event()

        async def udp_to_ptcp():
            nonlocal proxifier_udp_addr
            try:
                while True:
                    data, addr = await loop.sock_recvfrom(udp_sock, 65536)
                    if not proxifier_udp_addr:
                        proxifier_udp_addr = addr
                        addr_event.set()
                    await send_udp_frame(ptcp_stream, data)
            except Exception:
                pass

        async def ptcp_to_udp():
            try:
                await addr_event.wait()
                while True:
                    frame = await read_udp_frame(ptcp_stream)
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

        t_udp_in = asyncio.create_task(udp_to_ptcp())
        t_udp_out = asyncio.create_task(ptcp_to_udp())
        t_tcp_ctrl = asyncio.create_task(monitor_tcp_control())

        await asyncio.wait([t_udp_in, t_udp_out, t_tcp_ctrl], return_when=asyncio.FIRST_COMPLETED)

        for t in (t_udp_in, t_udp_out, t_tcp_ctrl):
            t.cancel()

        udp_sock.close()
        await ptcp_stream.close()