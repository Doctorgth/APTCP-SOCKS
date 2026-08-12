import asyncio
import ssl
from aioptcp import PTCPClient
from common.tunnel import PTCPStream, send_tunnel_auth_request, read_tunnel_auth_response, TUNNEL_AUTH_USER_PASS, TUNNEL_AUTH_NONE, TUNNEL_AUTH_SUCCESS

class APTCPTunnelClient:
    """
    Manages establishing an APTCP connection to the APTCP Server
    and performing authentication over the tunnel stream.
    """
    def __init__(self, host: str, port: int, timeout: int = 30, tls_enabled: bool = False, tls_ca_cert: str = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tls_enabled = tls_enabled
        self.tls_ca_cert = tls_ca_cert

    async def connect_stream(self) -> PTCPStream:
        ssl_ctx = None
        if self.tls_enabled:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            if self.tls_ca_cert:
                ssl_ctx.load_verify_locations(cafile=self.tls_ca_cert)
                # Отключаем проверку hostname, так как мы подключаемся по IP-адресу, 
                # но оставляем проверку валидности самого файла сертификата
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_REQUIRED
            else:
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE

        client = PTCPClient(self.host, self.port, timeout=self.timeout, ssl=ssl_ctx)
        await client.connect()
        return PTCPStream(client)

    async def connect_and_authenticate(self, auth_enabled: bool, username: str = "", password: str = "") -> PTCPStream:
        stream = await self.connect_stream()
        if auth_enabled:
            await send_tunnel_auth_request(stream, username, password, auth_type=TUNNEL_AUTH_USER_PASS)
        else:
            await send_tunnel_auth_request(stream, auth_type=TUNNEL_AUTH_NONE)

        status = await read_tunnel_auth_response(stream)
        if status != TUNNEL_AUTH_SUCCESS:
            await stream.close()
            raise PermissionError("APTCP Server authentication failed (Invalid credentials)")

        return stream