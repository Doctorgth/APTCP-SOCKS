import asyncio
import logging
import ssl
from typing import Dict, Any

from aioptcp import PTCPServer
from server.socks_handler import TunnelHandler

logger = logging.getLogger("APTCPServer")


class APTCPSocksServer:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.host = config.get("aptcp_host", "0.0.0.0")
        self.port = int(config.get("aptcp_port", 1080))
        self.timeout = int(config.get("timeout", 30))

        self.tls_enabled = config.get("tls_enabled", False)
        self.tls_cert = config.get("tls_cert", "server/cert.pem")
        self.tls_key = config.get("tls_key", "server/key.pem")

        ssl_ctx = None
        if self.tls_enabled:
            ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_ctx.load_cert_chain(certfile=self.tls_cert, keyfile=self.tls_key)

        self.handler = TunnelHandler(config)
        self.ptcp_server = PTCPServer(self.host, self.port, timeout=self.timeout, ssl=ssl_ctx)

    async def start(self):
        await self.ptcp_server.start()
        logger.info(f"APTCP SOCKS Server listening on {self.host}:{self.port}")
        asyncio.create_task(self._accept_loop())

    async def _accept_loop(self):
        while True:
            try:
                conn = await self.ptcp_server.accept()
                asyncio.create_task(self.handler.handle_connection(conn))
            except Exception as e:
                logger.error(f"Error accepting APTCP connection: {e}")
                await asyncio.sleep(0.1)