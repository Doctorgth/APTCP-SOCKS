import asyncio
import logging
import sys
import os

from common.config import load_json_config
from server.aptcp_server import APTCPSocksServer

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Server: %(message)s')

async def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "server/config.json"
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        return

    config = load_json_config(config_path)
    server = APTCPSocksServer(config)
    await server.start()
    logging.info("APTCP SOCKS Server running. Press Ctrl+C to stop.")
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass