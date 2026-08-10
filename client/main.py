import asyncio
import logging
import sys
import os

# Автоматическое определение корня проекта и добавление его в sys.path
# Это решает проблему ModuleNotFoundError при любых способах запуска
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import load_json_config
from client.socks_server import SOCKS5Server

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - Client: %(message)s')

async def main():
    # Вычисляем путь к конфигу по умолчанию относительно папки со скриптом
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.join(script_dir, "config.json")

    config_path = sys.argv[1] if len(sys.argv) > 1 else default_config
    if not os.path.exists(config_path):
        logging.error(f"Config file not found: {config_path}")
        return

    config = load_json_config(config_path)
    server = SOCKS5Server(config)
    await server.start()
    logging.info("SOCKS5 Client Proxy running. Press Ctrl+C to stop.")
    await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass