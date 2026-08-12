import struct
import asyncio
import logging
from typing import Dict, Optional, Any, Callable, Awaitable, Tuple
from common.socks5 import pack_socks_address, read_socks_address

logger = logging.getLogger("Mux")

FRAME_OPEN = 0x01       # Client -> Server: Open stream payload=[cmd, atyp, host, port]
FRAME_OPEN_RESP = 0x02  # Server -> Client: Open response payload=[rep, atyp, bnd_host, bnd_port]
FRAME_DATA = 0x03       # Bi-directional: Stream payload
FRAME_CLOSE = 0x04      # Bi-directional: Close stream

class MuxChannel:
    """Represents a single virtual bidirectional stream inside a MuxSession."""
    def __init__(self, stream_id: int, session: 'MuxSession'):
        self.stream_id = stream_id
        self.session = session
        self.read_queue = asyncio.Queue()
        self.is_closed = False

    async def read(self) -> bytes:
        if self.is_closed and self.read_queue.empty():
            return b""
        data = await self.read_queue.get()
        return data

    async def send(self, data: bytes):
        if not self.is_closed:
            await self.session.send_frame(self.stream_id, FRAME_DATA, data)

    async def close(self):
        if not self.is_closed:
            self.is_closed = True
            await self.read_queue.put(b"")
            await self.session.send_frame(self.stream_id, FRAME_CLOSE, b"")
            self.session.remove_channel(self.stream_id)


class MuxSession:
    """Manages a multiplexed session over an underlying PTCPStream."""
    def __init__(self, stream: Any, is_server: bool = False, on_new_stream_cb: Optional[Callable[[MuxChannel, bytes], Awaitable[None]]] = None):
        self.stream = stream
        self.is_server = is_server
        self.on_new_stream_cb = on_new_stream_cb
        self.channels: Dict[int, MuxChannel] = {}
        self.next_stream_id = 1 if not is_server else 2
        self._write_lock = asyncio.Lock()
        self._open_futures: Dict[int, asyncio.Future] = {}
        self.is_closed = False
        self._read_loop_task = asyncio.create_task(self._read_loop())

    def create_channel(self) -> MuxChannel:
        stream_id = self.next_stream_id
        self.next_stream_id += 2
        channel = MuxChannel(stream_id, self)
        self.channels[stream_id] = channel
        return channel

    def remove_channel(self, stream_id: int):
        self.channels.pop(stream_id, None)
        fut = self._open_futures.pop(stream_id, None)
        if fut and not fut.done():
            fut.cancel()

    async def open_stream(self, cmd: int, target_host: str, target_port: int, timeout: float = 10.0) -> Tuple[MuxChannel, int, str, int]:
        channel = self.create_channel()
        payload = bytes([cmd]) + pack_socks_address(target_host, target_port)

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        self._open_futures[channel.stream_id] = fut

        await self.send_frame(channel.stream_id, FRAME_OPEN, payload)

        try:
            resp_payload = await asyncio.wait_for(fut, timeout=timeout)
        except Exception as e:
            channel.is_closed = True
            self.remove_channel(channel.stream_id)
            raise TimeoutError(f"Timeout waiting for Mux stream open response: {e}")

        rep = resp_payload[0]
        idx = 1
        async def mock_read(n):
            nonlocal idx
            res = resp_payload[idx:idx+n]
            idx += n
            return res

        _, bnd_host, bnd_port, _ = await read_socks_address(mock_read)
        return channel, rep, bnd_host, bnd_port

    async def send_frame(self, stream_id: int, frame_type: int, payload: bytes = b""):
        if self.is_closed:
            return
        # Нарезаем большие пачки данных на стабильные куски до 32КБ, чтобы не переполнять заголовок H (макс 65535)
        chunk_size = 32768
        if len(payload) > chunk_size:
            for i in range(0, len(payload), chunk_size):
                await self.send_frame(stream_id, frame_type, payload[i:i+chunk_size])
            return

        header = struct.pack("!IBH", stream_id, frame_type, len(payload))
        async with self._write_lock:
            try:
                await self.stream.send(header + payload)
            except Exception:
                self.is_closed = True

    async def _read_loop(self):
        try:
            while not self.is_closed:
                header = await self.stream.readexactly(7)
                stream_id, frame_type, payload_len = struct.unpack("!IBH", header)

                payload = b""
                if payload_len > 0:
                    payload = await self.stream.readexactly(payload_len)

                if frame_type == FRAME_DATA:
                    channel = self.channels.get(stream_id)
                    if channel:
                        await channel.read_queue.put(payload)

                elif frame_type == FRAME_CLOSE:
                    channel = self.channels.get(stream_id)
                    if channel:
                        channel.is_closed = True
                        await channel.read_queue.put(b"")
                        self.channels.pop(stream_id, None)

                elif frame_type == FRAME_OPEN_RESP:
                    fut = self._open_futures.get(stream_id)
                    if fut and not fut.done():
                        fut.set_result(payload)

                elif frame_type == FRAME_OPEN:
                    if self.is_server:
                        channel = MuxChannel(stream_id, self)
                        self.channels[stream_id] = channel
                        if self.on_new_stream_cb:
                            asyncio.create_task(self.on_new_stream_cb(channel, payload))

        except Exception as e:
            logger.error(f"MuxSession _read_loop error: {e}", exc_info=True)
        finally:
            self.is_closed = True
            for ch in list(self.channels.values()):
                ch.is_closed = True
                await ch.read_queue.put(b"")
            self.channels.clear()

    async def close(self):
        self.is_closed = True
        self._read_loop_task.cancel()
        try:
            await self.stream.close()
        except Exception:
            pass