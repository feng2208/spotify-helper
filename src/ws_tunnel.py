"""
commit: 7f879c94

WebSocket Tunnel: Pure-Python WebSocket client + 1:1 tunnel.

Each incoming local TCP connection creates a new WebSocket connection 
to the remote server and streams data bidirectionally.
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import random
import re
import ssl
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger("ws_tunnel")

# ---------------------------------------------------------------------------
# WebSocket constants (RFC 6455)
# ---------------------------------------------------------------------------
OP_CONTINUATION = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA


@dataclass
class WSConnectionConfig:
    url: str
    tcp_host: Optional[str] = None
    tcp_port: Optional[int] = None
    server_id: Optional[str] = None

# ===================================================================
# Pure-Python async WebSocket client (RFC 6455)
# ===================================================================
class WebSocketClient:
    """
    Minimal async WebSocket client implemented from scratch.
    Only binary & control frames are handled — no extensions,
    no per-message compression.
    """

    def __init__(self, config: WSConnectionConfig, target: Optional[str] = None, connect_timeout: float = 5.0):
        self.config = config
        
        parsed = urlparse(config.url)
        self.scheme = parsed.scheme or "ws"
        raw_host = parsed.hostname or "127.0.0.1"
        self.sni = raw_host
        self.req_host = raw_host
        if "_" in raw_host:
            self.sni, self.req_host = raw_host.split("_", 1)
        self.port = parsed.port
        if self.port is None:
            self.port = 443 if self.scheme.lower() == "wss" else 80
            
        self.tcp_host = config.tcp_host or self.req_host
        self.tcp_port = config.tcp_port or self.port

        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query
        self.target = target

        self.connect_timeout = connect_timeout
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.connected = False
        self._write_lock = asyncio.Lock()

    # ----- connection / handshake ------------------------------------------

    async def connect(self):
        """Open TCP connection and perform the WebSocket opening handshake."""
        try:
            kwargs = {}
            if self.scheme.lower() == "wss":
                ssl_context = ssl.create_default_context()
                if self.sni != self.req_host:
                    ssl_context.check_hostname = False
                kwargs["ssl"] = ssl_context
                kwargs["server_hostname"] = self.sni
            
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(self.tcp_host, self.tcp_port, **kwargs),
                timeout=self.connect_timeout,
            )

            if self.scheme.lower() == "wss" and self.sni != self.req_host:
                cert = self._writer.get_extra_info('ssl_object').getpeercert()
                if not cert:
                    raise ssl.CertificateError("empty or no certificate")
                
                def match_dns(val):
                    pattern = r'\A' + re.escape(val).replace(r'\*', '[^.]+') + r'\Z'
                    return re.match(pattern, self.req_host, re.IGNORECASE)

                if not any(k == 'DNS' and match_dns(v) for k, v in cert.get('subjectAltName', ())):
                    raise ssl.CertificateError(f"hostname {self.req_host!r} doesn't match certificate")
                    
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Connection timed out "
                f"after {self.connect_timeout}s"
            )

        # Random 16-byte nonce, base64-encoded
        key = base64.b64encode(os.urandom(16)).decode("ascii")

        request = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.req_host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
        )
        if self.target:
            request += f"X-Target: {self.target}\r\n"
        request += "\r\n"
        self._writer.write(request.encode("ascii"))
        await self._writer.drain()

        # Read the full HTTP response header
        try:
            response = await self._reader.readuntil(b"\r\n\r\n")
        except asyncio.IncompleteReadError:
            raise ConnectionError("Connection closed during handshake")
        except asyncio.LimitOverrunError:
            raise ConnectionError("Handshake response too large")

        resp_text = response.decode("ascii", errors="replace")
        status_line = resp_text.split("\r\n", 1)[0]
        if "101" not in status_line:
            raise ConnectionError(f"WebSocket handshake failed: {status_line}")

        # Verify Sec-WebSocket-Accept
        magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        expected = base64.b64encode(
            hashlib.sha1((key + magic).encode("ascii")).digest()
        ).decode("ascii")

        accept_ok = False
        for line in resp_text.split("\r\n"):
            if line.lower().startswith("sec-websocket-accept:"):
                actual = line.split(":", 1)[1].strip()
                if actual != expected:
                    raise ConnectionError(f"Invalid Sec-WebSocket-Accept header: actual='{actual}', expected='{expected}'")
                accept_ok = True
                break
        if not accept_ok:
            raise ConnectionError("Missing Sec-WebSocket-Accept header")

        self.connected = True

    # ----- frame I/O -------------------------------------------------------

    async def _read_exact(self, n: int) -> bytes | None:
        """Read exactly *n* bytes, or return ``None`` on EOF."""
        try:
            return await self._reader.readexactly(n)
        except asyncio.IncompleteReadError:
            return None

    async def recv_frame(self) -> tuple[int | None, bytes | None]:
        """Read one WebSocket frame.  Returns ``(opcode, payload)``."""
        header = await self._read_exact(2)
        if header is None:
            return None, None

        # fin  = (header[0] >> 7) & 1  # not used currently
        opcode = header[0] & 0x0F
        masked = (header[1] >> 7) & 1
        length = header[1] & 0x7F

        if length == 126:
            raw = await self._read_exact(2)
            if raw is None:
                return None, None
            length = int.from_bytes(raw, "big")
        elif length == 127:
            raw = await self._read_exact(8)
            if raw is None:
                return None, None
            length = int.from_bytes(raw, "big")

        mask_key = None
        if masked:
            mask_key = await self._read_exact(4)
            if mask_key is None:
                return None, None

        payload = await self._read_exact(length) if length else b""
        if payload is None:
            return None, None

        if masked and mask_key:
            payload = self._apply_mask(mask_key, payload)

        return opcode, payload

    async def send_frame(self, opcode: int, payload: bytes):
        """Send one WebSocket frame.  Client frames are always masked."""
        if not self.connected:
            raise ConnectionError("ws_tunnel not connected")

        async with self._write_lock:
            frame = bytearray()

            # FIN=1 | opcode
            frame.append(0x80 | opcode)

            # MASK=1 | payload length
            length = len(payload)
            if length < 126:
                frame.append(0x80 | length)
            elif length < 0x10000:
                frame.append(0x80 | 126)
                frame.extend(length.to_bytes(2, "big"))
            else:
                frame.append(0x80 | 127)
                frame.extend(length.to_bytes(8, "big"))

            # 4-byte random mask
            mask_key = os.urandom(4)
            frame.extend(mask_key)

            # Masked payload
            frame.extend(self._apply_mask(mask_key, payload))

            self._writer.write(bytes(frame))
            await self._writer.drain()

    async def send_binary(self, data: bytes):
        await self.send_frame(OP_BINARY, data)

    async def send_close(self, code: int = 1000, reason: str = ""):
        payload = code.to_bytes(2, "big") + reason.encode("utf-8")
        await self.send_frame(OP_CLOSE, payload)

    async def send_pong(self, data: bytes):
        await self.send_frame(OP_PONG, data)

    # ----- helpers ----------------------------------------------------------

    @staticmethod
    def _apply_mask(mask_key: bytes, data: bytes) -> bytes:
        """XOR *data* with the 4-byte *mask_key* (RFC 6455 §5.3)."""
        if not data:
            return data
        
        # in-place mask application with bytearray
        data_arr = bytearray(data)
        mask_arr = bytearray(mask_key)
        for i in range(len(data_arr)):
            data_arr[i] ^= mask_arr[i & 3]
        return bytes(data_arr)

    async def close(self):
        """Gracefully close the WebSocket connection."""
        if self.connected:
            try:
                await self.send_close()
            except Exception:
                pass
            self.connected = False
        if self._writer:
            try:
                self._writer.close()
            except Exception:
                pass
            self._writer = None


# ===================================================================
# 1:1 Tunnel running over multiple WebSocket connections
# ===================================================================
class WSServerManager:
    def __init__(self, config_url: Optional[str], base_ws_url: str):
        self.config_url = config_url
        self.base_ws_url = base_ws_url
        self.addresses: list[str] = []
        self.failed: set[str] = set()

    def fetch(self) -> None:
        if not self.config_url:
            return
        try:
            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:149.0) Gecko/20100101 Firefox/149.0"
            }
            req = urllib.request.Request(self.config_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read()
                self.addresses = json.loads(data)
                
            if not isinstance(self.addresses, list):
                logger.warning("WS servers JSON payload is not a list. Ignoring.")
                self.addresses = []
                return
                
        except Exception as e:
            logger.error("Failed to fetch WS servers: %s", e)

    def get_url(self) -> WSConnectionConfig:
        if not self.addresses:
            return WSConnectionConfig(url=self.base_ws_url)
                
        available_addresses = [
            addr for addr in self.addresses 
            if addr not in self.failed
        ]

        if available_addresses:
            addr = random.choice(available_addresses)
            parts = addr.rsplit(":", 1)
            ip = parts[0]
            if len(parts) > 1 and parts[1].isdigit():
                port = int(parts[1])
            else:
                parsed = urllib.parse.urlparse(self.base_ws_url)
                port = 443 if parsed.scheme.lower() == 'wss' else 80
                
            return WSConnectionConfig(
                url=self.base_ws_url,
                tcp_host=ip,
                tcp_port=port,
                server_id=addr
            )

        logger.warning("All WS servers failed, falling back to base WS_URL: %s", self.base_ws_url)
        return WSConnectionConfig(url=self.base_ws_url)

    def mark_failed(self, server_id: str) -> None:
        if server_id and server_id not in self.failed:
            self.failed.add(server_id)
            logger.warning("Marked WS server %s as failed", server_id)


class TunnelClient:
    """
    Accepts local TCP connections and forwards their traffic by opening a
    new WebSocket connection to the server for each local TCP connection.
    """

    def __init__(self, config_provider: Callable[[], WSConnectionConfig] | WSConnectionConfig, 
                 target: str | Callable,
                 listen_host: str, listen_port: int, 
                 on_failed: Optional[Callable[[str], None]] = None):
        self.config_provider = config_provider
        self.target = target
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.on_failed = on_failed

        self._running = True
        self._stopping = False
        self._server: Optional[asyncio.Server] = None
        self._active_connections: set[WebSocketClient] = set()

    # ----- TCP listener / per-connection handler ---------------------------

    async def _handle_client(self, reader: asyncio.StreamReader,
                             writer: asyncio.StreamWriter):
        client_addr = writer.get_extra_info('peername')
        
        target_value = self.target() if callable(self.target) else self.target

        if callable(self.config_provider):
            config = self.config_provider()
        else:
            config = self.config_provider

        ws = WebSocketClient(config, target=target_value)
        self._active_connections.add(ws)

        try:
            await ws.connect()
        except Exception as exc:
            logger.error("Failed to connect WS to %s:%s (URL %s) for %s: %s", 
                         config.tcp_host, config.tcp_port, config.url, client_addr, exc)
            if self.on_failed and config.server_id:
                self.on_failed(config.server_id)
            writer.close()
            self._active_connections.discard(ws)
            return

        async def tcp_to_ws():
            try:
                while self._running:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await ws.send_binary(data)
            except Exception as e:
                logger.debug("tcp_to_ws error: %s", e)
            finally:
                # Signal the other side by closing WS
                await ws.close()

        async def ws_to_tcp():
            try:
                while self._running and ws.connected:
                    opcode, payload = await ws.recv_frame()
                    if opcode is None:
                        break
                    
                    if opcode == OP_PING:
                        await ws.send_pong(payload)
                    elif opcode == OP_PONG:
                        continue
                    elif opcode == OP_CLOSE:
                        break
                    elif opcode == OP_BINARY:
                        writer.write(payload)
                        await writer.drain()
            except Exception as e:
                logger.debug("ws_to_tcp error: %s", e)
            finally:
                writer.close()

        # Run both directions concurrently
        await asyncio.gather(tcp_to_ws(), ws_to_tcp(), return_exceptions=True)

        # Cleanup
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        await ws.close()
        self._active_connections.discard(ws)

    # ----- lifecycle -------------------------------------------------------

    def shutdown(self) -> None:
        """Thread-safe way to trigger a shutdown of the tunnel client."""
        if self._stopping:
            return
        self._stopping = True
        if self._server and self._server.get_loop().is_running():
            self._server.get_loop().call_soon_threadsafe(
                lambda: asyncio.create_task(self.stop())
            )
        else:
            self._running = False

    async def start(self):
        self._server = await asyncio.start_server(
            self._handle_client, self.listen_host, self.listen_port,
        )
        async with self._server:
            try:
                await self._server.serve_forever()
            except asyncio.CancelledError:
                # Normal path when the server is closed during shutdown.
                if not self._stopping:
                    raise

    async def stop(self):
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            
        for ws in list(self._active_connections):
            await ws.close()
        self._active_connections.clear()
