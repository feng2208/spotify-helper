# https://github.com/feng2208/spotify-helper

# mitmdump -s src/spotify-helper.py -p 8180 --set flow_detail=0


"""
Configuration via environment variables:
    WS_URL                  - WebSocket server URL (default: wss://feng2208.cloudns.cl/sp)
    WS_SERVERS_URL          - WebSocket server address url (default: https://feng2208.cloudns.cl/sp.json)
    LISTEN_HOST             - Local listen host (default: 127.0.0.1)
    LISTEN_PORT             - Local listen port (default: 18080)
    WS_FETCH_INTERVAL       - WS servers update interval in seconds (default: 28800, i.e. 8 hours)
    WS_FETCH_RETRY_INTERVAL - WS servers retry interval on failure in seconds (default: 600, i.e. 10 minutes)
"""


import asyncio
import collections
import json
import logging
import os
import threading

from mitmproxy import tls
from mitmproxy.http import HTTPFlow, Response
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

from ws_tunnel import TunnelClient, WSServerManager


WS_URL = os.environ.get("WS_URL", "wss://feng2208.cloudns.cl/sp")
WS_SERVERS_URL = os.environ.get("WS_SERVERS_URL", "https://feng2208.cloudns.cl/sp.json")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "18080"))
WS_FETCH_INTERVAL = int(os.environ.get("WS_FETCH_INTERVAL", 8 * 3600))
WS_FETCH_RETRY_INTERVAL = int(os.environ.get("WS_FETCH_RETRY_INTERVAL", 10 * 60))

SPOTIFY_AP = [
    'ap-gue1.spotify.com',
    'ap-guc3.spotify.com',
    'ap-gew1.spotify.com',
    'ap-gew4.spotify.com',
    'ap-gae2.spotify.com',
]
SPOTIFY_HOSTS = [
    'www.google.com',
    '*.gstatic.com',
    'accounts.spotify.com',
    'www.spotify.com',
    'login5.spotify.com',
    'spclient.wg.spotify.com',
    '*-spclient.spotify.com',
]


logger = logging.getLogger("ws_tunnel")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(handler)


def generate_pac_content(domains, proxy_server):
    """
    构造 PAC 文件的 JavaScript 内容。
    使用 shExpMatch 函数来处理通配符匹配。
    """
    # 将 Python 列表转换为 JSON 格式的字符串，以便在 JS 中作为数组使用
    domains_json = json.dumps(domains, indent=8)

    js_content = f"""
function FindProxyForURL(url, host) {{
    var rules = {domains_json};
    var proxy = "{proxy_server}";
    for (var i = 0; i < rules.length; i++) {{
        if (shExpMatch(host, rules[i])) {{
            return proxy;
        }}
    }}
    return "DIRECT";
}}
"""
    return js_content


class SpotifyHelper:

    def __init__(self):
        self.ws_servers_url = WS_SERVERS_URL
        self.ws_url = WS_URL
        self.fetch_interval = WS_FETCH_INTERVAL
        self.fetch_retry_interval = WS_FETCH_RETRY_INTERVAL
        self.server_manager = WSServerManager(self.ws_servers_url, self.ws_url)
        self.target_queue = collections.deque()
        self.listen_host = LISTEN_HOST
        self.listen_port = LISTEN_PORT

        self._tunnel: TunnelClient | None = None
        self._thread: threading.Thread | None = None

    def load(self, loader) -> None:
        loader.add_option(
            name="connection_strategy",
            typespec=str,
            default="lazy",
            help="set connection strategy to lazy",
        )
        loader.add_option(
            name="showhost",
            typespec=bool,
            default=True,
            help="Use the Host header to construct URLs for display",
        )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True

    def server_connect(self, data: ServerConnectionHookData) -> None:
        """Called before mitmproxy opens a connection to a server."""
        if not data.server.address:
            return
            
        original_host, original_port = data.server.address
        target_str = f"{original_host}:{original_port}"

        if self._should_reroute(original_host):
            self.target_queue.append(target_str)
            data.server.address = (self.listen_host, self.listen_port)
            logging.info(f"xxxxxxxx-spotify-xxxxxxxx: {original_host}")

    def requestheaders(self, flow: HTTPFlow) -> None:
        if flow.request.path == "/proxy.pac":
            proxy_server = f"PROXY {flow.request.host_header}"
            hosts = list(set(SPOTIFY_HOSTS + SPOTIFY_AP))
            pac_content = generate_pac_content(hosts, proxy_server)
            flow.response = Response.make(
                200,
                pac_content,
                {"Content-Type": "application/x-ns-proxy-autoconfig"}
            )
            logging.info(f"Served PAC to {flow.client_conn.peername}")

    def _should_reroute(self, host: str) -> bool:
        if host in SPOTIFY_AP:
            return True

        for h in SPOTIFY_HOSTS:
            if host == h or host.endswith(h[1:]):
                return True

        return False

    def running(self) -> None:
        """Called once mitmproxy is fully up — start the tunnel thread."""
        self._thread = threading.Thread(
            target=self._run_tunnel, daemon=True, name="ws-tunnel",
        )
        self._thread.start()

    def _run_tunnel(self) -> None:
        initial_ok = self.server_manager.fetch()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def get_target():
            if self.target_queue:
                return self.target_queue.popleft()
            logger.warning("target_queue is empty, no target available")
            return None

        self._tunnel = TunnelClient(
            config_provider=self.server_manager.get_url,
            target=get_target,
            listen_host=self.listen_host,
            listen_port=self.listen_port,
            on_failed=self.server_manager.mark_failed
        )

        fetch_task = loop.create_task(
            self.server_manager.run_periodic_fetch(
                interval=self.fetch_interval,
                retry_interval=self.fetch_retry_interval,
                initial_success=initial_ok,
            )
        )

        try:
            loop.run_until_complete(self._tunnel.start())
        except asyncio.CancelledError:
            logger.error("Tunnel event loop cancelled during shutdown")
        except Exception as exc:
            logger.error("Tunnel fatal error: %s", exc)
        finally:
            fetch_task.cancel()
            try:
                loop.run_until_complete(fetch_task)
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

            try:
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                logger.debug("Failed to shutdown async generators cleanly", exc_info=True)
            loop.close()

    def done(self) -> None:
        """Called when mitmproxy shuts down."""
        if self._tunnel:
            self._tunnel.shutdown()


addons = [SpotifyHelper()]
