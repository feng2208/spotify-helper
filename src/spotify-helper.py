# https://github.com/feng2208/spotify-helper

# mitmdump -s src/spotify-helper.py -p 8180 --set flow_detail=0
# deps:
#   blackboxprotobuf v1.4.0 https://github.com/nccgroup/blackboxprotobuf
#   six v1.16.0 https://github.com/benjaminp/six


"""
Configuration via environment variables:
    WS_URL       - WebSocket server URL (default: wss://feng2208.cloudns.cl/sp)
    WS_SERVERS_URL - WebSocket server address url (default: https://feng2208.cloudns.cl/cf.json)
    LISTEN_HOST  - Local listen host (default: 127.0.0.1)
    LISTEN_PORT  - Local listen port (default: 18080)
"""


from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls
from mitmproxy import ctx
from mitmproxy.proxy.server_hooks import ServerConnectionHookData
import json

import asyncio
import collections
import logging
import os
import threading

from ws_tunnel import TunnelClient, WSServerManager

import sys
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SRC_DIR + "/lib/")
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException


WS_URL = os.environ.get("WS_URL", "wss://feng2208.cloudns.cl/sp")
WS_SERVERS_URL = os.environ.get("WS_SERVERS_URL", "https://feng2208.cloudns.cl/sp.json")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "18080"))

SPOTS = {
    'player-license': 'premium',
    'player-license-v2': 'premium',
    'streaming-rules': '',
    'financial-product': 'pr:premium,tc:0',
    'name': 'Spotify Premium',
    'on-demand': 1,
    'ads': 0,
    'catalogue': 'premium',
    'high-bitrate': 1,
    'nft-disabled': '1',
    'offline': 1,
    'type': 'premium',
    'social-session': 1,
    'social-session-free-tier': 0,
    'is-eligible-premium-unboxing': 1,
}
SPOTS_DEL = []
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
    'spclient.wg.spotify.com',
    'login5.spotify.com',
]
SPOTIFY_ADS = [
    '/ads/',
    '/ad-logic/',
    '/desktop-update/',
    '/gabo-receiver-service/',
]
SPOTIFY_PREMIUM = [
    'spclient.wg.spotify.com',
    '*-spclient.spotify.com',
]
SPOTIFY_CUSTOMIZE = 'v1/customize'
SPOTIFY_BOOTSTRAP = 'v1/bootstrap'



logger = logging.getLogger("ws_tunnel")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    ))
    logger.addHandler(handler)




def is_new_version(new_version: str) -> bool:
    old_version = (9, 1, 14) # iOS 9.1.14
    return tuple(map(int, new_version.split('.')))[:3] > old_version

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


# spotify ptotobuf
def modify_spotify_body(data, attributes, bootstrap=False):
    try:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-xxxxxxxx")
        message, typedef = blackboxprotobuf.decode_message(data)
    except BlackboxProtobufException:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-Error-xxxxxxxx")
        return None

    if bootstrap:
        changed = change_attributes(message['2']['1']['1']['1']['3']['1'], attributes)
    else:
        changed = change_attributes(message['1']['3']['1'], attributes)

    if changed:
        try:
            logging.info(f"xxxxxxxx-spotify-protobuf-changed-xxxxxxxx")
            logging.info(f"xxxxxxxx-spotify-protobuf-encode-xxxxxxxx")
            return blackboxprotobuf.encode_message(message, typedef)
        except BlackboxProtobufException:
            logging.info(f"xxxxxxxx-spotify-protobuf-encode-Error-xxxxxxxx")
    else:
        logging.info(f"xxxxxxxx-spotify-protobuf-not-changed-xxxxxxxx")
        logging.info(f"xxxxxxxx-spotify-protobuf-need-to-update-code-xxxxxxxx")

    return None

def change_attributes(configs: list, attributes: dict) -> bool:
    changed = False
    if isinstance(configs, list):
        for config in configs:
            # config: {'1': 'attr_key', '2': {'value_key': 'value'}}
            # attributes: {'attr_key': 'value'}
            if not isinstance(config, dict):
                continue
            if '1' not in config or '2' not in config:
                continue
            if not isinstance(config['2'], dict):
                continue

            attr_key = config['1']
            value_key = list(config['2'].keys())[0]
            if attr_key in attributes:
                config['2'][value_key] = attributes[attr_key]
                changed = True
            elif attr_key in SPOTS_DEL:
                configs.remove(config)
                changed = True
    return changed




class SpotifyHelper:

    def __init__(self):
        self.ws_servers_url = WS_SERVERS_URL
        self.ws_url = WS_URL
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
        loader.add_option(
            name="sp_auth",
            typespec=bool,
            default=False,
            help="enable spotify mode",
        )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        if self._spclient(data.context.client.sni):
            data.ignore_connection = False

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
        flow.request.stream = True
        req_path = flow.request.path
        
        if self._spclient(flow.request.host_header):
            # spotify ads and trackers
            if self._is_ads(req_path):
                flow.request.stream = False
                flow.response = Response.make(200)

            # spotify protobuf
            elif self._sp_path(req_path):
                if 'if-none-match' in flow.request.headers:
                    del flow.request.headers['if-none-match']

        elif req_path == "/proxy.pac":
            proxy_server = f"PROXY {flow.request.host_header}"
            hosts = list(set(SPOTIFY_HOSTS + SPOTIFY_AP + SPOTIFY_PREMIUM))
            pac_content = generate_pac_content(hosts, proxy_server)
            flow.response = Response.make(
                200,
                pac_content,
                {"Content-Type": "application/x-ns-proxy-autoconfig"}
            )
            logging.info(f"Served PAC to {flow.client_conn.peername}")

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True
        if self._should_modify(flow):
            flow.response.stream = False

    def response(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        if self._should_modify(flow):
            if flow.response.status_code != 200:
                logging.info(f"xxxxxxxx-spotify-protobuf-status-code-not-200-xxxxxxxx")
                return
            if not isinstance(flow.response.content, bytes):
                logging.info(f"xxxxxxxx-spotify-protobuf-not-bytes-xxxxxxxx")
                return

            if SPOTIFY_BOOTSTRAP in req_path:
                logging.info(f"xxxxxxxx-spotify-protobuf-bootstrap-xxxxxxxx")
                data = modify_spotify_body(flow.response.content, SPOTS, bootstrap=True)
            else:
                logging.info(f"xxxxxxxx-spotify-protobuf-customize-xxxxxxxx")
                data = modify_spotify_body(flow.response.content, SPOTS)
            if data is not None:
                flow.response.content = data

    def _is_ads(self, path: str) -> bool:
        for p in SPOTIFY_ADS:
            if p in path:
                return True
        return False

    def _spclient(self, host: str) -> bool:
        if ctx.options.sp_auth:
            return False

        for h in SPOTIFY_PREMIUM:
            if host == h or host.endswith(h[1:]):
                return True
        return False

    def _sp_path(self, req_path: str) -> bool:
        return SPOTIFY_CUSTOMIZE in req_path or SPOTIFY_BOOTSTRAP in req_path

    def _should_modify(self, flow: HTTPFlow) -> bool:
        should_modify = False
        if self._spclient(flow.request.host_header) and self._sp_path(flow.request.path):
            should_modify = True
            if ('app-platform' in flow.request.headers 
                    and 'spotify-app-version' in flow.request.headers):
                sp_platform = flow.request.headers["app-platform"]
                sp_version = flow.request.headers["spotify-app-version"]
                logging.info(f"xxxxxxxx-spotify-version: {sp_platform}/{sp_version}")

                # do not modify if iOS new version
                if sp_platform == "iOS" and is_new_version(sp_version):
                    should_modify = False

        return should_modify

    def _should_reroute(self, host: str) -> bool:
        should_reroute = False

        # desktop version prevent automatic logout after 14 days
        if host in SPOTIFY_AP:
            should_reroute = True

        else:
            for h in SPOTIFY_HOSTS:
                if host == h or host.endswith(h[1:]):
                    should_reroute = True

        return should_reroute

    def running(self) -> None:
        """Called once mitmproxy is fully up — start the tunnel thread."""
        if ctx.options.sp_auth:
            logging.info(f"xxxxxxxx-spotify-xxxxxxxx: auth mode")
        self._thread = threading.Thread(
            target=self._run_tunnel, daemon=True, name="ws-tunnel",
        )
        self._thread.start()

    def _run_tunnel(self) -> None:
        self.server_manager.fetch()
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

        try:
            loop.run_until_complete(self._tunnel.start())
        except asyncio.CancelledError:
            logger.error("Tunnel event loop cancelled during shutdown")
        except Exception as exc:
            logger.error("Tunnel fatal error: %s", exc)
        finally:
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
