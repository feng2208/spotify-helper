"""
https://github.com/feng2208/spotify-helper

mitmdump -s src/spotify-helper-en.py -p 8180 --set flow_detail=0
deps:
  blackboxprotobuf v1.4.0 https://github.com/nccgroup/blackboxprotobuf
  six v1.16.0 https://github.com/benjaminp/six
"""


from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls

import logging
import os
import sys
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SRC_DIR + "/lib/")
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException


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
        if self._spclient(data.context.client.sni):
            data.ignore_connection = False

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
        return should_modify


addons = [SpotifyHelper()]
