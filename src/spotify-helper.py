# https://github.com/feng2208/spotify-helper

# mitmdump -s src/spotify-helper.py -p 8180 
# deps:
#   blackboxprotobuf v1.4.0 https://github.com/nccgroup/blackboxprotobuf
#   six v1.16.0 https://github.com/benjaminp/six


import logging
from dataclasses import dataclass

from mitmproxy.addonmanager import Loader
from mitmproxy.http import HTTPFlow
from mitmproxy.http import Response
from mitmproxy import tls
from mitmproxy.addons.tlsconfig import TlsConfig
from mitmproxy.proxy.server_hooks import ServerConnectionHookData

import hashlib
import struct

import os
import sys
SRC_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SRC_DIR + "/lib/")
import blackboxprotobuf
from blackboxprotobuf.lib.exceptions import BlackboxProtobufException

from pathlib import Path
from ruamel.yaml import YAML
import re

CONFIG_FILE = SRC_DIR + "/config.yaml"

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
    'can_use_superbird': 1,
    'type': 'premium',
    'social-session': 1,
    'social-session-free-tier': 0,
    'is-eligible-premium-unboxing': 1,
}

SPOTS_DEL = []

TLS_CLIENTS = {}

# spotify ptotobuf
def modify_spotify_body(data, bootstrap=False):
    try:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-xxxxxxxx")
        message, typedef = blackboxprotobuf.decode_message(data)
    except BlackboxProtobufException:
        logging.info(f"xxxxxxxx-spotify-protobuf-decode-Error-xxxxxxxx")
        return None

    if bootstrap:
        configs = message['2']['1']['1']['1']['3']['1']
    else:
        configs = message['1']['3']['1']

    changed = False
    if isinstance(configs, list):
        for config in configs:
            # config: {'1': 'attr_key', '2': {'value_key': 'value'}}
            # SPOTS: {'attr_key': 'value'}
            if not isinstance(config, dict):
                continue
            if '1' not in config or '2' not in config:
                continue
            if not isinstance(config['2'], dict):
                continue

            attr_key = config['1']
            value_key = list(config['2'].keys())[0]
            if attr_key in SPOTS:
                config['2'][value_key] = SPOTS[attr_key]
                changed = True
            elif attr_key in SPOTS_DEL:
                configs.remove(config)
                changed = True

        if bootstrap:
            message['2']['1']['1']['1']['3']['1'] = configs
        else:
            message['1']['3']['1'] = configs

        if changed:
            logging.info(f"xxxxxxxx-spotify-protobuf-changed-xxxxxxxx")
            try:
                logging.info(f"xxxxxxxx-spotify-protobuf-encode-xxxxxxxx")
                data = blackboxprotobuf.encode_message(message, typedef)
                return data
            except BlackboxProtobufException:
                logging.info(f"xxxxxxxx-spotify-protobuf-encode-Error-xxxxxxxx")

    if not changed:
        logging.info(f"xxxxxxxx-spotify-protobuf-not-changed-xxxxxxxx")
        logging.info(f"xxxxxxxx-spotify-protobuf-need-to-update-code-xxxxxxxx")

    return None

@dataclass
class Mapping:
    sni: str
    address: tuple

class SpotifyHelper(TlsConfig):
    # configurations for regular ("example.com") mappings:
    host_mappings: dict[str, Mapping]

    # Configurations for star ("*.example.com") mappings:
    star_mappings: dict[str, Mapping]

    tcp_hosts: list[str]

    hosts_loaded: bool
    yaml_config: dict

    def __init__(self) -> None:
        self.host_mappings = {}
        self.star_mappings = {}
        self.tcp_hosts = []
        self.hosts_loaded = False
        self.yaml_config = {}

    def load(self, loader: Loader) -> None:
        if not self.hosts_loaded:
            yaml = YAML(typ='safe')
            self.yaml_config = yaml.load(Path(CONFIG_FILE))
            self._load_hosts()
            self.hosts_loaded = True

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
            name="tcp_hosts",
            typespec=list,
            default=self.tcp_hosts,
            help="Generic TCP SSL proxy mode for all hosts that match the pattern",
        )

    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        data.ignore_connection = True
        host = data.context.client.sni

        if data.context.server.address is None and host is not None:
            data.context.server.address = (host, 443)

        if self._spclient(host):
            data.ignore_connection = False

        mapping = self._get_sni(host)
        if mapping is not None:
            logging.info(f"xxxxxxxx-tls-server-host: {host}")
            if mapping.sni is not None:
                data.ignore_connection = False
                data.context.client.server_sni = mapping.sni
                logging.info(f"xxxxxxxx-tls-server-sni: {mapping.sni}")
            if mapping.address is not None:
                data.context.client.server_address = mapping.address
                logging.info(f"xxxxxxxx-tls-server-address: {mapping.address}")

        if not data.ignore_connection:
            ja3 = self._get_ja3(data)
            if ja3 is not None:
                data.context.client.ja3 = ja3
                if ja3 in TLS_CLIENTS and TLS_CLIENTS.get(ja3) > 2:
                    data.ignore_connection = True

    def tls_failed_client(self, data: tls.TlsData) -> None:
        if hasattr(data.conn, "ja3"):
            logging.info(f"xxxxxxxx-tls-client-failed-ja3: {data.conn.ja3}")
            logging.info(f"xxxxxxxx-tls-client-failed-sni: {data.conn.sni}")
            if data.conn.ja3 in TLS_CLIENTS:
                TLS_CLIENTS[data.conn.ja3] += 1
            else:
                TLS_CLIENTS[data.conn.ja3] = 1

    def server_connect(self, data: ServerConnectionHookData) -> None:
        _host = data.server.address[0]
        if _host in self.yaml_config['spotify_ap']:
            host = self.yaml_config['spotify_ap_address'].split(':')[0]
            port = int(self.yaml_config['spotify_ap_address'].split(':')[1])
            data.server.address = (host, port)
            logging.info(f"xxxxxxxx-spotify-ap: {_host} {data.server.address}")

        else:
            if hasattr(data.client, "server_address"):
                data.server.address = data.client.server_address
            if hasattr(data.client, "server_sni"):
                data.server.sni = data.client.server_sni

    def server_connect_error(self, data: ServerConnectionHookData) -> None:
        logging.info(f"connect error: {data.server.address[0]}:{data.server.address[1]}")

    def requestheaders(self, flow: HTTPFlow) -> None:
        flow.request.stream = True
        req_path = flow.request.path
        if self._spclient(flow.request.host_header):
            # spotify ads and trackers
            if (req_path.startswith("/ads/")
                    or req_path.startswith("/ad-logic/")
                    or req_path.startswith("/desktop-update/")
                    or req_path.startswith("/gabo-receiver-service/")):
                flow.request.stream = False
                flow.response = Response.make(503)
            elif (req_path.startswith("/artistview/v1/artist")):
                flow.request.path = flow.request.path.replace('platform=iphone', 'platform=ipad')
            # spotify protobuf
            elif self._sp_path(req_path):
                if 'if-none-match' in flow.request.headers:
                    del flow.request.headers['if-none-match']

    def responseheaders(self, flow: HTTPFlow) -> None:
        flow.response.stream = True
        if self._spclient(flow.request.host_header) and self._sp_path(flow.request.path):
            flow.response.stream = False

    def response(self, flow: HTTPFlow) -> None:
        req_path = flow.request.path
        if self._spclient(flow.request.host_header) and self._sp_path(req_path):
            if flow.response.status_code != 200:
                logging.info(f"xxxxxxxx-spotify-protobuf-status-code-not-200-xxxxxxxx")
                return
            if not isinstance(flow.response.content, bytes):
                logging.info(f"xxxxxxxx-spotify-protobuf-not-bytes-xxxxxxxx")
                return
            if "v1/bootstrap" in req_path:
                logging.info(f"xxxxxxxx-spotify-protobuf-bootstrap-xxxxxxxx")
                data = modify_spotify_body(flow.response.content, bootstrap=True)
            else:
                logging.info(f"xxxxxxxx-spotify-protobuf-customize-xxxxxxxx")
                data = modify_spotify_body(flow.response.content)
            if data is not None:
                flow.response.content = data
                    
    def _spclient(self, host: str) -> bool:
        if (host == "spclient.wg.spotify.com"
                or "spclient.spotify.com" in host):
            return True
        return False

    def _sp_path(self, req_path: str) -> bool:
        paths = [
                 'v1/customize',
                 'v1/bootstrap',
                ]
        for path in paths:
            if path in req_path:
                return True
        return False
        
    def _load_hosts(self) -> None:
        host_mappings: dict[str, Mapping] = {}
        star_mappings: dict[str, Mapping] = {}
        tcp_hosts: list[str] = []

        for mapping in self.yaml_config["mappings"]:
            address = mapping.get("address")
            sni = mapping.get("sni")
            if address is not None:
                address = (address.split(':')[0], int(address.split(':')[1]))

            item = Mapping(
                        sni=sni,
                        address=address,
                   )
            for host in mapping["hosts"]:
                if host.startswith("*."):
                    star_mappings[host[2:]] = item
                    if sni is not None:
                        tcp_hosts.append(host[1:].replace('.', r'\.'))
                else:
                    host_mappings[host] = item
                    if sni is not None:
                        tcp_hosts.append(host.replace('.', r'\.'))

        self.host_mappings = host_mappings
        self.star_mappings = star_mappings
        self.tcp_hosts = tcp_hosts

    def _get_sni(self, host: str) -> Mapping | None:
        mapping = self.host_mappings.get(host)
        if mapping is not None:
            return mapping

        index = 0
        while True:
            index = host.find(".", index)
            if index == -1:
                break
            super_domain = host[(index + 1):]
            mapping = self.star_mappings.get(super_domain)
            if mapping is not None:
                return mapping
            index += 1

        return None

    def _get_ja3(self, data: tls.TlsClientHelloData) -> str | None:
        # GREASE 过滤表
        GREASE_TABLE = {
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
            0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
        }

        try:
            ch = data.client_hello
            raw_bytes = ch.raw_bytes()

            # ==========================================
            # 1. 智能定位 TLS Version: 771 (0x0303)
            # ==========================================
            tls_version = 0

            # 检查 Byte 0 是否是 0x16 (TLS Record Content Type)
            if raw_bytes[0] == 0x16:
                # 情况 A: 包含 Record Header (5字节) + Handshake Header (4字节)
                # 目标版本号在第 9 和 10 字节 (Index 9:11)
                # 结构: [16 03 01 LL LL] [01 LL LL LL] [VV VV]
                tls_version = struct.unpack('!H', raw_bytes[9:11])[0]

            elif raw_bytes[0] == 0x01:
                # 情况 B: 仅包含 Handshake Header (4字节)
                # 目标版本号在第 4 和 5 字节 (Index 4:6)
                # 结构: [01 LL LL LL] [VV VV]
                tls_version = struct.unpack('!H', raw_bytes[4:6])[0]

            else:
                return None

            # ==========================================
            # 2. 提取其他字段 (Ciphers, Exts...)
            # ==========================================
            # Ciphers
            ciphers = [c for c in ch.cipher_suites if c not in GREASE_TABLE]

            # Extensions
            extensions = [ext[0] for ext in ch.extensions if ext[0] not in GREASE_TABLE]

            # Curves & Points (简化演示，实际需解析 payload)
            ec_curves = []
            ec_point_formats = []

            # 解析扩展的具体内容 (Extension ID 10 和 11)
            for ext_id, ext_data in ch.extensions:
                if ext_id == 10: # Supported Groups
                     if len(ext_data) >= 2:
                        count = (len(ext_data) - 2) // 2
                        fmt = f"!{count}H"
                        curves = struct.unpack(fmt, ext_data[2:2 + count * 2])
                        ec_curves = [c for c in curves if c not in GREASE_TABLE]
                elif ext_id == 11: # EC Point Formats
                    if len(ext_data) >= 1:
                        count = len(ext_data) - 1
                        fmt = f"{count}B"
                        formats = struct.unpack(fmt, ext_data[1:1 + count])
                        ec_point_formats = [f for f in formats if f not in GREASE_TABLE]

            # ==========================================
            # 3. 构造 JA3
            # ==========================================
            ja3_raw = ",".join([
                str(tls_version),
                "-".join(str(c) for c in ciphers),
                "-".join(str(e) for e in extensions),
                "-".join(str(c) for c in ec_curves),
                "-".join(str(f) for f in ec_point_formats)
            ])

            return hashlib.md5(ja3_raw.encode()).hexdigest()

        except Exception as e:
            return None


addons = [SpotifyHelper()]
