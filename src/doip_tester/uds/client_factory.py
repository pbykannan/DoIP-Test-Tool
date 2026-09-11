import copy
import os
from typing import Callable, Optional

from doipclient import DoIPClient
from doipclient.connectors import DoIPClientUDSConnector
from udsoncan.client import Client
from udsoncan.configs import default_client_config

from doip_tester.config.models import AppConfig
from doip_tester.uds.logging_connector import LoggingDoIPClientUDSConnector

# 与 chery v116 doip_callback.c / examples/uds27_chery.c 对齐；可被 uds.security_key_level1/3 覆盖
_DEFAULT_KEY_LEVEL1 = bytes.fromhex("3D2E6DE2A12517BAC5B31BBD0E7E3B54")
_DEFAULT_KEY_LEVEL3 = bytes.fromhex("D0DFAA1588E04B5B14CE834E65E621CD")


def _aes128_cmac(key16: bytes, msg: bytes) -> bytes:
    try:
        from Crypto.Cipher import AES
        from Crypto.Hash import CMAC
    except Exception as exc:
        raise RuntimeError(
            "27算法需要 pycryptodome（pip install pycryptodome）"
        ) from exc
    cobj = CMAC.new(key16, ciphermod=AES)
    cobj.update(msg)
    return cobj.digest()


def _make_chery_v116_security_algo(key_level1: bytes, key_level3: bytes):
    """闭包绑定项目密钥；level 0x11 用 level3 密钥，其余按 level1。"""

    def _algo(seed: bytes, level: int, params=None) -> bytes:
        """
        与参考实现对齐：
        - 正式模式：seed 16字节 -> key = AES-128-CMAC(secret16, seed16)
        - 临时模式：seed 4字节时常见为 echo，返回同长以保证流程可继续。
        """
        seed_b = bytes(seed or b"")
        if len(seed_b) == 16:
            sec = key_level3 if int(level) == 0x11 else key_level1
            return _aes128_cmac(sec, seed_b)
        if len(seed_b) == 4:
            return seed_b
        raise ValueError("Unsupported seed length for 0x27: %d" % len(seed_b))

    return _algo


def baic_v2_derive_session_key(key: bytes, df: bytes) -> bytes:
    """北汽 v2.0：SK = AES-128-CMAC(Key, DF)（PDF 附录 A.2.4）。"""
    return _aes128_cmac(key, df)


def baic_v2_compute_token(sk: bytes, seed: bytes) -> bytes:
    """北汽 v2.0：Token = AES-128-CMAC(SK, Seed)（PDF 附录 A.2.4）。"""
    return _aes128_cmac(sk, seed)


def _make_baic_v2_security_algo(
    key_level1: bytes,
    key_level3: bytes,
    df_source: Optional[Callable[[int], bytes]] = None,
):
    """
    北汽《UDS安全访问认证方案 v2.0》：
      1) Tester 发 27 01/11 -> ECU 返回 16 字节随机 Seed；
      2) Tester 生成 16 字节派生因子 DF；
      3) SK = AES-CMAC(Key, DF)；
      4) Token = AES-CMAC(SK, Seed)；
      5) 27 02/12 上传 32 字节 DF||Token。
    level 0x01 用 UDS 密钥因子，level 0x11 用 BOOT 密钥因子。
    ``df_source`` 仅测试用；缺省为 os.urandom。
    """

    def _algo(seed: bytes, level: int, params=None) -> bytes:
        seed_b = bytes(seed or b"")
        if len(seed_b) != 16:
            raise ValueError(
                "北汽 v2.0 认证要求 16 字节 Seed，收到 %d 字节" % len(seed_b)
            )
        key = key_level3 if int(level) == 0x11 else key_level1
        df = df_source(16) if df_source is not None else os.urandom(16)
        sk = baic_v2_derive_session_key(key, df)
        token = baic_v2_compute_token(sk, seed_b)
        return df + token

    return _algo


def build_uds_client(
    doip: DoIPClient,
    cfg: AppConfig,
    traffic_log: Optional[Callable[[str], None]] = None,
) -> Client:
    u = cfg.uds
    if traffic_log is not None:
        conn = LoggingDoIPClientUDSConnector(
            doip,
            ecu_ip=cfg.network.host,
            log=traffic_log,
            name="DoIP",
            close_connection=True,
        )
    else:
        conn = DoIPClientUDSConnector(doip, name="DoIP", close_connection=True)
    ucfg = copy.deepcopy(default_client_config)
    ucfg["request_timeout"] = u.request_timeout
    ucfg["p2_timeout"] = u.p2_timeout
    ucfg["p2_star_timeout"] = u.p2_star_timeout
    # True=使用 ECU 宣告的 P2/P2*；False=用配置的 p2_timeout/p2_star_timeout（部分 ECU 宣告的 P2 过短，实际响应更慢）
    ucfg["use_server_timing"] = u.use_server_timing
    if u.server_address_format is not None:
        ucfg["server_address_format"] = u.server_address_format
    if u.server_memorysize_format is not None:
        ucfg["server_memorysize_format"] = u.server_memorysize_format
    ucfg["data_identifiers"] = {}
    # 统一给 0x27 提供算法，避免 unlock_security_access 报
    # "Client configuration does not provide a security algorithm"
    k1 = u.security_key_level1 or _DEFAULT_KEY_LEVEL1
    k3 = u.security_key_level3 or _DEFAULT_KEY_LEVEL3
    algo_name = str(u.security_algorithm or "cmac-chery").strip().lower()
    if algo_name == "baic-df-token" or algo_name == "baic_v2":
        ucfg["security_algo"] = _make_baic_v2_security_algo(k1, k3)
    elif algo_name in ("cmac-chery", "chery", ""):
        ucfg["security_algo"] = _make_chery_v116_security_algo(k1, k3)
    else:
        raise ValueError("uds.security_algorithm 未知: %r" % u.security_algorithm)
    ucfg["security_algo_params"] = None
    client = Client(conn, config=ucfg, request_timeout=u.request_timeout)
    return client
