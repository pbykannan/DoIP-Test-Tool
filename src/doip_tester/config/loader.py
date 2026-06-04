import copy
from pathlib import Path
from typing import Any, Dict, Union

import yaml

from .models import AppConfig


def _coerce_numbers(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _coerce_numbers(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_coerce_numbers(v) for v in obj]
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith("0x") or s.startswith("0X"):
            return int(s, 16)
    return obj


def parse_hex_bytes(s: Union[str, None]) -> bytes:
    if not s or not str(s).strip():
        return b""
    # 任意空白（换行、制表符等）都从 hex 字面量中剔除，便于多行粘贴
    hex_only = "".join(str(s).split())
    hex_only = hex_only.replace("0x", "").replace("0X", "")
    return bytes.fromhex(hex_only)


def load_app_config_from_str(text: str) -> AppConfig:
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(
            "YAML 语法错误（缩进请使用空格，不要使用 Tab 制表符）:\n%s" % exc
        ) from exc
    if not isinstance(raw, dict):
        raise ValueError("config root must be a mapping")
    data = _coerce_numbers(copy.deepcopy(raw))
    return AppConfig.from_dict(data)


def load_app_config(path: Union[str, Path]) -> AppConfig:
    p = Path(path)
    return load_app_config_from_str(p.read_text(encoding="utf-8"))


def app_config_to_dict(cfg: AppConfig) -> Dict[str, Any]:
    """Serialize AppConfig to a YAML-friendly nested dict (matches ``project_configs/*.yaml`` shape)."""
    net: Dict[str, Any] = {
        "host": cfg.network.host,
        "tcp_port": cfg.network.tcp_port,
        "udp_port": cfg.network.udp_port,
    }
    if cfg.network.client_bind_ip:
        net["client_bind_ip"] = cfg.network.client_bind_ip

    doip: Dict[str, Any] = {
        "client_logical_address": cfg.doip.client_logical_address,
        "server_logical_address": cfg.doip.server_logical_address,
        "protocol_version": cfg.doip.protocol_version,
        "activation_type": cfg.doip.activation_type,
        "activation_disabled": cfg.doip.activation_disabled,
    }
    if cfg.doip.vm_specific is not None:
        doip["vm_specific"] = cfg.doip.vm_specific
    if cfg.doip.socket_read_timeout is not None:
        doip["socket_read_timeout"] = cfg.doip.socket_read_timeout
    doip["uds_addressing"] = cfg.doip.uds_addressing
    doip["functional_logical_address"] = cfg.doip.functional_logical_address

    uds: Dict[str, Any] = {
        "request_timeout": cfg.uds.request_timeout,
        "p2_timeout": cfg.uds.p2_timeout,
        "p2_star_timeout": cfg.uds.p2_star_timeout,
    }
    if cfg.uds.server_address_format is not None:
        uds["server_address_format"] = cfg.uds.server_address_format
    if cfg.uds.server_memorysize_format is not None:
        uds["server_memorysize_format"] = cfg.uds.server_memorysize_format
    if cfg.uds.security_key_level1:
        uds["security_key_level1"] = cfg.uds.security_key_level1.hex().upper()
    if cfg.uds.security_key_level3:
        uds["security_key_level3"] = cfg.uds.security_key_level3.hex().upper()

    diagnostics: Dict[str, Any] = {
        "dids": list(cfg.diagnostics.dids),
        "dtc_status_mask": cfg.diagnostics.dtc_status_mask,
    }
    if cfg.diagnostics.service_presets:
        svc_list = []
        for svc in cfg.diagnostics.service_presets:
            item_list = []
            for item in svc.items:
                node: Dict[str, Any] = {
                    "request": bytes(item.request).hex().upper(),
                }
                if item.comment:
                    node["comment"] = item.comment
                item_list.append(node)
            svc_list.append({"sid": int(svc.sid), "items": item_list})
        diagnostics["service_presets"] = svc_list

    flash: Dict[str, Any] = {
        "memory_address": cfg.flash.memory_address,
        "address_format": cfg.flash.address_format,
        "memorysize_format": cfg.flash.memorysize_format,
    }
    if cfg.flash.override_block_payload is not None:
        flash["override_block_payload"] = cfg.flash.override_block_payload
    if cfg.flash.post_request_download_delay_sec is not None:
        flash["post_request_download_delay_sec"] = (
            cfg.flash.post_request_download_delay_sec
        )
    if cfg.flash.transfer_exit_data:
        flash["transfer_exit_data"] = cfg.flash.transfer_exit_data.hex()
    if cfg.flash.pre_transfer_raw_requests:
        raw_items = []
        for step in cfg.flash.pre_transfer_raw_requests:
            if step.addressing == "physical":
                raw_items.append(step.payload.hex())
            else:
                raw_items.append(
                    {"payload": step.payload.hex(), "addressing": step.addressing}
                )
        flash["pre_transfer_raw_requests"] = raw_items
    routines = []
    for r in cfg.flash.pre_transfer_routines:
        item: Dict[str, Any] = {
            "routine_id": r.routine_id,
            "control_type": r.control_type,
        }
        if r.data:
            item["data"] = r.data.hex()
        routines.append(item)
    if routines:
        flash["pre_transfer_routines"] = routines
    if cfg.flash.fingerprint_did is not None:
        flash["fingerprint_did"] = cfg.flash.fingerprint_did
    if cfg.flash.fingerprint_data:
        flash["fingerprint_data"] = cfg.flash.fingerprint_data.hex()
    post_routines = []
    for r in cfg.flash.post_transfer_routines:
        item = {
            "routine_id": r.routine_id,
            "control_type": r.control_type,
        }
        if r.data:
            item["data"] = r.data.hex()
        post_routines.append(item)
    if post_routines:
        flash["post_transfer_routines"] = post_routines
    if cfg.flash.post_transfer_raw_requests:
        raw_items = []
        for step in cfg.flash.post_transfer_raw_requests:
            if step.addressing == "physical":
                raw_items.append(step.payload.hex())
            else:
                raw_items.append(
                    {"payload": step.payload.hex(), "addressing": step.addressing}
                )
        flash["post_transfer_raw_requests"] = raw_items
    if cfg.flash.post_transfer_reconnect_delay_sec is not None:
        flash["post_transfer_reconnect_delay_sec"] = float(
            cfg.flash.post_transfer_reconnect_delay_sec
        )
    if cfg.flash.post_transfer_after_reconnect_raw_requests:
        raw_items2 = []
        for step in cfg.flash.post_transfer_after_reconnect_raw_requests:
            if step.addressing == "physical":
                raw_items2.append(step.payload.hex())
            else:
                raw_items2.append(
                    {"payload": step.payload.hex(), "addressing": step.addressing}
                )
        flash["post_transfer_after_reconnect_raw_requests"] = raw_items2
    if cfg.flash.diagnostic_sessions_before_download:
        flash["diagnostic_sessions_before_download"] = list(
            cfg.flash.diagnostic_sessions_before_download
        )
    if cfg.flash.security_access_levels_before_download:
        flash["security_access_levels_before_download"] = list(
            cfg.flash.security_access_levels_before_download
        )

    return {
        "network": net,
        "doip": doip,
        "uds": uds,
        "diagnostics": diagnostics,
        "flash": flash,
    }


def dump_app_config_yaml(cfg: AppConfig) -> str:
    data = app_config_to_dict(cfg)
    return yaml.safe_dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=88,
    )
