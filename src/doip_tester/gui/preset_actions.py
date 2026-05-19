"""配置驱动的诊断命令树：仅显示诊断服务与子功能。"""

from __future__ import annotations

import binascii
import tkinter as tk
from tkinter import ttk
from typing import List, Optional

from doip_tester.config.models import AppConfig, ServicePreset, ServicePresetItem
from doip_tester.uds.diagnostics import DiagnosticService

_PFX = "preset_"
_PFX_AUTO_27 = "preset_auto27_"


def _hex_with_spaces(raw: bytes) -> str:
    h = binascii.hexlify(bytes(raw)).decode("ascii").upper()
    return " ".join(h[i : i + 2] for i in range(0, len(h), 2))


def _build_default_service_presets(cfg: AppConfig) -> List[ServicePreset]:
    dids = sorted({int(x) & 0xFFFF for x in cfg.diagnostics.dids})
    did_items = [
        ServicePresetItem(request=bytes([0x22, (d >> 8) & 0xFF, d & 0xFF]), comment="")
        for d in dids
    ]
    return [
        ServicePreset(
            sid=0x10,
            items=[
                ServicePresetItem(request=bytes.fromhex("1001"), comment="默认会话"),
                ServicePresetItem(request=bytes.fromhex("1002"), comment="编程会话"),
                ServicePresetItem(request=bytes.fromhex("1003"), comment="扩展会话"),
            ],
        ),
        ServicePreset(
            sid=0x11,
            items=[ServicePresetItem(request=bytes.fromhex("1101"), comment="硬复位")],
        ),
        ServicePreset(
            sid=0x14,
            items=[
                ServicePresetItem(
                    request=bytes.fromhex("14FFFFFF"), comment="清除全部 DTC"
                )
            ],
        ),
        ServicePreset(
            sid=0x19,
            items=[
                ServicePresetItem(
                    request=bytes(
                        [0x19, 0x01, int(cfg.diagnostics.dtc_status_mask) & 0xFF]
                    ),
                    comment="按状态掩码读 DTC 数量",
                ),
                ServicePresetItem(
                    request=bytes(
                        [0x19, 0x02, int(cfg.diagnostics.dtc_status_mask) & 0xFF]
                    ),
                    comment="按状态掩码读 DTC 列表",
                ),
                ServicePresetItem(request=bytes.fromhex("1903"), comment="读快照标识"),
                ServicePresetItem(
                    request=bytes.fromhex("1906FF"), comment="读扩展数据记录"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("190A09"), comment="读支持的 DTC"
                ),
            ],
        ),
        ServicePreset(sid=0x22, items=did_items),
        ServicePreset(
            sid=0x27,
            items=[
                ServicePresetItem(request=bytes.fromhex("2701"), comment="请求 Seed(L1)"),
                ServicePresetItem(request=bytes.fromhex("2711"), comment="请求 Seed(L3)"),
            ],
        ),
        ServicePreset(
            sid=0x28,
            items=[
                ServicePresetItem(request=bytes.fromhex("280001"), comment="恢复通信 NCM"),
                ServicePresetItem(request=bytes.fromhex("280003"), comment="恢复通信 NWMCM+NCM"),
                ServicePresetItem(
                    request=bytes.fromhex("280101"), comment="开Rx关Tx NCM"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("280103"), comment="开Rx关Tx NWMCM+NCM"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("280201"), comment="关Rx开Tx NCM"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("280203"), comment="关Rx开Tx NWMCM+NCM"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("280301"), comment="关Rx关Tx NCM"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("280303"), comment="关Rx关Tx NWMCM+NCM"
                ),
                ServicePresetItem(request=bytes.fromhex("288001"), comment="恢复通信 NCM(抑制)"),
                ServicePresetItem(
                    request=bytes.fromhex("288003"), comment="恢复通信 NWMCM+NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288101"), comment="开Rx关Tx NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288103"), comment="开Rx关Tx NWMCM+NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288201"), comment="关Rx开Tx NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288203"), comment="关Rx开Tx NWMCM+NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288301"), comment="关Rx关Tx NCM(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("288303"), comment="关Rx关Tx NWMCM+NCM(抑制)"
                ),
            ],
        ),
        ServicePreset(
            sid=0x3E,
            items=[
                ServicePresetItem(request=bytes.fromhex("3E00"), comment="TesterPresent"),
                ServicePresetItem(
                    request=bytes.fromhex("3E80"), comment="TesterPresent(抑制)"
                ),
            ],
        ),
        ServicePreset(
            sid=0x85,
            items=[
                ServicePresetItem(request=bytes.fromhex("8501"), comment="DTC Setting ON"),
                ServicePresetItem(request=bytes.fromhex("8502"), comment="DTC Setting OFF"),
                ServicePresetItem(
                    request=bytes.fromhex("8581"), comment="DTC Setting ON(抑制)"
                ),
                ServicePresetItem(
                    request=bytes.fromhex("8582"), comment="DTC Setting OFF(抑制)"
                ),
            ],
        ),
    ]


def run_preset(key: str, diag: DiagnosticService, cfg: AppConfig) -> None:
    auto_lvl = preset_auto_unlock_level(key)
    if auto_lvl is not None:
        diag.security_unlock(auto_lvl)
        return
    data = resolve_preset_payload(key, cfg)
    diag.send_raw_payload(data)


def preset_auto_unlock_level(key: str) -> Optional[int]:
    if key == _PFX_AUTO_27 + "l1":
        return 0x01
    if key == _PFX_AUTO_27 + "l3":
        return 0x11
    return None


def resolve_preset_payload(key: str, cfg: AppConfig) -> bytes:
    if preset_auto_unlock_level(key) is not None:
        raise KeyError("Auto preset does not map to single raw payload: %r" % key)
    if key.startswith(_PFX):
        body = key[len(_PFX) :]
        sid_str, idx_str = body.split("_", 1)
        sid = int(sid_str, 16) & 0xFF
        idx = int(idx_str)
        services = list(cfg.diagnostics.service_presets) or _build_default_service_presets(cfg)
        svc = next((x for x in services if (int(x.sid) & 0xFF) == sid), None)
        if svc is None:
            raise KeyError("Unknown service SID for preset: %r" % key)
        items = sorted(list(svc.items), key=lambda x: bytes(x.request))
        if idx < 0 or idx >= len(items):
            raise KeyError("Preset item index out of range: %r" % key)
        return bytes(items[idx].request)
    raise KeyError("Unknown preset: %r" % key)


def build_preset_tree(tree: ttk.Treeview, cfg: Optional[AppConfig]) -> None:
    for ch in tree.get_children(""):
        tree.delete(ch)
    root = tree.insert("", tk.END, text="诊断服务树（来自当前配置）", open=True)
    if cfg is None:
        tree.insert(root, tk.END, text="(请先加载有效 YAML)", iid="cfg_hint_empty")
        return

    services = list(cfg.diagnostics.service_presets) or _build_default_service_presets(cfg)
    services = sorted(services, key=lambda x: int(x.sid) & 0xFF)
    if not services:
        tree.insert(root, tk.END, text="(diagnostics.service_presets 为空)", iid="cfg_hint_svc")
        return

    for svc in services:
        sid = int(svc.sid) & 0xFF
        node = tree.insert(root, tk.END, text="%02X" % sid, open=False)
        items = sorted(list(svc.items), key=lambda x: bytes(x.request))
        if not items:
            tree.insert(node, tk.END, text="(无子功能)", iid="cfg_hint_%02X" % sid)
            continue
        for idx, item in enumerate(items):
            req_txt = _hex_with_spaces(bytes(item.request))
            cmt = str(item.comment or "").strip()
            text = "SID %s" % req_txt
            if cmt:
                text = "%s（%s）" % (text, cmt)
            tree.insert(node, tk.END, text=text, iid="%s%02X_%d" % (_PFX, sid, idx))
        if sid == 0x27:
            tree.insert(
                node,
                tk.END,
                text="AUTO unlock LvL1（27 01 -> 算法 -> 27 02）",
                iid=_PFX_AUTO_27 + "l1",
            )
            tree.insert(
                node,
                tk.END,
                text="AUTO unlock LvL3（27 11 -> 算法 -> 27 12）",
                iid=_PFX_AUTO_27 + "l3",
            )


def is_preset_leaf(iid: str) -> bool:
    return iid.startswith(_PFX) or iid.startswith(_PFX_AUTO_27)
