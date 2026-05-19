import queue
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Any, Dict, List, Optional, Tuple

from udsoncan.exceptions import NegativeResponseException
from udsoncan.client import Client

from doip_tester.config.loader import load_app_config_from_str, parse_hex_bytes
from doip_tester.config.models import AppConfig
from doip_tester.doip.session import DoIPSession
from doip_tester.netinfo import enumerate_ipv4_addresses
from doip_tester.projects import (
    list_project_names,
    project_yaml_path,
    read_first_bundled_project_yaml_text,
    read_first_project_yaml_text,
)
from doip_tester.flash.transfer import FlashAborted, run_flash_download_from_path
from doip_tester.gui.preset_actions import (
    build_preset_tree,
    is_preset_leaf,
    preset_auto_unlock_level,
    resolve_preset_payload,
    run_preset,
)
from doip_tester.paths import app_root, ensure_data_beside_exe
from doip_tester.version import get_app_version
from doip_tester.uds.client_factory import build_uds_client
from doip_tester.uds.diagnostics import DiagnosticService


def _default_config_text() -> str:
    """YAML shown when ``project_configs`` is empty — mirrors real templates, not root ``config.yaml``."""
    t = read_first_project_yaml_text(app_root())
    if t is not None:
        return t
    t = read_first_bundled_project_yaml_text()
    if t is not None:
        return t
    return 'network:\n  host: "192.168.1.1"\n'


def _fmt_la(n: int) -> str:
    return "0x%04X" % n if 0 <= n <= 0xFFFF else str(n)


def _enable_windows_dpi_awareness() -> None:
    """Enable best-effort DPI awareness on Windows (for mixed-DPI multi-monitor)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        user32 = ctypes.windll.user32
        shcore = getattr(ctypes.windll, "shcore", None)
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        if hasattr(user32, "SetProcessDpiAwarenessContext"):
            if user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4)):
                return
        # PROCESS_PER_MONITOR_DPI_AWARE = 2
        if shcore is not None and hasattr(shcore, "SetProcessDpiAwareness"):
            shcore.SetProcessDpiAwareness(2)
            return
        if hasattr(user32, "SetProcessDPIAware"):
            user32.SetProcessDPIAware()
    except Exception:
        # DPI API 不可用时保持默认行为
        return


def _apply_dark_ttk(app: tk.Tk) -> Tuple[str, str, str, str, str, str, str]:
    """
    Catppuccin Mocha 风格暗色主题；进度条为 Mantle 槽 + 柔和粉（Pink/Flamingo 系降饱和）与高对比度百分比字。
    返回 (主背景, 前景, 面板/编辑区背景, 选中高亮, 次要说明文字, 青色强调, 粉紫强调).
    """
    bg = "#1e1e2e"
    fg = "#cdd6f4"
    panel = "#313244"
    sel = "#45475a"
    hint = "#6c7086"
    accent = "#89b4fa"
    pink = "#f5c2e7"  # Mocha Pink，按钮按下等点缀
    # 进度条：Catppuccin Mantle / 柔和粉填充；字在槽与填充上都可读
    prog_trough = "#181825"  # Mantle
    prog_fill = "#cfa3bf"  # 介于 Pink(#f5c2e7) 与 Surface 之间的柔粉
    prog_label_fg = "#fff9fc"

    app.configure(bg=bg)
    style = ttk.Style(app)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    btn_bg = "#45475a"
    btn_hi = "#585b70"
    btn_press = pink
    entry_bg = "#313244"

    style.configure(".", background=bg, foreground=fg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("TLabelframe", background=bg, foreground=fg)
    style.configure("TLabelframe.Label", background=bg, foreground=fg, font=("Segoe UI", 9, "bold"))
    style.configure("TButton", background=btn_bg, foreground=fg, borderwidth=0, padding=(8, 4))
    style.map(
        "TButton",
        background=[
            ("active", btn_hi),
            ("pressed", btn_press),
            ("disabled", btn_bg),
        ],
        foreground=[("disabled", hint)],
    )
    style.configure("TEntry", fieldbackground=entry_bg, foreground=fg, borderwidth=1,
                     relief="solid")
    style.map("TEntry",
              fieldbackground=[("focus", entry_bg)],
              bordercolor=[("focus", accent)])
    style.configure("TCombobox", fieldbackground=entry_bg, foreground=fg, borderwidth=1)
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", entry_bg), ("focus", entry_bg)],
    )
    style.configure(
        "Treeview",
        background=panel,
        foreground=fg,
        fieldbackground=panel,
        borderwidth=0,
        rowheight=26,
    )
    style.map(
        "Treeview",
        background=[("selected", sel)],
        foreground=[("selected", fg)],
    )
    style.configure(
        "TScrollbar",
        background=sel,
        troughcolor=panel,
        arrowcolor=hint,
        borderwidth=0,
        width=14,
    )
    style.configure(
        "Horizontal.TProgressbar",
        troughcolor=prog_trough,
        background=prog_fill,
        borderwidth=0,
    )
    try:
        style.layout(
            "Flash.Horizontal.TProgressbar",
            [
                (
                    "Horizontal.Progressbar.trough",
                    {
                        "sticky": "nswe",
                        "children": [
                            ("Horizontal.Progressbar.pbar", {"side": "left", "sticky": "ns"}),
                            ("Horizontal.Progressbar.label", {"sticky": ""}),
                        ],
                    },
                )
            ],
        )
        style.configure(
            "Flash.Horizontal.TProgressbar",
            troughcolor=prog_trough,
            background=prog_fill,
            borderwidth=0,
            text="0%",
            anchor="center",
            foreground=prog_label_fg,
            font=("Segoe UI", 9, "bold"),
        )
    except Exception:
        pass
    style.configure("TRadiobutton", background=bg, foreground=fg)
    style.configure("TCheckbutton", background=bg, foreground=fg)
    style.map("TRadiobutton", background=[("active", bg)])
    style.map("TCheckbutton", background=[("active", bg)])
    # Windows 自带 Tcl/Tk 上 ttk::panedwindow 通常无 minsize；界面分割请用 tk.PanedWindow（见 DoIPTesterApp._build_ui）。
    style.configure("TSeparator", background=sel)

    return bg, fg, panel, sel, hint, accent, pink


def _suppress_paned_handles(pw: tk.PanedWindow) -> None:
    """关闭分割条小方块把手；部分 Windows/Tk 仍会画错位 handle，把手尺寸也压为 0。"""
    try:
        pw.configure(showhandle=False, handlesize=0, handlepad=0)
    except Exception:
        pass


class DoIPTesterApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("DoIP 测试客户端  %s" % get_app_version())
        self._set_initial_geometry()

        self._log_queue: "queue.Queue[str]" = queue.Queue()
        self._prog_queue: "queue.Queue[Tuple[int, int]]" = queue.Queue()
        self._ui_queue: "queue.Queue[Tuple[str, Any]]" = queue.Queue()
        self._cmd_queue: "queue.Queue[Optional[Tuple[str, Dict[str, Any]]]]" = (
            queue.Queue()
        )
        self._worker_stop = threading.Event()
        self._uds_lock = threading.Lock()
        self._doip_session: Optional[DoIPSession] = None
        self._uds_client = None
        self._diag: Optional[DiagnosticService] = None
        self._flash_cancel = threading.Event()
        # TesterPresent 仅通过 worker 队列发送，避免独立线程与诊断争用 _uds_lock 导致第二条命令长期排队
        self._tp_active = False
        self._tp_schedule_after_id: Optional[Any] = None
        self._repo_root = app_root()
        # 避免 Checkbutton 因代码里修改 BooleanVar 触发 command 递归
        self._tp_programmatic = False
        # Windows：焦点移到「执行选中项」等控件时 Treeview 的 selection() 常被清空
        self._last_leaf_preset_iid: Optional[str] = None
        self._disconnecting = False
        self._connecting = False
        self._connect_seq = 0
        self._watch_project_path: Optional[Path] = None
        self._watch_project_mtime_ns: Optional[int] = None
        self._watch_project_loaded_text: str = ""

        self._build_ui()
        self._bind_shortcuts()
        self._worker = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker.start()
        self.after(120, self._poll_queues)

    def _set_initial_geometry(self) -> None:
        """Set adaptive startup size based on current screen."""
        try:
            sw = int(self.winfo_screenwidth())
            sh = int(self.winfo_screenheight())
        except Exception:
            sw, sh = 1920, 1080
        w = max(1080, int(sw * 0.72))
        h = max(680, int(sh * 0.78))
        w = min(w, max(1000, sw - 80))
        h = min(h, max(640, sh - 80))
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(980, 620)

    @staticmethod
    def _normalize_yaml_text_for_compare(text: str) -> str:
        # Tk Text 取值通常会额外带一个末尾换行；比较时去掉它，避免误判“有改动”
        return text.replace("\r\n", "\n").rstrip("\n")

    def _emit_log(self, msg: str) -> None:
        self._log_queue.put(msg)

    def _rebuild_preset_tree(self, cfg: Optional[AppConfig]) -> None:
        build_preset_tree(self._preset_tree, cfg)

    def _build_ui(self) -> None:
        _bg, self._theme_fg, self._theme_panel, self._theme_sel, self._theme_hint, self._theme_accent, self._theme_purple = (
            _apply_dark_ttk(self)
        )
        self._init_config_ui_state()

        # ========== HEADER ==========
        header_frame = ttk.Frame(self, padding=(10, 4, 10, 0))
        header_frame.pack(fill=tk.X)

        # Toolbar row
        toolbar = ttk.Frame(header_frame)
        toolbar.pack(fill=tk.X, pady=(0, 4))

        ttk.Label(toolbar, text="项目", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        self._project_var = tk.StringVar()
        self._project_combo = ttk.Combobox(
            toolbar, textvariable=self._project_var, width=16, state="readonly"
        )
        self._project_combo.pack(side=tk.LEFT, padx=(4, 12))
        self._project_combo.bind("<<ComboboxSelected>>", self._on_project_selected)

        ttk.Label(toolbar, text="本机 IP", font=("Segoe UI", 8)).pack(side=tk.LEFT)
        self._bind_combo = ttk.Combobox(toolbar, width=20)
        self._bind_combo.pack(side=tk.LEFT, padx=4)
        self._bind_combo.bind("<<ComboboxSelected>>", self._on_bind_ip_selected)
        ttk.Button(toolbar, text="↺ 刷新网卡", command=self._refresh_pc_ips).pack(
            side=tk.LEFT, padx=4
        )
        self._proj_hint_label = ttk.Label(
            toolbar,
            text="多网卡时选择连接 TBOX/ECU 所用的本机地址",
            foreground=self._theme_hint,
            font=("Segoe UI", 8),
        )
        self._proj_hint_label.pack(side=tk.LEFT, padx=(8, 0))

        conn_frame = ttk.Frame(toolbar)
        conn_frame.pack(side=tk.RIGHT)
        self._conn_btn = ttk.Button(conn_frame, text="▶ 连接", command=self._connect)
        self._conn_btn.pack(side=tk.LEFT, padx=2)
        self._disconn_btn = ttk.Button(
            conn_frame, text="⏹ 断开", command=self._disconnect, state=tk.DISABLED
        )
        self._disconn_btn.pack(side=tk.LEFT, padx=2)
        self._status = ttk.Label(conn_frame, text="未连接", font=("Segoe UI", 8))
        self._status.pack(side=tk.LEFT, padx=8)

        toolbar.bind("<Configure>", self._on_project_row_resize, add="+")
        self.after(0, self._on_project_row_resize)

        ttk.Separator(self, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=6, pady=(0, 2))

        # ========== MAIN CONTENT ==========
        # tk.PanedWindow：minsize；用细色条作分割（无 handle）。sash 过宽时 Windows/Tk 上命中区偏大，
        # 在树/右侧内容区易出现「整块都像分割条」的十字/双箭头光标。
        _pane_strip = "#6c7086"  # Catppuccin Mocha Overlay2，与内容区反差更大
        _pane_base: Dict[str, Any] = dict(
            bg=_pane_strip,
            bd=0,
            showhandle=False,
            handlesize=0,
            handlepad=0,
            sashwidth=4,
            sashrelief=tk.FLAT,
            sashpad=0,
        )
        _pane_opts_h = dict(_pane_base, sashcursor="size_we")
        _pane_opts_v = dict(_pane_base, sashcursor="size_ns")
        mid = tk.PanedWindow(self, orient=tk.HORIZONTAL, **_pane_opts_h)
        mid.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)
        self._main_paned = mid

        # 左侧工作区（诊断/刷写/日志）更宽；右侧配置区；minsize 与 _init_config_ui_state 中默认一致
        left = ttk.Frame(mid)
        mid.add(left, stretch="always", minsize=int(self._min_left_pane_width))

        right = ttk.Frame(mid)
        mid.add(right, stretch="always", minsize=int(self._min_right_pane_width))
        self._main_paned_left = left
        self._main_paned_right = right
        mid.bind("<ButtonRelease-1>", self._enqueue_main_pane_limits, add="+")
        self.after(0, self._enqueue_main_pane_limits_on_paned_width_change)
        # 勿在 PanedWindow 上绑 <Configure>：子控件(Treeview/滚动条)重绘会级联触发，造成 sash 与滚动条抖动
        self.bind("<Configure>", self._enqueue_main_pane_limits_on_paned_width_change, add="+")
        self._build_config_panel(right)

        # 左侧垂直分割：「诊断&刷写」| 日志；区内横向：树 | 右栏（上手动约 80% / 下刷写约 20%，不可拖）
        vpane = tk.PanedWindow(left, orient=tk.VERTICAL, **_pane_opts_v)
        vpane.pack(fill=tk.BOTH, expand=True)
        self._left_vpane = vpane

        top_frame = ttk.Frame(vpane)
        vpane.add(top_frame, stretch="always", minsize=420)

        diag_lab = ttk.LabelFrame(top_frame, text="诊断&刷写", padding=6)
        diag_lab.pack(fill=tk.BOTH, expand=True)

        h_pane = tk.PanedWindow(diag_lab, orient=tk.HORIZONTAL, **_pane_opts_h)
        h_pane.pack(fill=tk.BOTH, expand=True)

        tree_fr = ttk.Frame(h_pane, cursor="arrow")
        h_pane.add(tree_fr, stretch="always", minsize=200)
        ysb = ttk.Scrollbar(tree_fr, orient=tk.VERTICAL)
        self._preset_tree = ttk.Treeview(
            tree_fr, height=24, yscrollcommand=ysb.set, cursor="arrow"
        )
        ysb["command"] = self._preset_tree.yview
        ysb.pack(side=tk.RIGHT, fill=tk.Y)
        self._preset_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._rebuild_preset_tree(None)
        self._preset_tree.bind("<Double-1>", self._on_preset_double_click)
        self._preset_tree.bind("<<TreeviewSelect>>", self._on_preset_tree_select)

        right_col = ttk.Frame(h_pane, cursor="arrow")
        h_pane.add(right_col, stretch="always", minsize=260)

        right_stack = ttk.Frame(right_col, cursor="arrow")
        right_stack.pack(fill=tk.BOTH, expand=True)
        # 手动区域 : 刷写 ≈ 8:2，固定比例、不可拖拽
        right_stack.columnconfigure(0, weight=1)
        right_stack.rowconfigure(0, weight=8)
        right_stack.rowconfigure(1, weight=2)

        manual_outer = ttk.Frame(right_stack)
        manual_outer.grid(row=0, column=0, sticky="nsew")
        self._manual_outer = manual_outer
        tp_row = ttk.Frame(manual_outer)
        tp_row.pack(fill=tk.X)
        self._tp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tp_row,
            text="TesterPresent 每 2s",
            variable=self._tp_var,
            command=self._toggle_tp,
        ).pack(side=tk.LEFT)
        self._tp_status_label = ttk.Label(
            tp_row, text="○", foreground=self._theme_hint, font=("Segoe UI", 8)
        )
        self._tp_status_label.pack(side=tk.LEFT, padx=(4, 0))

        manual_fr = ttk.Frame(manual_outer)
        manual_fr.pack(fill=tk.X, pady=(10, 0))
        self._manual_fr = manual_fr
        self._manual_label = ttk.Label(manual_fr, text="＞ 手动发送(hex):", font=("JetBrainsMono NF", 9))
        self._manual_label.pack(side=tk.LEFT)
        self._manual_exec_btn = ttk.Button(
            manual_fr, text="▶ 执行", command=self._manual_hex_send, width=6
        )
        self._manual_exec_btn.pack(side=tk.RIGHT)

        manual_hex_holder = ttk.Frame(manual_outer)
        manual_hex_holder.pack(fill=tk.BOTH, expand=True, pady=(4, 0))
        manual_hex_holder.columnconfigure(0, weight=1)
        manual_hex_holder.rowconfigure(0, weight=1)
        manual_hex_sb = ttk.Scrollbar(manual_hex_holder, orient=tk.VERTICAL)
        self._manual_hex_text = tk.Text(
            manual_hex_holder,
            height=4,
            width=8,
            wrap=tk.CHAR,
            undo=True,
            maxundo=-1,
            font=("JetBrainsMono NF", 9),
            bg=self._theme_panel,
            fg=self._theme_fg,
            insertbackground=self._theme_fg,
            selectbackground=self._theme_sel,
            selectforeground=self._theme_fg,
            highlightthickness=0,
            relief=tk.FLAT,
            bd=1,
            padx=6,
            pady=6,
        )
        self._manual_hex_text.configure(yscrollcommand=manual_hex_sb.set)
        manual_hex_sb.configure(command=self._manual_hex_text.yview)
        self._manual_hex_text.grid(row=0, column=0, sticky="nsew")
        manual_hex_sb.grid(row=0, column=1, sticky="ns")
        self._manual_hex_holder = manual_hex_holder
        self._manual_hex_scrollbar = manual_hex_sb
        self._manual_hex_text.edit_modified(False)
        self._manual_hex_text.bind("<<Modified>>", self._on_manual_hex_text_modified, add="+")
        self._manual_hex_holder.bind("<Configure>", self._schedule_manual_hex_height_sync, add="+")

        self._preset_hint_label = ttk.Label(
            manual_outer,
            text="预置服务：双击树中叶子会先填入手动发送框，再自动发送 1 帧；27 的 AUTO 节点会自动完成 seed/key 解锁。",
            foreground=self._theme_hint,
        )
        self._preset_hint_label.pack(anchor=tk.W, pady=(6, 0))

        flash = ttk.LabelFrame(right_stack, text="刷写 (34/36/37)", padding=6)
        flash.grid(row=1, column=0, sticky="nsew")

        manual_outer.bind("<Configure>", self._on_diag_controls_resize, add="+")

        def _first_diag_layout() -> None:
            try:
                self.update_idletasks()
            except Exception:
                pass
            self._on_diag_controls_resize()

        self.after_idle(_first_diag_layout)
        self.after(160, self._schedule_manual_hex_height_sync)

        fr = ttk.Frame(flash)
        fr.pack(fill=tk.X)
        self._fw_path = tk.StringVar()

        path_row = ttk.Frame(fr)
        path_row.pack(side=tk.TOP, fill=tk.X, pady=(0, 6))
        self._flash_path_entry = ttk.Entry(path_row, textvariable=self._fw_path, width=52)
        self._flash_path_entry.pack(side=tk.TOP, fill=tk.X, expand=False)

        pick_row = ttk.Frame(fr)
        pick_row.pack(side=tk.TOP, fill=tk.X, pady=(0, 0))
        self._flash_choose_file_btn = ttk.Button(
            pick_row, text="📁 选文件…", command=self._browse_fw
        )
        self._flash_choose_file_btn.pack(side=tk.LEFT, padx=(0, 8))
        self._flash_choose_dir_btn = ttk.Button(
            pick_row, text="📁 选目录…", command=self._browse_fw_dir
        )
        self._flash_choose_dir_btn.pack(side=tk.LEFT)

        self._prog_wrap = ttk.Frame(flash)
        self._prog_wrap.pack(fill=tk.X, pady=(14, 8))
        self._prog = ttk.Progressbar(
            self._prog_wrap, mode="determinate", length=400, style="Flash.Horizontal.TProgressbar"
        )
        self._prog.pack(fill=tk.X)

        flash_actions = ttk.Frame(flash)
        flash_actions.pack(fill=tk.X, pady=(4, 0))
        self._flash_btn = ttk.Button(
            flash_actions, text="▶ 开始刷写", command=self._start_flash
        )
        self._flash_btn.pack(side=tk.LEFT, padx=(0, 8))
        self._cancel_flash_btn = ttk.Button(
            flash_actions, text="⏹ 中止", command=self._cancel_flash, state=tk.DISABLED
        )
        self._cancel_flash_btn.pack(side=tk.LEFT)

        def _refresh_paned_no_handles() -> None:
            for _pw in (mid, vpane, h_pane):
                _suppress_paned_handles(_pw)

        _refresh_paned_no_handles()
        self.after_idle(_refresh_paned_no_handles)
        self.after(500, _refresh_paned_no_handles)

        bottom_frame = ttk.Frame(vpane)
        vpane.add(bottom_frame, stretch="always", minsize=100)

        log_header = ttk.Frame(bottom_frame)
        log_header.pack(fill=tk.X, pady=(4, 0))
        ttk.Label(log_header, text="日志", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Button(
            log_header, text="✕ 清空", command=self._clear_log, width=6
        ).pack(side=tk.RIGHT)
        self._log = scrolledtext.ScrolledText(
            bottom_frame, height=8, state=tk.DISABLED, font=("JetBrainsMono NF", 9)
        )
        self._log.pack(fill=tk.BOTH, expand=True)
        self._log.configure(
            bg=self._theme_panel,
            fg=self._theme_fg,
            insertbackground=self._theme_fg,
            selectbackground=self._theme_sel,
            selectforeground=self._theme_fg,
            highlightthickness=0,
            relief=tk.FLAT,
            font=("JetBrainsMono NF", 9),
        )
        self._log.tag_configure("error", foreground="#f38ba8")
        self._log.tag_configure("warn", foreground="#f9e2af")
        self._log.tag_configure("info", foreground="#89b4fa")
        self._log.tag_configure("timestamp", foreground=self._theme_hint)

        # ========== STATUS BAR ==========
        bot_container = ttk.Frame(self)
        bot_container.pack(fill=tk.X, side=tk.BOTTOM)
        ttk.Separator(bot_container, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=6)
        status_bar = ttk.Frame(bot_container, padding=(10, 2, 10, 4))
        status_bar.pack(fill=tk.X)
        self._status_left = ttk.Label(
            status_bar, text="⏹ 未连接", foreground=self._theme_hint, font=("Segoe UI", 8)
        )
        self._status_left.pack(side=tk.LEFT)
        self._status_right = ttk.Label(
            status_bar, text="DoIP Test  %s" % get_app_version(),
            foreground=self._theme_hint, font=("Segoe UI", 8)
        )
        self._status_right.pack(side=tk.RIGHT)

        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self._populate_projects()

    def _init_config_ui_state(self) -> None:
        self._v_bind = tk.StringVar(value="")
        self._addr_mode = tk.StringVar(value="physical")
        self._v_functional_la = tk.StringVar(value="0xE400")
        self._v_manual_hex = tk.StringVar(value="")
        self._v_addr_effective = tk.StringVar(value="当前生效: 物理寻址 -> 0x002B")
        self._v_prog_text = tk.StringVar(value="0%")
        self._min_left_pane_width = 700
        self._min_right_pane_width = 240
        self._main_pane_adjust_job: Optional[Any] = None
        self._last_paned_total_width: Optional[int] = None
        self._main_pane_minsize_key: Optional[tuple[int, int]] = None
        self._manual_compact_layout = False
        self._manual_hex_resize_job: Optional[Any] = None

    def _enqueue_main_pane_limits_on_paned_width_change(self, evt=None) -> None:
        """仅在主区 PanedWindow 总宽变化明显时排队调整，过滤子控件重绘导致的重复事件。"""
        if evt is not None and getattr(evt, "widget", None) is not self:
            return
        mid = getattr(self, "_main_paned", None)
        if mid is None:
            return
        try:
            tw = int(mid.winfo_width())
        except Exception:
            return
        if tw <= 1:
            return
        prev = self._last_paned_total_width
        if prev is not None and abs(tw - prev) < 12:
            return
        self._last_paned_total_width = tw
        self._enqueue_main_pane_limits()

    def _enqueue_main_pane_limits(self, _evt=None) -> None:
        """合并全屏/竖屏时连续排队，避免 sash 微调 ↔ 重排死循环抖动。"""
        if self._main_pane_adjust_job is not None:
            try:
                self.after_cancel(self._main_pane_adjust_job)
            except Exception:
                pass
        self._main_pane_adjust_job = self.after(120, self._enforce_main_pane_limits)

    def _enforce_main_pane_limits(self, _evt=None) -> None:
        """用 tk.PanedWindow 的 pane minsize（ttk Panedwindow 在 Windows 附带 Tcl 下常不支持 minsize）。"""
        self._main_pane_adjust_job = None
        mid = getattr(self, "_main_paned", None)
        left_p = getattr(self, "_main_paned_left", None)
        right_p = getattr(self, "_main_paned_right", None)
        if mid is None or left_p is None or right_p is None:
            return
        try:
            total = int(mid.winfo_width())
        except Exception:
            return
        if total <= 1:
            return
        min_right = int(self._min_right_pane_width)
        min_left_cfg = int(self._min_left_pane_width)
        # 竖屏全屏总宽常小于 760+280：动态降低左侧下限
        if total < min_left_cfg + min_right:
            # 下限过低时拖分割条会把整段诊断树压没；在仍可容纳右栏时尽量保留左侧可用宽
            min_left = max(320, total - min_right)
        else:
            min_left = min_left_cfg
        upper = max(0, total - min_right)
        lower = min_left if min_left <= upper else upper
        key = (int(lower), min_right)
        if getattr(self, "_main_pane_minsize_key", None) == key:
            return
        self._main_pane_minsize_key = key
        try:
            mid.paneconfig(left_p, minsize=key[0])
            mid.paneconfig(right_p, minsize=key[1])
        except Exception:
            pass

    def _set_manual_compact_layout(self, compact: bool) -> None:
        if compact == self._manual_compact_layout:
            return
        self._manual_compact_layout = compact
        try:
            self._manual_label.pack_forget()
            self._manual_exec_btn.pack_forget()
        except Exception:
            return
        if compact:
            self._manual_label.pack(side=tk.TOP, anchor=tk.W, pady=(0, 4))
            self._manual_exec_btn.pack(side=tk.TOP, anchor=tk.E, pady=(0, 8))
        else:
            self._manual_label.pack(side=tk.LEFT)
            self._manual_exec_btn.pack(side=tk.RIGHT)

    def _on_diag_controls_resize(self, _evt=None) -> None:
        """手动区控件：工具条窄屏换行；预置说明按整列宽换行（勿用固定的 380px / 偏小 manual_fr）。"""
        outer = getattr(self, "_manual_outer", None)
        if outer is None:
            return
        try:
            cw = int(outer.winfo_width())
        except Exception:
            cw = 0
        if cw <= 30:
            return
        try:
            mf = int(self._manual_fr.winfo_width())
        except Exception:
            mf = cw
        self._set_manual_compact_layout(mf < 460)
        try:
            self._preset_hint_label.configure(wraplength=max(120, cw - 24))
        except Exception:
            pass

    def _on_manual_hex_text_modified(self, _evt: Optional[tk.Event] = None) -> None:
        tw = getattr(self, "_manual_hex_text", None)
        if tw is None:
            return
        try:
            if not tw.edit_modified():
                return
            tw.edit_modified(False)
        except tk.TclError:
            return
        self._schedule_manual_hex_height_sync()

    def _schedule_manual_hex_height_sync(self, _evt: Optional[tk.Event] = None) -> None:
        job = getattr(self, "_manual_hex_resize_job", None)
        if job is not None:
            try:
                self.after_cancel(job)
            except Exception:
                pass
        self._manual_hex_resize_job = self.after(42, self._sync_manual_hex_widget_height)

    def _manual_hex_display_lines(self, tw: tk.Text) -> int:
        try:
            raw = tw.get("1.0", "end-1c")
            if not raw.strip():
                return 1
        except tk.TclError:
            return 1
        if len(raw) > 65536:
            # 极大内容避免反复 count：直接占满可视区交给滚动条
            try:
                return max(10000, int(tw.index("end-1c").split(".")[0]))
            except Exception:
                return 10000
        try:
            n = tw.count("1.0", "end-1c", "displaylines", "update")
            ni = int(n[0]) if isinstance(n, (list, tuple)) else int(n)
            return max(1, ni)
        except Exception:
            try:
                return max(1, int(tw.index("end-1c").split(".")[0]))
            except Exception:
                return 4

    def _sync_manual_hex_widget_height(self) -> None:
        self._manual_hex_resize_job = None
        tw = getattr(self, "_manual_hex_text", None)
        holder = getattr(self, "_manual_hex_holder", None)
        if tw is None or holder is None:
            return
        try:
            holder.update_idletasks()
            avail_px = int(holder.winfo_height()) - 6
            if avail_px < 48:
                return
        except Exception:
            return
        try:
            li = tw.dlineinfo("1.1")
            line_px = max(14, int(li[3]) + 2) if li else 20
        except tk.TclError:
            line_px = 20
        max_ln = max(4, avail_px // line_px)
        content_ln = self._manual_hex_display_lines(tw)
        desired = max(4, min(max_ln, content_ln))
        try:
            cur = int(float(tw.cget("height")))
        except (tk.TclError, ValueError, TypeError):
            cur = -1
        if cur != desired:
            try:
                tw.edit_modified(False)
                tw.configure(height=desired)
            except tk.TclError:
                pass

    def _on_config_panel_resize(self, evt=None) -> None:
        try:
            w = int(evt.width) if evt is not None else 320
        except Exception:
            w = 320
        wrap = max(120, w - 26)
        try:
            self._cfg_intro_label.configure(wraplength=wrap)
            self._yaml_shortcut_label.configure(wraplength=max(120, w - 26))
        except Exception:
            pass

    def _on_project_row_resize(self, evt=None) -> None:
        try:
            w = int(evt.width) if evt is not None else 1000
        except Exception:
            w = 1000
        try:
            if w < 980:
                self._proj_hint_label.pack_forget()
            else:
                if not self._proj_hint_label.winfo_ismapped():
                    self._proj_hint_label.pack(side=tk.LEFT, padx=(8, 0))
        except Exception:
            pass

    def _build_config_panel(self, left: ttk.Frame) -> None:
        self._cfg_intro_label = ttk.Label(
            left,
            text="修改诊断服务与刷写功能可编辑下方 YAML",
            foreground=self._theme_hint,
            wraplength=300,
            font=("Segoe UI", 8),
        )
        self._cfg_intro_label.pack(anchor=tk.W, pady=(0, 6))

        addr_fr = ttk.LabelFrame(left, text="UDS 寻址（DoIP 诊断目标逻辑地址）", padding=8)
        addr_fr.pack(fill=tk.X, pady=(0, 8))
        r0 = ttk.Frame(addr_fr)
        r0.pack(fill=tk.X)
        phys_frame = ttk.Frame(r0, padding=(6, 3, 12, 3))
        phys_frame.pack(side=tk.LEFT)
        ttk.Radiobutton(
            phys_frame,
            text="物理寻址",
            variable=self._addr_mode,
            value="physical",
            command=self._on_addr_mode_change,
        ).pack(side=tk.LEFT)
        func_frame = ttk.Frame(r0, padding=(12, 3, 6, 3))
        func_frame.pack(side=tk.LEFT)
        ttk.Radiobutton(
            func_frame,
            text="功能寻址",
            variable=self._addr_mode,
            value="functional",
            command=self._on_addr_mode_change,
        ).pack(side=tk.LEFT)

        r1 = ttk.Frame(addr_fr)
        r1.pack(fill=tk.X, pady=(6, 4))
        ttk.Label(r1, text="functional address(hex):", font=("Segoe UI", 9)).pack(side=tk.LEFT)
        self._ent_functional_la = ttk.Entry(
            r1, textvariable=self._v_functional_la, width=12, font=("JetBrainsMono NF", 10)
        )
        self._ent_functional_la.pack(side=tk.LEFT, padx=6)
        self._ent_functional_la.bind(
            "<Return>", lambda _evt: self._apply_live_uds_addressing_from_ui()
        )
        self._ent_functional_la.bind(
            "<FocusOut>", lambda _evt: self._apply_live_uds_addressing_from_ui()
        )
        eff = ttk.Label(
            addr_fr, textvariable=self._v_addr_effective, foreground=self._theme_accent,
            font=("Segoe UI", 9, "bold"), padding=(0, 4, 0, 0)
        )
        eff.pack(anchor=tk.W)

        yaml_actions = ttk.Frame(left)
        yaml_actions.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(yaml_actions, text="📂 加载 YAML", command=self._load_yaml_file).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(yaml_actions, text="💾 保存 YAML", command=self._save_yaml_file).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(
            yaml_actions, text="🔄 刷新配置", command=self._refresh_watched_yaml_once
        ).pack(
            side=tk.LEFT
        )
        self._yaml_shortcut_label = ttk.Label(
            left,
            text="Ctrl+O 加载  |  Ctrl+S 保存  |  F5 刷新",
            foreground=self._theme_hint,
            font=("Segoe UI", 8),
            justify=tk.LEFT,
        )
        self._yaml_shortcut_label.pack(anchor=tk.W, pady=(0, 4))

        self._cfg_text = scrolledtext.ScrolledText(
            left, width=36, height=22, font=("JetBrainsMono NF", 9)
        )
        self._cfg_text.pack(fill=tk.BOTH, expand=True)
        self._cfg_text.configure(
            bg=self._theme_panel,
            fg=self._theme_fg,
            insertbackground=self._theme_fg,
            selectbackground=self._theme_sel,
            selectforeground=self._theme_fg,
            highlightthickness=0,
            relief=tk.FLAT,
            font=("JetBrainsMono NF", 9),
        )
        self._cfg_text.insert("1.0", _default_config_text())
        self._on_addr_mode_change()
        left.bind("<Configure>", self._on_config_panel_resize, add="+")
        self.after(0, self._on_config_panel_resize)

    def _on_addr_mode_change(self) -> None:
        st = tk.NORMAL if self._addr_mode.get() == "functional" else tk.DISABLED
        self._ent_functional_la.configure(state=st)
        self._update_addr_effective_hint()
        self._apply_live_uds_addressing_from_ui()

    def _apply_live_uds_addressing_from_ui(self) -> None:
        """Apply UI addressing mode to current DoIP client immediately when connected."""
        if self._doip_session is None:
            return
        try:
            target = (
                int(self._v_functional_la.get().strip(), 0)
                if self._addr_mode.get() == "functional"
                else int(self._doip_session.client._ecu_logical_address)
            )
        except Exception as exc:
            self._emit_log("UDS 寻址参数无效（未应用）: %s" % exc)
            return
        try:
            with self._uds_lock:
                cli = self._doip_session.client
                cli._uds_target_logical_address = int(target) & 0xFFFF
            self._emit_log(
                "UDS 寻址已切换为 %s，DoIP 目标逻辑地址=0x%04X"
                % (self._addr_mode.get(), int(target) & 0xFFFF)
            )
            self._update_addr_effective_hint()
        except Exception as exc:
            self._emit_log("UDS 寻址切换失败: %s" % exc)

    def _sync_ui_from_cfg(self, cfg: AppConfig) -> None:
        self._addr_mode.set(
            "functional" if cfg.doip.uds_addressing == "functional" else "physical"
        )
        self._v_functional_la.set(_fmt_la(cfg.doip.functional_logical_address))
        self._v_bind.set(cfg.network.client_bind_ip or "")
        self._sync_bind_combo_from_bind_var()
        self._on_addr_mode_change()

    def _update_addr_effective_hint(self) -> None:
        mode = "功能寻址" if self._addr_mode.get() == "functional" else "物理寻址"
        target: Optional[int] = None
        if self._doip_session is not None:
            try:
                target = int(self._doip_session.client._uds_target_logical_address) & 0xFFFF
            except Exception:
                target = None
        if target is None:
            try:
                if self._addr_mode.get() == "functional":
                    target = int(self._v_functional_la.get().strip(), 0) & 0xFFFF
                else:
                    target = int(self._parse_cfg().doip.server_logical_address) & 0xFFFF
            except Exception:
                target = 0x002B
        self._v_addr_effective.set("当前生效: %s -> 0x%04X" % (mode, target))

    def _bind_shortcuts(self) -> None:
        self.bind_all("<Control-o>", self._on_shortcut_load_yaml, add="+")
        self.bind_all("<Control-O>", self._on_shortcut_load_yaml, add="+")
        self.bind_all("<Control-s>", self._on_shortcut_save_yaml, add="+")
        self.bind_all("<Control-S>", self._on_shortcut_save_yaml, add="+")
        self.bind_all("<F5>", self._on_shortcut_refresh_yaml, add="+")

    def _on_shortcut_load_yaml(self, _evt=None):
        self._load_yaml_file()
        return "break"

    def _on_shortcut_save_yaml(self, _evt=None):
        self._save_yaml_file()
        return "break"

    def _on_shortcut_refresh_yaml(self, _evt=None):
        self._refresh_watched_yaml_once()
        return "break"

    def _populate_projects(self) -> None:
        names = list_project_names(self._repo_root)
        if names:
            self._project_combo.configure(values=names)
            self._project_var.set(names[0])
            self._load_project_yaml(names[0], log=False)
        else:
            self._clear_project_watch()
            self._project_combo.configure(values=["(无 project_configs/*.yaml)"])
            self._project_var.set("(无 project_configs/*.yaml)")
            self._cfg_text.delete("1.0", tk.END)
            self._cfg_text.insert("1.0", _default_config_text())
            try:
                cfg = self._parse_cfg()
                self._sync_ui_from_cfg(cfg)
                self._rebuild_preset_tree(cfg)
            except Exception:
                pass
            self._refresh_pc_ips(emit_log=False)

    def _load_project_yaml(self, name: str, log: bool = True) -> None:
        if name.startswith("("):
            return
        path = project_yaml_path(self._repo_root, name)
        if not path.is_file():
            self._clear_project_watch()
            self._emit_log("项目文件不存在: %s" % path)
            return
        text = path.read_text(encoding="utf-8")
        self._cfg_text.delete("1.0", tk.END)
        self._cfg_text.insert("1.0", text)
        try:
            cfg = self._parse_cfg()
            self._sync_ui_from_cfg(cfg)
            self._rebuild_preset_tree(cfg)
        except Exception as exc:
            if log:
                messagebox.showerror("配置", "项目 YAML 无效：\n%s" % exc)
            return
        self._set_project_watch(path, text)
        self._refresh_pc_ips(emit_log=log)
        if log:
            self._emit_log("已加载项目: %s" % name)

    def _on_project_selected(self, _evt: Optional[tk.Event] = None) -> None:
        name = self._project_var.get()
        self._load_project_yaml(name, log=True)

    def _refresh_pc_ips(self, emit_log: bool = True) -> None:
        ips = enumerate_ipv4_addresses()
        bind = self._v_bind.get().strip()
        parts: List[str] = ["自动"]
        if bind and bind not in ips:
            parts.append(bind)
        parts.extend(sorted(set(ips)))
        self._bind_combo.configure(values=tuple(parts))
        self._sync_bind_combo_from_bind_var()
        if emit_log:
            self._emit_log(
                "网卡 IPv4: %s"
                % ("、".join(ips) if ips else "未发现（可检查虚拟网卡/权限）")
            )

    def _sync_bind_combo_from_bind_var(self) -> None:
        val = self._v_bind.get().strip()
        vals = list(self._bind_combo.cget("values"))
        if not vals:
            return
        if val:
            if val not in vals:
                merged = ("自动", val) + tuple(x for x in vals[1:] if x != val)
                self._bind_combo.configure(values=merged)
            self._bind_combo.set(val)
        else:
            self._bind_combo.set("自动")

    def _on_bind_ip_selected(self, _evt: Optional[tk.Event] = None) -> None:
        sel = self._bind_combo.get()
        if sel == "自动" or not sel:
            self._v_bind.set("")
        else:
            self._v_bind.set(sel)

    def _append_log(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        if "错误" in msg or "失败" in msg or "异常" in msg or "error" in msg.lower():
            tag = "error"
        elif self._detect_warning(msg):
            tag = "warn"
        else:
            tag = "info"
        self._log.configure(state=tk.NORMAL)
        self._log.insert(tk.END, "[%s] " % ts, "timestamp")
        self._log.insert(tk.END, "%s\n" % msg, tag)
        self._log.see(tk.END)
        self._log.configure(state=tk.DISABLED)

    @staticmethod
    def _detect_warning(msg: str) -> bool:
        kw = ("警告", "warn", "warning", "注意", "超时", "timeout")
        return any(k in msg.lower() for k in kw)

    def _clear_log(self) -> None:
        self._log.configure(state=tk.NORMAL)
        self._log.delete("1.0", tk.END)
        self._log.configure(state=tk.DISABLED)

    def _poll_queues(self) -> None:
        try:
            try:
                while True:
                    m = self._log_queue.get_nowait()
                    self._append_log(m)
            except queue.Empty:
                pass
            try:
                while True:
                    cur, tot = self._prog_queue.get_nowait()
                    self._prog["maximum"] = max(tot, 1)
                    self._prog["value"] = cur
                    self._update_progress_text(cur, tot)
            except queue.Empty:
                pass
            try:
                while True:
                    kind, payload = self._ui_queue.get_nowait()
                    if kind == "connected":
                        ok = bool(payload)
                        if ok:
                            self._status.configure(text="已连接")
                            self._status_left.configure(text="● 已连接", foreground=self._theme_accent)
                            self._conn_btn.configure(state=tk.DISABLED)
                            self._disconn_btn.configure(state=tk.NORMAL)
                        else:
                            self._status.configure(text="未连接")
                            self._status_left.configure(text="⏹ 未连接", foreground=self._theme_hint)
                            self._conn_btn.configure(state=tk.NORMAL)
                            self._disconn_btn.configure(state=tk.DISABLED)
                        self._update_addr_effective_hint()
                    elif kind == "disconnected":
                        self._status.configure(text="未连接")
                        self._status_left.configure(text="⏹ 未连接", foreground=self._theme_hint)
                        self._conn_btn.configure(state=tk.NORMAL)
                        self._disconn_btn.configure(state=tk.DISABLED)
                        self._update_addr_effective_hint()
                    elif kind == "flash_done":
                        self._flash_btn.configure(state=tk.NORMAL)
                        self._cancel_flash_btn.configure(state=tk.DISABLED)
                        self._update_progress_text(
                            int(float(self._prog["value"])),
                            int(float(self._prog["maximum"])),
                        )
                        if self._tp_var.get():
                            self._start_tp()
                    elif kind == "tp_done":
                        # 上一帧 TP 结束后再等 2s 发下一帧，避免队列里堆满 tp_tick
                        if self._tp_active:
                            self._tp_schedule_after_id = self.after(
                                2000, self._enqueue_tp_tick_delayed
                            )
            except queue.Empty:
                pass
        except Exception as exc:
            # 防止 UI 轮询因个别异常停止，导致按钮状态永远卡在“连接中…”
            self._emit_log("UI 轮询异常: %s" % exc)
        finally:
            self.after(120, self._poll_queues)

    def _update_progress_text(self, cur: int, tot: int) -> None:
        denom = max(int(tot), 1)
        pct = int(max(0.0, min(100.0, float(cur) * 100.0 / float(denom))))
        self._v_prog_text.set("%d%%" % pct)
        try:
            ttk.Style(self).configure("Flash.Horizontal.TProgressbar", text=self._v_prog_text.get())
        except Exception:
            pass

    def _set_project_watch(self, path: Path, loaded_text: str) -> None:
        self._watch_project_path = path
        self._watch_project_loaded_text = self._normalize_yaml_text_for_compare(
            loaded_text
        )
        try:
            self._watch_project_mtime_ns = path.stat().st_mtime_ns
        except OSError:
            self._watch_project_mtime_ns = None

    def _clear_project_watch(self) -> None:
        self._watch_project_path = None
        self._watch_project_mtime_ns = None
        self._watch_project_loaded_text = ""

    def _refresh_watched_yaml_once(self) -> None:
        path = self._watch_project_path
        if path is None:
            messagebox.showinfo("配置", "当前没有可刷新的已跟踪配置文件。")
            return
        try:
            mtime_ns = path.stat().st_mtime_ns
        except OSError:
            self._emit_log("配置文件不存在或不可访问: %s" % path)
            return
        old_mtime_ns = self._watch_project_mtime_ns
        if old_mtime_ns is not None and mtime_ns == old_mtime_ns:
            self._emit_log("配置文件无变化，无需刷新。")
            return
        text = path.read_text(encoding="utf-8")
        self._cfg_text.delete("1.0", tk.END)
        self._cfg_text.insert("1.0", text)
        try:
            cfg = self._parse_cfg()
            self._sync_ui_from_cfg(cfg)
            self._rebuild_preset_tree(cfg)
            self._watch_project_loaded_text = self._normalize_yaml_text_for_compare(
                text
            )
            self._watch_project_mtime_ns = mtime_ns
            self._emit_log("检测到配置变化，已刷新 YAML 和服务树。")
        except Exception as exc:
            self._watch_project_mtime_ns = mtime_ns
            messagebox.showerror("配置", "配置刷新失败：\n%s" % exc)

    def _load_yaml_file(self) -> None:
        p = filedialog.askopenfilename(
            filetypes=[("YAML", "*.yaml;*.yml"), ("All", "*.*")]
        )
        if p:
            path = Path(p)
            text = path.read_text(encoding="utf-8")
            self._cfg_text.delete("1.0", tk.END)
            self._cfg_text.insert("1.0", text)
            try:
                cfg = self._parse_cfg()
                self._sync_ui_from_cfg(cfg)
                self._rebuild_preset_tree(cfg)
                self._set_project_watch(path, text)
            except Exception:
                pass
            self._refresh_pc_ips(emit_log=False)

    def _save_yaml_file(self) -> None:
        p = filedialog.asksaveasfilename(
            defaultextension=".yaml",
            filetypes=[("YAML", "*.yaml"), ("All", "*.*")],
        )
        if p:
            text = self._cfg_text.get("1.0", tk.END)
            path = Path(p)
            path.write_text(text, encoding="utf-8")
            if self._watch_project_path is not None:
                try:
                    if path.resolve() == self._watch_project_path.resolve():
                        self._watch_project_loaded_text = (
                            self._normalize_yaml_text_for_compare(text)
                        )
                        self._watch_project_mtime_ns = path.stat().st_mtime_ns
                except OSError:
                    pass
            # 保存后立即按当前编辑区内容刷新 UI/树，避免还要手动“加载 YAML”
            try:
                cfg = self._parse_cfg()
                self._sync_ui_from_cfg(cfg)
                self._rebuild_preset_tree(cfg)
            except Exception as exc:
                messagebox.showerror("配置", "保存成功，但解析失败：\n%s" % exc)
            self._emit_log("已保存: %s" % p)

    def _parse_cfg(self) -> AppConfig:
        """Parse YAML text only (no form overlay)."""
        return load_app_config_from_str(self._cfg_text.get("1.0", tk.END))

    def _effective_cfg(self) -> AppConfig:
        """YAML + 顶部「本机 IP」组合框 + 物理/功能寻址。须在 Tk 主线程调用。"""
        cfg = self._parse_cfg()
        sel = self._bind_combo.get()
        if sel == "自动" or not sel:
            cfg.network.client_bind_ip = None
        else:
            cfg.network.client_bind_ip = sel.strip()
        cfg.doip.uds_addressing = (
            "functional" if self._addr_mode.get() == "functional" else "physical"
        )
        cfg.doip.functional_logical_address = int(
            self._v_functional_la.get().strip(), 0
        )
        return cfg

    def _enqueue(self, cmd: str, **kwargs: Any) -> None:
        self._cmd_queue.put((cmd, dict(kwargs)))

    def _clear_pending_cmd_queue(self) -> None:
        """Drop pending non-worker-stop commands to avoid stale ops after disconnect."""
        while True:
            try:
                item = self._cmd_queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                self._cmd_queue.put(None)
                break

    def _drop_pending_tp_ticks(self) -> None:
        """Remove stale tp_tick items so flash can start immediately."""
        drained: List[Any] = []
        while True:
            try:
                drained.append(self._cmd_queue.get_nowait())
            except queue.Empty:
                break
        for item in drained:
            if item is None:
                self._cmd_queue.put(None)
                continue
            cmd, _args = item
            if cmd != "tp_tick":
                self._cmd_queue.put(item)

    def _enqueue_preset(self, key: str) -> None:
        try:
            cfg = self._effective_cfg()
        except Exception as exc:
            messagebox.showerror("配置", str(exc))
            return
        self._cmd_queue.put(("preset", {"cfg": cfg, "key": key}))

    def _on_preset_tree_select(self, _evt: Optional[tk.Event] = None) -> None:
        sel = self._preset_tree.selection()
        if len(sel) == 1 and is_preset_leaf(sel[0]):
            self._last_leaf_preset_iid = sel[0]

    def _run_selected_preset(self) -> None:
        """将选中预置填入手动发送框，不直接发包。"""
        tree = self._preset_tree
        sel = tree.selection()
        row = sel[0] if sel else None
        if row is None:
            row = self._last_leaf_preset_iid
        if row is None:
            messagebox.showwarning(
                "诊断",
                "请先在树中单击选中一条命令（叶子项）。",
            )
            return
        if not is_preset_leaf(row):
            messagebox.showinfo(
                "诊断",
                "当前选中的是分组标题，请展开后选中具体命令（最底层一行）再执行。",
            )
            return
        if preset_auto_unlock_level(row) is not None:
            self._enqueue_preset(row)
            return
        self._fill_manual_hex_from_preset(row)

    def _on_preset_double_click(self, event: tk.Event) -> None:
        tree = self._preset_tree
        try:
            row = str(tree.identify("item", event.x, event.y) or "")
        except tk.TclError:
            row = ""
        if not row:
            row = str(tree.identify_row(event.y) or "")
        if not row or not is_preset_leaf(row):
            return
        tree.selection_set(row)
        if preset_auto_unlock_level(row) is not None:
            self._enqueue_preset(row)
            return
        if self._fill_manual_hex_from_preset(row):
            self._manual_hex_send()

    def _fill_manual_hex_from_preset(self, key: str) -> bool:
        try:
            cfg = self._effective_cfg()
            payload = resolve_preset_payload(key, cfg)
        except Exception as exc:
            messagebox.showerror("预置", str(exc))
            return False
        s = payload.hex().upper()
        pretty = " ".join(s[i : i + 2] for i in range(0, len(s), 2))
        txt = getattr(self, "_manual_hex_text", None)
        if txt is None:
            return False
        txt.delete("1.0", tk.END)
        txt.insert("1.0", pretty)
        txt.edit_modified(False)
        self._v_manual_hex.set(pretty)
        self._schedule_manual_hex_height_sync()
        self._emit_log("已填入手动发送框: %s" % pretty)
        return True

    def _manual_hex_send(self) -> None:
        tw = getattr(self, "_manual_hex_text", None)
        s = (tw.get("1.0", "end-1c").strip() if tw else self._v_manual_hex.get().strip())
        if not s:
            messagebox.showwarning("诊断", "请输入十六进制字节（可含空格）。")
            return
        self._enqueue("raw_hex", hex=s)

    def _worker_loop(self) -> None:
        while not self._worker_stop.is_set():
            try:
                item = self._cmd_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                break
            cmd, _args = item
            try:
                with self._uds_lock:
                    self._handle_cmd(cmd, _args)
            except NegativeResponseException as exc:
                try:
                    if self._diag:
                        self._emit_log(self._diag.format_negative(exc))
                    else:
                        self._emit_log("NegativeResponse: %s" % exc)
                except Exception as fmt_exc:
                    # 绝不能让负响应日志格式化错误杀死 worker 线程
                    self._emit_log("NegativeResponse: %s" % exc)
                    self._emit_log("NegativeResponse format failed: %s" % fmt_exc)
            except Exception as exc:
                self._emit_log("错误: %s" % exc)

    def _handle_cmd(self, cmd: str, args: Dict[str, Any]) -> None:
        if cmd == "preset":
            run_preset(str(args["key"]), self._require_diag(), args["cfg"])
        elif cmd == "raw_hex":
            data = parse_hex_bytes(str(args["hex"]))
            if not data:
                raise ValueError("无效的 hex")
            self._require_diag().send_raw_payload(data)
        elif cmd == "flash":
            try:
                self._do_flash(args["cfg"], args["path"])
            except FlashAborted:
                self._emit_log("刷写已中止")
            except Exception as exc:
                self._emit_log("刷写失败: %s" % exc)
            finally:
                self._ui_queue.put(("flash_done", None))
        elif cmd == "tp_tick":
            if not self._tp_active:
                return
            if self._uds_client is not None:
                try:
                    # 3E 周期保活使用抑制正响应（3E 80），减少总线回包与日志噪声
                    with self._uds_client.suppress_positive_response(wait_nrc=False):
                        self._uds_client.tester_present()
                    self._emit_log("TesterPresent OK (suppress positive response)")
                except Exception as exc:
                    self._emit_log("TesterPresent: %s" % exc)
            self._ui_queue.put(("tp_done", None))

    def _enqueue_tp_tick_delayed(self) -> None:
        self._tp_schedule_after_id = None
        if not self._tp_active:
            return
        self._enqueue("tp_tick")

    def _require_diag(self) -> DiagnosticService:
        if self._diag is None:
            raise RuntimeError("未连接")
        return self._diag

    def _do_connect(self, cfg: AppConfig) -> None:
        self._do_disconnect()
        self._emit_log("解析配置 OK，正在连接…")
        try:
            sess = DoIPSession(cfg, log=self._emit_log)
            sess.connect()
            self._doip_session = sess
            client = build_uds_client(sess.client, cfg, traffic_log=self._emit_log)
            client.open()
            self._uds_client = client
            self._diag = DiagnosticService(client, log=self._emit_log)
            self._emit_log("UDS 客户端已打开")
        except Exception:
            self._do_disconnect()
            raise

    def _do_disconnect(self) -> None:
        """关闭会话并清空引用；调用方需已持有 _uds_lock（worker 路径）。"""
        uds_client, doip_session = self._detach_transport_locked()
        self._close_transport_refs(uds_client, doip_session)

    def _detach_transport_locked(self) -> Tuple[Any, Optional[DoIPSession]]:
        """
        在 _uds_lock 保护下摘除当前传输对象并清空共享引用。
        返回摘除前对象，供锁外执行真正 close，避免持锁阻塞太久。
        """
        uds_client = self._uds_client
        doip_session = self._doip_session
        self._uds_client = None
        self._diag = None
        self._doip_session = None
        return uds_client, doip_session

    def _close_transport_refs(
        self, uds_client: Any, doip_session: Optional[DoIPSession], log_prefix: str = ""
    ) -> None:
        if uds_client is not None:
            try:
                uds_client.close()
            except Exception as exc:
                self._emit_log("%s关闭 UDS 异常: %s" % (log_prefix or "", exc))
        if doip_session is not None:
            try:
                doip_session.close()
            except Exception as exc:
                self._emit_log("%s关闭 DoIP 异常: %s" % (log_prefix or "", exc))

    def _disconnect_transport_worker(self, notify_ui: bool = True) -> None:
        """
        断开不可再走 worker 队列：worker 若卡在 UDS recv，队列里的 disconnect 永远不会执行。
        先在独立线程里关闭套接字，唤醒阻塞的 recv，再在锁内清空引用。
        _stop_tp 须在主线程先执行（仅 _disconnect / _on_close 调用本方法前应已调用）。
        """
        try:
            # 不能先等 _uds_lock：worker 可能正持锁阻塞在 recv，先关 socket 才能唤醒它。
            uds_client = self._uds_client
            doip_session = self._doip_session
            self._close_transport_refs(uds_client, doip_session, log_prefix="")
            with self._uds_lock:
                # 仅清理“这次断开前看到的对象”，避免误清空用户随后新建的连接。
                if self._uds_client is uds_client:
                    self._uds_client = None
                    self._diag = None
                if self._doip_session is doip_session:
                    self._doip_session = None
        finally:
            self._disconnecting = False
            if notify_ui:
                self._ui_queue.put(("disconnected", None))
                self._emit_log("已断开")

    def _connect(self) -> None:
        if self._disconnecting:
            self._emit_log("正在断开中，请稍后再连接。")
            return
        if self._connecting:
            return
        try:
            connect_cfg = self._effective_cfg()
        except Exception as exc:
            messagebox.showerror("配置", "配置无效: %s" % exc)
            return
        self._connecting = True
        self._connect_seq += 1
        seq = self._connect_seq
        self._stop_tp()
        self._clear_pending_cmd_queue()
        self._conn_btn.configure(state=tk.DISABLED)
        # 连接阶段也允许点「断开」来中止卡住的连接流程
        self._disconn_btn.configure(state=tk.NORMAL)
        self._status.configure(text="连接中…")
        self._status_left.configure(text="⟳ 连接中…", foreground="#fab387")
        def run_connect(this_seq: int, cfg: AppConfig) -> None:
            ok = False
            try:
                with self._uds_lock:
                    self._do_connect(cfg)
                ok = True
            except Exception as exc:
                self._emit_log("连接失败: %s" % exc)
            finally:
                # 连接过程中若用户已断开或发起了新连接，丢弃本次结果
                if this_seq != self._connect_seq:
                    if ok:
                        with self._uds_lock:
                            self._do_disconnect()
                    return
                self._connecting = False
                self._ui_queue.put(("connected", ok))

        threading.Thread(
            target=lambda: run_connect(seq, connect_cfg),
            daemon=True,
        ).start()

    def _disconnect(self) -> None:
        if self._disconnecting:
            return
        self._disconnecting = True
        self._connecting = False
        self._connect_seq += 1
        self._stop_tp()
        self._clear_pending_cmd_queue()
        self._status.configure(text="断开中…")
        self._status_left.configure(text="⟳ 断开中…", foreground="#fab387")
        self._conn_btn.configure(state=tk.DISABLED)
        self._disconn_btn.configure(state=tk.DISABLED)
        threading.Thread(
            target=lambda: self._disconnect_transport_worker(True),
            daemon=True,
        ).start()

    def _toggle_tp(self) -> None:
        if self._tp_programmatic:
            return
        if self._tp_var.get():
            self._start_tp()
        else:
            self._stop_tp(clear_checkbox=False)

    def _start_tp(self) -> None:
        self._stop_tp(clear_checkbox=False)
        self._tp_active = True
        self._tp_schedule_after_id = self.after(2000, self._enqueue_tp_tick_delayed)
        try:
            self._tp_status_label.configure(text="●", foreground="#a6e3a1")
        except Exception:
            pass

    def _stop_tp(self, clear_checkbox: bool = True) -> None:
        self._tp_active = False
        if self._tp_schedule_after_id is not None:
            try:
                self.after_cancel(self._tp_schedule_after_id)
            except Exception:
                pass
            self._tp_schedule_after_id = None
        try:
            self._tp_status_label.configure(text="○", foreground=self._theme_hint)
        except Exception:
            pass
        if clear_checkbox:
            self._tp_programmatic = True
            self._tp_var.set(False)
            self._tp_programmatic = False

    def _browse_fw(self) -> None:
        p = filedialog.askopenfilename(
            filetypes=[("Binary/Package", "*.bin;*.hex;*.zip;*.*"), ("All", "*.*")]
        )
        if p:
            self._fw_path.set(p)

    def _browse_fw_dir(self) -> None:
        p = filedialog.askdirectory()
        if p:
            self._fw_path.set(p)

    def _start_flash(self) -> None:
        path = self._fw_path.get().strip()
        if not path:
            messagebox.showwarning("刷写", "请选择固件文件或目录")
            return
        p = Path(path)
        if not (p.is_file() or p.is_dir()):
            messagebox.showerror("刷写", "路径不存在: %s" % path)
            return
        try:
            cfg = self._effective_cfg()
        except Exception as exc:
            messagebox.showerror("配置", "配置无效：\n%s" % exc)
            return
        if not messagebox.askyesno(
            "确认", "开始刷写？请确认已选对固件与配置中的地址/格式。"
        ):
            return
        self._flash_cancel.clear()
        self._flash_btn.configure(state=tk.DISABLED)
        self._cancel_flash_btn.configure(state=tk.NORMAL)
        self._prog["value"] = 0
        self._prog["maximum"] = 1
        self._v_prog_text.set("0%")
        self._update_progress_text(0, 1)
        # 刷写占用 worker 持锁；GUI 定时 3E 无法插队，临时切换为刷写线程内持续 3E 保活
        self._stop_tp(clear_checkbox=False)
        self._drop_pending_tp_ticks()
        self._emit_log("刷写任务已提交，正在准备…")
        self._enqueue("flash", cfg=cfg, path=path)

    def _cancel_flash(self) -> None:
        self._flash_cancel.set()
        self._emit_log("已请求中止刷写…")

    def _flash_reconnect_after_ecu_reset(self, cfg: AppConfig) -> Client:
        """Post HardReset: 断开、等待、再连；须在持 _uds_lock 的 worker 内调用。"""
        self._do_disconnect()
        dly = cfg.flash.post_transfer_reconnect_delay_sec
        if dly is None:
            dly = 8.0
        self._emit_log("后编程: 已断开，等待 ECU 复位 %.1fs …" % float(dly))
        deadline = time.monotonic() + float(dly)
        while time.monotonic() < deadline:
            if self._flash_cancel.is_set():
                raise FlashAborted("cancelled during post-reset wait")
            time.sleep(min(0.25, deadline - time.monotonic()))
        self._emit_log("后编程: 正在重新路由激活并打开 UDS…")
        self._do_connect(cfg)
        if self._uds_client is None:
            raise RuntimeError("重连后 UDS 客户端未建立")
        return self._uds_client

    def _do_flash(self, cfg: AppConfig, path: str) -> None:
        self._emit_log("正在准备刷写文件: %s" % path)

        def prog(cur: int, tot: int) -> None:
            self._prog_queue.put((cur, tot))

        reconnect_fn = None
        if cfg.flash.post_transfer_after_reconnect_raw_requests:
            reconnect_fn = lambda: self._flash_reconnect_after_ecu_reset(cfg)
        run_flash_download_from_path(
            self._require_diag().client,
            cfg,
            path,
            log=self._emit_log,
            cancel=self._flash_cancel,
            progress=prog,
            reconnect_after_ecu_reset=reconnect_fn,
        )
        self._emit_log("刷写完成")

    def _on_close(self) -> None:
        self._stop_tp()
        dw = threading.Thread(
            target=lambda: self._disconnect_transport_worker(False),
            daemon=True,
        )
        dw.start()
        dw.join(timeout=3.0)
        self._worker_stop.set()
        self._cmd_queue.put(None)
        self.destroy()


def main() -> None:
    _enable_windows_dpi_awareness()
    ensure_data_beside_exe()
    app = DoIPTesterApp()
    app.mainloop()
