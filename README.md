# DoIP 测试客户端（Windows）

简易 DoIP + UDS 诊断与刷写（34/36/37）客户端，带 Tkinter 图形界面。传输层基于 [doipclient](https://github.com/jacobschaer/python-doipclient)，UDS 基于 [udsoncan](https://github.com/pylessard/python-udsoncan)。

## 环境

- Windows 10/11
- **Python 3.8+**（推荐 3.11+；开发时在 3.8 上已验证依赖可安装）

## 安装

```powershell
cd e:\DoIP-Test
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## 运行

```powershell
python main.py
```

顶部可选择 **项目**（[`project_configs`](project_configs/) 下每个 `.yaml` 即一套参数）。安装包/源码已内置默认模板（如 **`N80.yaml`**、**`qirui.yaml`**），开箱可选项目再微调；也可复制改名自建新项目。**本机 IP** 可从枚举到的网卡地址中选择，写入 `network.client_bind_ip`；点 **刷新网卡** 重新扫描。

**升级工具后仍连不上、且日志里是 `proto=0x02`：** 多半是 **exe 同目录里旧的 `project_configs\\*.yaml` 仍写着 `protocol_version: 2`**（首次解压后不会自动覆盖）。请删掉该目录或对应 yaml，再运行一次 exe 会重新解压模板；或在表单「协议版本」改为 **3** 并点「表单→YAML」保存。

**日志仍显示 `logical_address=0x0001`、`client=0x0E00`（对接 192.168.118.128 台架）：** 与 DOIP_UDS **x86_server_config** 不一致；应使用 **服务端逻辑地址 0x002B (43)**、**客户端 0x0E80 (3712)**。请用仓库中最新 [`project_configs/qirui.yaml`](project_configs/qirui.yaml) 覆盖 exe 旁的 `project_configs\\qirui.yaml`，或在表单改正后点 **「YAML → 表单」** 确认并 **「表单 → YAML」** 保存；勿沿用首次解压的旧模板。

左侧为 **「表单配置」** 与 **「YAML 文本」** 两个标签页：可在表单中改 IP、逻辑地址、超时、DID、刷写地址等；**连接、读 DID、读 DTC、刷写** 会按「当前 YAML + 当前表单」合并后的结果生效。需要把表单写回文件时，用 **「表单 → YAML」** 再 **「保存 YAML」**；从文件加载后会自动 **「YAML → 表单」**。

**配置来源说明：** 程序**不会**读取仓库根目录的 `config.yaml`（旧文档习惯可忽略）。界面始终编辑并保存 **`project_configs/<项目>.yaml`**（下拉选的「项目」）；新建项目可复制 [`project_configs/qirui.yaml`](project_configs/qirui.yaml) 等改名。

## 与 DOIP_UDS 对齐

请参阅 [docs/ALIGNMENT.md](docs/ALIGNMENT.md)，并在映射 Samba 后对照你们服务端与 Wireshark 调整 **`project_configs` 里当前项目的 YAML**。

## 测试

```powershell
set PYTHONPATH=e:\DoIP-Test\src
python -m unittest discover -s tests -p "test_*.py" -v
```

## 打包为 Windows exe（双击运行）

1. 安装依赖（含打包工具）：`pip install -r requirements.txt pyinstaller`
2. 在项目根目录执行：

```powershell
.\scripts\build_windows_exe.bat
```

可选指定界面标题中的版本（格式 `yy.mm.dd.nn`，同日构建序号 **00～99**）：

```powershell
.\scripts\build_windows_exe.bat 26.05.09.03
# 或 set DOIP_APP_VERSION=26.05.09.01 后执行脚本（不带参数则写入当天 yy.mm.dd.00）
```

开发直接运行 `python main.py` 时，未设置环境变量则标题中的版本为**当天** `yy.mm.dd.00`；设置 `DOIP_APP_VERSION` 可本地模拟任意合法版本串。

使用 `scripts\build_windows_exe.bat` 时，产物文件名为 **`dist\DoIPTester_yy.mm.dd.nn.exe`**（与嵌入版本、窗口标题一致），便于区分多次打包。

打包脚本通过 `scripts\pip_no_proxy.py` 安装依赖，绕过 Windows 注册表/无效代理（浏览器能上网时 pip 仍可能 `ProxyError`）。若仍失败，请检查 **`%APPDATA%\pip\pip.ini`** 里的 `proxy` 行，或手动执行：`python scripts\pip_no_proxy.py install -r requirements.txt pyinstaller`。

或在 PowerShell 手动：

```powershell
cd e:\DoIP-Test
python -m PyInstaller --noconfirm --clean --windowed --onefile --name DoIPTester `
  --add-data "project_configs;project_configs" `
  main.py
```

生成 **`dist\DoIPTester.exe`**（若未改 `--name`）；推荐直接用 **`build_windows_exe.bat`**，得到带版本号的 **`dist\DoIPTester_yy.mm.dd.nn.exe`**。脚本会把仓库里的 **`project_configs\*.yaml`** 再拷贝一份到 **`dist\project_configs\`**，便于你对比本次打包是否带上最新模板（单文件 exe 本身不包含可直接打开的 yaml 目录）。

**打包报 `PermissionError` / 无法覆盖 exe：** 先**退出正在运行的** `DoIPTester*.exe`（及任务管理器里残留进程），再执行脚本；构建脚本会尝试结束进程名以 `DoIPTester` 开头的进程。若仍失败，检查杀毒是否锁定 `dist` 下文件，或把旧 exe 改名/删除后再打包。

首次运行会在 **exe 同目录** 生成 **`project_configs`**（从 exe 内嵌模板解压）。**若该目录已存在，程序默认不会覆盖其中的 yaml**（避免冲掉你的修改），因此只替换 exe 时，旁侧的 **`qirui.yaml` 可能仍是旧内容**。解决办法任选其一：删掉 exe 旁的 **`project_configs`** 后重新运行；用仓库/ **`dist\project_configs`** 里的文件手动覆盖；或在启动前设置环境变量 **`DOIP_REFRESH_PROJECT_YAML=1`** 强制用 exe 内嵌模板覆盖一份。杀毒软件可能误报「未签名 exe」，按需加白名单。

## 连接失败（DoIP Negative Acknowledge / NACK）

若日志出现 **`NACK Code: 0`**（IncorrectPatternFormat），多为：**DoIP 协议版本**与对端不一致——在表单或 YAML 中将 **`doip.protocol_version` 改为 `3`**（对应 ISO 2019 常用 `0x03`）后再试；仍失败则确认 **13400 上是否为明文 DoIP**（TLS 一般为 **3496**）、目标 IP 与 **ECU 逻辑地址**是否正确。

若 **`protocol_version=3`** 后变为 **`ECU failed to respond in time`**：多为 **路由激活等待超时**（第三方库单次读默认仅约 **2 秒**）。本工具已用 **`doip.socket_read_timeout`**（表单「路由读超时」或 YAML，默认未填时程序内 **10s**，模板里常用 **15s**）拉长等待；仍超时可调到 **20～30**，并确认 **本机 IP** 与 ECU 同网段。

**本机 IP**：请选与 ECU **同一网段或可路由**的地址；尽量避免仅选 **169.254.x.x**（APIPA），除非确定走该接口。

## 说明

- 网络与诊断操作在后台线程执行，避免阻塞界面；**TesterPresent** 与按钮操作共享同一把锁，避免并发访问 UDS 客户端。
- 清 DTC、ECU 复位、刷写等操作在界面中会要求确认。
- 刷写流程依赖 ECU 对 `RequestDownload` 的地址/长度格式及 `maxNumberOfBlockLength` 的约定，请通过配置中的 `address_format`、`memorysize_format`、`override_block_payload` 与实机对齐。
- 刷写默认顺序：**Extended →（可选 `pre_transfer_raw_requests` / `pre_transfer_routines`）→ Programming → L3（0x11）解锁 →（可选 `fingerprint_did`/`fingerprint_data`）→ 0x34/36/37 →（可选 `post_transfer_routines` / `post_transfer_raw_requests`）**。可用于挂接图 5/6/7 的 OEM 前置、验签和后处理步骤。
- UDS 客户端按协议跟随 ECU 侧 server timing（`use_server_timing=true`）。刷写进行时界面「TesterPresent 每 2s」会暂停，由刷写线程按固定 2s 间隔发 **3E 80** 保活；结束后再恢复勾选。
