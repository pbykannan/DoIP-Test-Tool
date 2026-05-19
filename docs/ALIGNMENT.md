# 与 DOIP_UDS 服务端对齐检查清单

在 Windows 上映射 Samba 后，用本清单对照你们的 **DOIP_UDS** 实现与 Wireshark 抓包，确保客户端参数一致。

## 1. 网络与端口

- TCP 目标端口是否为 **13400**（ISO 默认）或自定义端口。
- UDP 发现端口是否与 TCP 一致（部分 VM/实现使用非标准端口）。
- 是否需要 TLS（`doipclient` 的 `use_secure` / 端口 **3496**）。

## 2. DoIP 头与协议版本

- `protocol_version`：常见为 **0x02**（2012）或 **0x03**（2019）。与你们栈里组包使用的版本字节一致。
- 负载类型（Payload type）是否仅使用标准 **0x0005** 路由激活、**0x8001** 诊断报文等。

## 3. 逻辑地址与路由激活

- **客户端逻辑地址**（`client_logical_address`）：规范上常为 `0x0E00`–`0x0FFF`，与你们示例中的 tester 地址一致。
- **服务端/ECU 逻辑地址**（`server_logical_address` / `ecu_logical_address`）：与 `examples` 中配置一致。
- **ActivationType**：`Default (0x00)`、`DiagnosticRequiredByRegulation (0x01)`、`CentralSecurity (0xE1)` 等；若你们使用 `None` 跳过激活，在本工具配置中设 `activation_disabled: true`。
- **Routing activation 负载长度**：ISO 允许 **7 字节**（源地址 + 激活类型 + 保留区）或 **11 字节**（再含 **vm_specific** 四字节）。`python-doipclient` 在 **`vm_specific is None`** 时组 **7** 字节；为 **`0` 或非空整数** 时组 **11** 字节。若你们栈（如 **CICVD**）宏定义为 **`CICVD_DOIP_PAYLOADLENGTH_ROUTING_ACTIVE_REQ = 0x0B`（11）**，客户端必须走 **11 字节** 格式——本工具对 YAML 里 **`vm_specific: null`** 会在连接时 **默认改为 `0`**，保证与常见 OEM 期望一致；需在 Wireshark 里核对整体帧长是否为 **11**。

## 4. UDS 与传输

- **P2 / P2*** 超时：可在本工具 **`project_configs` 里所选项目 YAML** 的 `uds.request_timeout` 等中调节，与 ECU 能力匹配。
- **地址与长度格式**（`server_address_format` / `server_memorysize_format`）：`RequestDownload` / `ReadMemoryByAddress` 等是否与你们栈约定一致（8/16/24/32/40 bit）。

## 5. 验证步骤建议

1. 运行你们 `examples` 中的服务端，记录 IP、端口、逻辑地址、激活类型。
2. 使用本工具连接；若失败，用 **Wireshark** 过滤 `tcp.port == <端口>`，对比 **Routing activation request/response** 与 **Diagnostic message** 十六进制与 DOIP_UDS 源码是否一致。
3. 逐项调整 **`project_configs` 下对应 YAML** 后重试，把最终可用配置保存为团队默认模板。

## 6. Samba 路径（本机已映射时）

- DOIP_UDS 根目录：`Z:\code\DOIP-UDS_dev\DOIP_UDS`
- examples 目录：`Z:\code\DOIP-UDS_dev\DOIP_UDS\examples`

C 侧参考客户端为 `examples\main-client.c`，服务端为 `examples\main-service.c`；配置可对照仓库内 `configs\x86_client_config.xml` 等（相对路径以示例程序工作目录为准）。

### 6.1 C 示例中的默认参数（`main-client.c`）

与 Python 工具 **`project_configs/*.yaml`**（如 `qirui.yaml`）对应关系如下，**以你当前台架/ECU 为准**，这里仅作快速起步：

| 项 | C 示例默认值 | Python 配置字段 |
|----|--------------|-----------------|
| 服务器 IP | `192.168.10.43` | `network.host` |
| TCP 端口 | `13400` | `network.tcp_port` |
| 目标逻辑地址 | `0x002B` | `doip.server_logical_address` |
| 无协商时的块大小回退 | `1024` 字节 | `flash.override_block_payload`（可选） |
| 路由相关超时 | `5000` ms | 由 `doipclient` 连接行为体现；可结合抓包调 |
| 服务层超时 | `15000` ms（含多帧 NRC 0x78） | `uds.request_timeout` 等 |

说明：示例里还定义了内部/扩展 SID（如 `0xF0`、`0x38` 等）用于与栈内回调配合，**标准 UDS 刷写仍是 0x34/0x36/0x37**；若实车协议走 OEM 文件传输服务，需另加专用实现，与当前 Python 工具中的 `udsoncan` 34/36/37 路径不同。

### 6.2 `configs/x86_server_config.xml`（服务端）与 Python 字段对照

服务端 `<doip_configuration>` 里命名与「客户端该填谁」容易搞反，按下表对齐（以仓库当前服务端为准）：

| 服务端 XML 标签 | 含义 | Python `config` / 表单 |
|-----------------|------|-------------------------|
| `ip_address` | ECU/栈监听 IP | `network.host` |
| `protocol_version`（如 `0x03`） | DoIP 头版本字节 | `doip.protocol_version`（填 `3`） |
| `source_logic_address`（如 `0x002B`） | **ECU 自身**逻辑地址 | `doip.server_logical_address`（十进制 `43`） |
| `target_logic_address`（如 `0x0E80,...`） | 允许的**诊断仪/客户端**源地址列表 | `doip.client_logical_address` 须为其中一项（常用 `0x0E80` → `3712`） |
| `function_logic_address`（如 `0xE400`） | **功能寻址**（UDS），非 TCP 连接里的「目标 IP」 | 物理连接仍指向 ECU；功能寻址需在 UDS 层使用，本工具首版以物理寻址为主 |

**常见错误**：把 `server_logical_address` 填成 `1`（`0x0001`）。若服务端 ECU 是 `0x002B`，客户端必须填 **`43`**，否则会路由激活失败或 NACK。

`configs/x86_client_config.xml` 是给 **C 参考客户端**用的另一套 IP（如 `192.168.10.101`），与 **x86_server_config.xml** 的 `192.168.118.128` 不同场景；连台架服务端时请以 **server_config** 为准。

## 7. 其他成品工具（仅对照）

测试同事提供的 `E:\北汽N80\doip-process\调试工具\测试小工具V0.6_12.11.exe` 可作为**黑盒行为参考**（能连上时对比：路由激活、会话、DID、刷写结果）。本仓库无法从 exe 反推实现；若需与之一致，建议用 **Wireshark** 同时抓 C 示例、小工具、本工具三者的 **DoIP/UDS 十六进制** 做差异表，再改 **`project_configs` 项目 YAML** 或扩展代码。