# 上游项目分析：ecloud-cloudpc-keepalive

> 分析对象：<https://github.com/XM040523/ecloud-cloudpc-keepalive>
> 快照提交：`e7faef9`（作者 `xm040523`，2026-06-21）、分支 `main`
> 分析方法：全量源码阅读 + Node/OpenSSL 解析校验 + 对线上网关的实测请求（仅 5 次，均为无凭证的公开端点）

---

## 1. 项目用途

移动云电脑（中国移动 Ecloud CloudPC）客户端在断开连接一段时间后会自动关机。该项目通过**逆向 Windows 客户端 V3.8.2**，复刻其 HTTP 协议栈，用纯 Python 定时调用两个接口来"占住"桌面会话，从而阻止自动关机（即"保活"，Keep-Alive）。

适用场景：云电脑上跑长时间任务、挂机、远程实验环境需要维持开机。

设计目标是**协议级**保活：不依赖官方客户端进程、不依赖 SPICE 协议、不需要 `uSmartView_VDI_Client.exe`、不需要图形界面，只要一次登录拿到的 `accessToken` + 一个 `instanceId`，就能用纯 HTTP 维持会话。

---

## 2. 目录结构

仓库极小，只有 4 个文件、约 39 KB，无子目录、无测试、无 CI：

```
ecloud-cloudpc-keepalive/
├── main.py            9,402 B   CLI 入口：参数解析、交互式登录、保活循环、运行时长格式化
├── protocol.py       12,389 B   协议层：常量、时间戳、签名、RSA 加解密、设备指纹、HTTP 客户端
├── requirements.txt      43 B   requests>=2.28.0 / pycryptodome>=3.18.0
└── README.md         17,282 B   背景、协议逆向过程、技术原理、常量表、踩坑记录
```

运行期自动生成（`.gitignore` 未提供，实际会被提交进 Git）：

```
data/
├── credentials.json         {"username", "accessToken", "savedAt"}
├── device.json              设备指纹（首次自动生成后固化）
└── selected_instance.json   {"instanceId", "machineId", "machineName"}
```

---

## 3. 依赖

| 依赖 | 版本 | 用途 |
|---|---|---|
| `requests` | >=2.28.0 | HTTP 会话、JSON 提交、30s 超时 |
| `pycryptodome` | >=3.18.0 | RSA PKCS#1 v1.5 加解密、AES-256-CBC（settingValue 解密） |
| 标准库 | — | `hashlib`(SHA-256)、`hmac`(SHA-1)、`base64`、`uuid`、`json`、`argparse`、`datetime` |

纯同步阻塞实现，无异步、无重试、无连接池调优。

---

## 4. 核心功能

| # | 功能 | 实现位置 |
|---|---|---|
| 1 | **密码登录**：`/login/verify` 换 `accessTicket` → `/login/verifyAccessTicket` 换 `accessToken` | `protocol.py:286-311`、`main.py:35-98` |
| 2 | **RSA-1024 PKCS#1 v1.5 分块加密**（117 字节/块）请求体，`base64` 后塞进 `{"params": ...}` | `protocol.py:133-140` |
| 3 | **RSA 分块解密**响应体（128 字节/块）——**代码中存在但从未被启用** | `protocol.py:143-155` |
| 4 | **V2.0 HmacSHA1 签名**：`BC_SIGNATURE&` 前缀盐 | `protocol.py:85-122` |
| 5 | **桌面列表**：`/user/getDeviceInfo` → `body.machineList[]` | `protocol.py:313-325` |
| 6 | **桌面保活**：`/resource/desktopUptime` + `/session/machineConnect` | `protocol.py:327-355` |
| 7 | **全自动配置**：设备指纹自动生成固化、桌面自动拉取、单实例自动选中 | `protocol.py:187-210`、`main.py:100-133` |
| 8 | **逆向辅助**：从客户端 `settingValue.js` 的 hex blob 派生 AES 密钥并解密配置 | `protocol.py:162-180` |

CLI 只有两个子命令：

- `python main.py login` —— 交互式输入账号密码，落盘三个配置文件；
- `python main.py desktop-keepalive [--rounds N] [--interval S] [--loop]` —— 读配置、循环保活。

---

## 5. 运行流程

### 5.1 登录（一次性）

```
输入 username/password
  → POST /login/verify          {username, password, timestamp, clientNeedTwoFactor:true}
       ├─ body.accessTicket      → 成功
       ├─ errorCode 30002009     未授信设备（需短信）
       ├─ errorCode 30002060     二次验证（需短信）
       └─ errorCode 30002063     增强策略（需短信）
  → POST /login/verifyAccessTicket {accessTicket}
       └─ body.accessToken
  → 写 data/credentials.json
  → POST /user/getDeviceInfo    {accessToken, companyCode, allCompany:true, version:"1.0.0"}
       └─ body.machineList[]  → 打印列表 → 选序号 → 写 selected_instance.json
  → POST /user/getSysTime       验证签名/连通性
```

三种短信验证分支在 `main.py` 中**只打印提示，未实现**（README 亦标注 4A MFA 未实现）。

### 5.2 保活（周期性）

```
读 credentials.json + selected_instance.json（缺失则自动拉列表取第 0 个）
while true:
    http = EcloudHTTP(access_token)          # 每轮重建，重读 device.json
    POST /resource/desktopUptime {instanceId}   → body.uptimeSeconds
    POST /session/machineConnect {instanceId, machineId} → errorCode
    打印 "[时间] Round #n | Uptime: x小时y分z秒 | Connect: 0"
    若 errorCode != 0 且 errorMsg 含 token/expire/expired → 判定 token 过期并退出
    sleep(interval) 或 结束
```

`--loop` 才是死循环；不加时无论 `--rounds` 多少都只跑 1 轮（`main.py:213-221` 的逻辑分支，`rounds` 实际只在非 loop 模式下被当作 1 使用）——这是一处行为瑕疵，移植时以"单轮/循环"语义为准并保留参数兼容。

---

## 6. 配置项

代码内硬编码，无环境变量、无配置文件：

| 常量 | 值 | 说明 |
|---|---|---|
| `BASE_URL` | `https://cloudpc.ecloud.10086.cn` | 网关域名 |
| `API_PATH` | `/api/cem/gateway/outer/cem-webapi` | 统一路由前缀 |
| `ACCESS_KEY` | `53bb79015a3f47c4be166d9371f68f14` | 签名 AccessKey |
| `SECRET_KEY` | `6b0d3b93f3aa4c7ea076c841bead1ddd` | HmacSHA1 密钥 |
| `HMAC_PREFIX` | `BC_SIGNATURE&` | 固定盐前缀 |
| `COMPANY_CODE` | `ECloud` | 业务参数 |
| `CLIENT_VERSION` | `3.8.2` | 伪装客户端版本 |
| `PLATFORM` | `win32` | 仅用于 settingValue 密钥派生 |
| `RSA_PUBLIC_KEY_PEM` | 1024-bit SPKI | **占位符，不可解析（见 §9）** |

用户可调项只有 CLI 的 `--rounds` / `--interval` / `--loop`。

---

## 7. 保活机制

保活不依赖长连接，本质是**周期性 HTTP 心跳 + 会话登记**：

1. **`/resource/desktopUptime`（核心）**
   请求体只有一个 `instanceId`。服务端据此把该桌面实例标记为"有活跃客户端"，并返回累计在线时长。README 的实测记录显示：间隔 5 秒连续调用，返回的运行时长逐次 +5 秒，证明服务端确实在为该会话累计在线时长，而非返回缓存值。这是保活能成立的关键证据。

2. **`/session/machineConnect`（辅助）**
   带 `instanceId` + `machineId` 上报"客户端已连接到这台机器"的会话事件，等价于官方客户端点击"连接"时发的那一发请求。它不建立真正的桌面隧道（那属于 SCG/SPICE，在原生二进制里），只做业务侧登记。

3. **`/machine/pushConnectEventData`（README 提及，代码未实现）**
   连接事件上报，连接时 1 次。代码未包含，属未移植项。

4. **失效边界**
   `accessToken` 过期后两个接口都会返回非 0 `errorCode`，工具检测到 `errorMsg` 含 `token`/`expire` 就退出，要求重新 `login`。**没有 refresh token 机制，无法自动续期**——这是原项目最大的运维痛点，也是移植到 Serverless 后必须解决的点（无 TTY 可交互）。

---

## 8. 关键模块关系

```
                    ┌──────────────────────────────┐
                    │           main.py            │
                    │  argparse / 交互 / 循环调度   │
                    │  format_uptime()             │
                    └───────┬──────────────┬───────┘
            调用协议方法     │              │  读写 JSON
                            ▼              ▼
              ┌──────────────────────┐  ┌────────────────────┐
              │     protocol.py      │  │       data/        │
              │ ┌──────────────────┐ │  │ credentials.json   │
              │ │ 常量/时间戳       │ │  │ device.json        │
              │ ├──────────────────┤ │  │ selected_instance  │
              │ │ build_signature  │ │  └────────────────────┘
              │ │ compute_signature│ │            ▲
              │ ├──────────────────┤ │            │ 设备指纹
              │ │ rsa_encrypt      │ │  ┌─────────┴──────────┐
              │ │ rsa_decrypt      │ │  │ load_or_create_    │
              │ ├──────────────────┤ │  │ device_config()    │
              │ │ derive_aes_key   │ │  └────────────────────┘
              │ │ decrypt_setting  │ │
              │ ├──────────────────┤ │
              │ │ class EcloudHTTP │ │─── requests.Session ──▶ cloudpc.ecloud.10086.cn
              │ │  .post()         │ │        (POST + 签名查询串 + RSA body)
              │ │  .login_with_... │ │
              │ │  .desktop_uptime │ │
              │ │  .machine_connect│ │
              │ └──────────────────┘ │
              └──────────────────────┘
```

依赖方向严格单向：`main.py → protocol.py`，协议层不反向依赖 CLI；持久化以模块级常量路径（`DEVICE_CONFIG_DIR` 等）耦合在 `protocol.py` 顶部，`main.py` 直接 `from protocol import CREDS_PATH` 复用路径。**这是移植时最需要解耦的地方**：Workers 没有可写文件系统，路径常量必须换成存储抽象。

单次请求的完整构造链：

```
业务参数 ─┐
commonParams ├─▶ 合并 accessToken ─▶ JSON ─▶ RSA(117B/块) ─▶ base64 ─▶ {"params": b64}
设备指纹 ─┘                                                                    │
                                                                               ▼
AccessKey/SignatureMethod/SignatureNonce/SignatureVersion/Timestamp ─▶ canonical │
                                                                      │        │
                                          sha256(canonical) ──────────┤        │
                                                                      ▼        │
                        "POST\n" + quote(apiPath+endpoint) + "\n" + hash        │
                                          │                                     │
                        HmacSHA1(key="BC_SIGNATURE&"+secret) ─▶ Signature       │
                                          │                                     │
                                          ▼                                     ▼
        POST {BASE_URL}{API_PATH}{endpoint}?{canonical}&Signature={sig}   body={"params":...}
                                          │
                                          ▼
                         响应 {"params": b64} ─▶ RSA 私钥分块解密 ─▶ JSON
```

---

## 9. 实测复核：三个会导致"开箱不可用"的缺陷

我用独立实现（Python 标准库 `hmac`/`hashlib` + Node `crypto`）对仓库代码做逐项复核，并对线上网关发了 5 次无凭证请求。结论：**仓库当前快照不能直接跑通**，存在 3 处阻塞级问题。

### 缺陷 A：RSA 公钥是占位符（阻塞所有请求）

`protocol.py:45-52` 的 PEM 解 base64 后是 **282 字节**，而 1024-bit SPKI 公钥应为 **162 字节**；OpenSSL 报 `digital envelope routines::decode error`，任意截断长度（162/163/164）均无法解析，公钥模数区内还残留 `nLkGj8xJBH5iH5R3JXqK7lJn` 的重复填充串。即：作者发布前把真实公钥替换掉了。

后果：`rsa_encrypt()` 第一行 `RSA.import_key(...)` 就抛异常，`post()` 无法发出任何请求。

### 缺陷 B：签名规范化未做 URL 编码（服务端判签名非法）

`protocol.py:103` 用 `"&".join(f"{k}={v}")` 拼 canonical，时间戳里的 `:` 保持原样。而服务端要求 canonical 是 `urlencode(sorted(params))`，`:` 必须是 `%3A`。

实测对照（端点 `/user/getSysTime`，同一组参数，仅 canonical 编码方式不同）：

| 变体 | 结果 |
|---|---|
| 原始拼接（上游实现） | `400 {"errorCode":"INVALID_PARAMETER","errorMessage":"Invalid parameter Signature "}` |
| `urlencode(sorted(...))` | **`200` + `{"params": "<RSA 密文>"}`** |

这一条同时带来好消息：**签名算法本身是对的，且线上网关可直连**（约 0.5s 响应）。`200` 意味着 AccessKey/SecretKey、`BC_SIGNATURE&` 盐、`quote(apiPath+endpoint, safe="")`、`Timestamp` 的 UTC+8 语义全部被服务端接受，可以作为移植后"部署验证"的客观依据。

### 缺陷 C：私钥从未传入，响应解密分支是死代码

`main.py` 全部 3 处 `EcloudHTTP(...)` 构造都没传 `rsa_private_key_pem`，`protocol.py:275` 的 `if "params" in result and self.rsa_private_key_pem` 永远为假 → 返回的是 `{"params": "..."}` 原始密文，`result.get("body", {})` 永远取不到业务字段。

连带后果：`main.py:192` 读 `body.uptimeSeconds` 恒为 0，日志永远打印 `Uptime: 0秒`；而 README 展示的响应是 `{"body": "13小时38分54秒"}` 字符串，与代码假设的数字字段也不一致。**"保活是否生效"在原工具里其实无法从日志判断。**

### 其他不一致

- `--rounds` 在非 `--loop` 模式下不起作用（恒为 1 轮）；
- 每轮重建 `EcloudHTTP` 并重读 `device.json`，无连接复用；
- 无重试、无退避、无日志落盘，异常仅 `print`；
- `decrypt_setting_value()` 依赖仓库里并不存在的 hex blob，属纯逆向辅助函数；
- 仓库无 `.gitignore`、无测试、无 License 文件（README 声明 MIT）。

---

## 10. 对移植的直接影响

1. **密码学必须自实现或换库**：Workers 的 Web Crypto 支持 `HMAC-SHA1`、`SHA-256`、`AES-CBC`，但**不支持 RSA PKCS#1 v1.5 加密**（只有 RSA-OAEP）。1000 行级别的 `node-forge` 引入成本与 Workers 打包风险都不划算，本项目用 `BigInt` 直接实现 1024-bit 模幂 + PKCS#1 v1.5 填充（约 80 行，零依赖），并用 Node `crypto` 做交叉验证。
2. **文件 → KV**：`data/*.json` 三件套映射为 KV 键；设备指纹一次生成后固化，语义不变。
3. **`while True: sleep()` → Cron Trigger**：Workers 无法常驻，`--interval 300` 映射为 Cron `*/5 * * * *`；`--rounds 1` 映射为手动触发的 `POST /api/keepalive`。
4. **交互式 `input()` → HTTP API + 面板**：`login` 改为 `POST /api/login`，并支持用环境变量注入账号密码以支持无人值守重登（原项目必须人工重登，这是 Serverless 下的必要适配）。
5. **必须修掉 A/B/C 三个缺陷**才能"保留原有功能"——因为原功能在当前快照下本就不可用。修复项会单独列在 `docs/PORTING.md` 的行为差异表中。
6. **密钥必须外置**：真实公钥/私钥不能进仓库，走 `wrangler secret put`；仓库内置上游占位符作为默认值，并在 `/api/diagnose` 中显式报"密钥不可解析"。
