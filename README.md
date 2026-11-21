# cmcloud-keepalive

移动云电脑（中国移动 Ecloud CloudPC）**协议级保活**的 Cloudflare Workers 移植版。

> **核心结论：保活不需要 SPICE、不需要 `uSmartView_VDI_Client.exe`、不需要图形界面。**
> 只要一次登录拿到 `accessToken`，再周期性用纯 HTTP 打两个接口，就能让云电脑认为
> "客户端还连着"，从而阻止因长时间离线触发的自动关机。
> 因此它可以完整跑在 Serverless 上：一个 Worker + 一个 KV + 一个 Cron Trigger。

- 运行时依赖 **0 个**（`devDependencies` 只有 `wrangler`）
- 纯 ESM JavaScript，**无构建步骤**：`wrangler deploy` 直接发布 `src/`
- 加密栈只用 Web Crypto（`HMAC-SHA1` / `SHA-256` / `AES-CBC`）+ 自实现 RSA（`BigInt` + 手工 DER）
- 自带管理面板（`GET /`）、JSON API（`/api/*`）、自检接口（`POST /api/diagnose`）

---

## 1. 它做什么

| 步骤 | 接口 | 作用 |
|---|---|---|
| 1 | `POST /login/verify` | 账号密码换 `accessTicket` |
| 2 | `POST /login/verifyAccessTicket` | `accessTicket` 换 `accessToken` |
| 3 | `POST /user/getDeviceInfo` | 拉桌面列表，选中目标实例 |
| 4 | `POST /resource/desktopUptime` | **保活核心**：服务端为该桌面累计在线时长 |
| 5 | `POST /session/machineConnect` | **保活辅助**：上报"客户端已连接"会话事件 |

协议细节（V2.0 HmacSHA1 签名、RSA-1024 PKCS#1 v1.5 分块加密）见
[`docs/ANALYSIS.md`](docs/ANALYSIS.md) 与 [`docs/PORTING.md`](docs/PORTING.md)。

---

## 2. 与上游的关系

本项目是 [`XM040523/ecloud-cloudpc-keepalive`](https://github.com/XM040523/ecloud-cloudpc-keepalive)
（快照 `e7faef9`，Python 3 + `requests` + `pycryptodome`）的移植，**协议常量、签名算法、
业务语义均来自上游的逆向分析成果**，在此致谢原作者。

上游快照存在三处**阻塞级缺陷**（详见 [`docs/ANALYSIS.md`](docs/ANALYSIS.md) §9），
本项目在移植的同时修掉了它们，否则"保留原有功能"无从谈起：

| 编号 | 上游问题 | 本项目的修复 |
|---|---|---|
| A | 内置 RSA 公钥是占位符（DER 282 B，1024-bit SPKI 应为 162 B），任何请求都会在 `RSA.import_key` 抛错 | 占位符保留为 `UPSTREAM_RSA_PUBLIC_KEY_PEM`；运行时公钥取自 `ECLOUD_RSA_PUBLIC_KEY`，并**主动校验可解析性**，不可解析时 `RSA_KEY_INVALID` + 面板/自检明确提示 |
| B | canonical 用 `k=v` 裸拼，`:` 未编码 → 服务端 `400 INVALID_PARAMETER` | canonical 改为 `urlencode(sorted(params))` 语义（RFC3986，`:` → `%3A`），服务端实测返回 200 |
| C | 私钥从未传入，响应解密是死代码；`body.uptimeSeconds` 恒为 0 | 支持 `ECLOUD_RSA_PRIVATE_KEY` 解密响应；未配置时返回 `{_encrypted:true}` 并由上层给出可读状态；uptime 同时兼容数字 `uptimeSeconds` 与字符串 `body`（如 `"13小时38分54秒"`） |

上游原始实现保存在 [`legacy/python/`](legacy/python/) 供对照，**未做任何修改**。

---

## 3. 快速开始

前置：Node ≥ 20、Cloudflare 账号。

```bash
# 1) 安装（只装 wrangler）
npm install

# 2) 登录 Cloudflare
npx wrangler login

# 3) 创建 KV namespace，把输出的 id 填进 wrangler.toml 的 [[kv_namespaces]].id
npx wrangler kv namespace create KEEPALIVE_KV
#   ✅ Created namespace "cmcloud-keepalive-KEEPALIVE_KV" with id "<你的 id>"

# 4) 写 4 个 secret（多行 PEM 直接粘贴，Ctrl-D / Ctrl-Z 结束）
npx wrangler secret put ECLOUD_RSA_PUBLIC_KEY    # 必填：真实 1024-bit 公钥 PEM
npx wrangler secret put ECLOUD_RSA_PRIVATE_KEY   # 可选：配了才能读出 uptime 业务字段
npx wrangler secret put ADMIN_TOKEN              # 强烈建议：/api/* 鉴权
npx wrangler secret put ECLOUD_USERNAME          # 可选：配合下一项实现自动重登
npx wrangler secret put ECLOUD_PASSWORD          # 可选

# 5) 部署
npm run deploy
```

部署后：

1. 浏览器打开 `https://cmcloud-keepalive.<你的子域>.workers.dev/`；
2. 在右上角 `ADMIN_TOKEN` 输入框填入 token（存在本机 `localStorage`）；
3. 用"账号 / 密码"表单登录一次（或只依赖 `ECLOUD_USERNAME/PASSWORD` 自动重登）；
4. 点"自检"，`signature` 一项应为 `OK` 且提示"签名已被服务端接受"；
5. 点"立即保活"，卡片区出现 `运行时长` 与 `connect 码 0` 即成功。

完整的逐步验证手册（含预期输出、回滚）见 [`docs/VERIFY.md`](docs/VERIFY.md)。

### 本地开发

```bash
npx wrangler dev            # 本地起服务，未绑 KV 时自动用进程内存储
npm test                    # 110 个用例，零网络
npx wrangler deploy --dry-run --outdir=.dryrun   # 打包自检
```

---

## 4. 环境变量

全部由 `src/config.js` 统一读取，**都有默认值**，未配置也能启动（只是不能保活）。

| 变量 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `ECLOUD_RSA_PUBLIC_KEY` | secret | **是**（实际发请求时） | 上游占位符（不可解析） | 请求体加密公钥，1024-bit SPKI PEM |
| `ECLOUD_RSA_PRIVATE_KEY` | secret | 否 | 空 | 响应体解密私钥，PKCS#1 或 PKCS#8 PEM |
| `ECLOUD_USERNAME` | secret | 二选一 | 空 | 自动重登账号 |
| `ECLOUD_PASSWORD` | secret | 二选一 | 空 | 自动重登密码 |
| `ECLOUD_INSTANCE_ID` | var / secret | 否 | 空 | 固定桌面实例；空则取列表第一个 |
| `ADMIN_TOKEN` | secret | 强烈建议 | 空 | `/api/*` 的 `Authorization: Bearer` 校验；空则放行并在 `/api/status` 标 `authDisabled:true` |
| `AUTO_RELOGIN` | var | 否 | `"true"` | 设为 `"false"` 后 token 过期只报错不重登 |

密钥相关约定：

- **绝不入库**。仓库里只有上游占位符，且 `validatePublicKey()` 会明确判定它不可解析。
- PEM 写成单行、用字面量 `\n` 分隔也可以，`config.js` 会自动还原换行。
- `/api/status` 只暴露布尔与掩码（账号 `ab***yz`、token 末 6 位），**不回显任何密钥**。

---

## 5. HTTP 接口

鉴权：`GET /api/health` 与 `GET /` 公开，其余 `/api/*` 需要 `Authorization: Bearer <ADMIN_TOKEN>`（恒定时间比较）。

| 方法 | 路径 | 作用 | 请求体 | 响应要点 |
|---|---|---|---|---|
| GET | `/` | 管理面板（内联 HTML/CSS/JS） | — | `text/html` |
| GET | `/api/health` | 存活探针 | — | `{ok,name,version,time}` |
| GET | `/api/status` | 全量状态 | — | `{configured,credentials,selected,machines,lastRun,logs,warnings,storage}` |
| POST | `/api/login` | 登录并落盘 | `{username,password}` | `{ok,errorCode?,hint?,machines?,warning?}` |
| POST | `/api/refresh` | 刷新桌面列表 | — | `{ok,machines,fetchedAt,selected}` |
| POST | `/api/select` | 选定桌面 | `{instanceId}` | `{ok,selected}` |
| POST | `/api/keepalive` | 立即执行一轮 | `{instanceId?}` | `{ok,uptimeSeconds,uptimeText,connectStatus,tokenExpired,error?,note?,stage}` |
| POST | `/api/logout` | 清除凭证 | — | `{ok}` |
| POST | `/api/diagnose` | 自检 | — | `{ok,checks:[{name,ok,detail}]}` |

状态码口径：

- `200` 业务执行完成（**包含 `ok:false` 的业务失败**：登录被拒、保活失败、未登录）
- `400` 请求体非法 / 缺字段 / `instanceId` 不存在
- `401` `ADMIN_TOKEN` 校验失败
- `404` / `405` 路由不存在 / 方法不允许
- `502` 已打到上游网关但通信失败（网络错误 / 非 2xx / 解密失败）
- `500` 未预期异常

### `POST /api/diagnose` 的五项检查

| name | 判定 |
|---|---|
| `publicKey` | 公钥是否可解析；不可解析时提示"当前公钥不可解析（疑似上游占位符），请配置 ECLOUD_RSA_PUBLIC_KEY" |
| `privateKey` | 私钥是否可解析；未配置视为 `ok:true`（可选能力） |
| `signature` | 调 `/user/getSysTime`：200 + 加密响应 → "签名已被服务端接受；响应已加密（未配置私钥，无法读取业务体）"；200 + 明文 → "签名与请求体均被接受"；400 + `INVALID_PARAMETER` → "签名被拒绝：检查 Timestamp 时钟偏移或 canonical 编码"；5xx → "签名已通过服务端校验，但请求体无法解密——通常是 ECLOUD_RSA_PUBLIC_KEY 与服务端私钥不配对"；网络异常 → "网关不可达: …" |
| `kv` | `KEEPALIVE_KV` 写探测；未绑定 KV 时用进程内存储并给出告警 |
| `token` | 是否已登录、凭证保存时间；提醒上游无 refresh token |

`ok` 为五项全部通过；任一失败都带可操作的中文 `detail`。

---

## 6. Cron 与 interval 映射

Workers 用 Cron Trigger 替代上游的 `while True: sleep(interval)`。默认 `*/5 * * * *`
（= 上游 `--interval 300`），表达式在 `wrangler.toml` 的 `[triggers].crons`。

| 期望间隔 | 上游等价参数 | cron 表达式 |
|---|---|---|
| 1 分钟（最小粒度） | `--interval 60` | `* * * * *` |
| **5 分钟（默认）** | **`--interval 300`** | **`*/5 * * * *`** |
| 10 分钟 | `--interval 600` | `*/10 * * * *` |
| 15 分钟 | `--interval 900` | `*/15 * * * *` |
| 30 分钟 | `--interval 1800` | `*/30 * * * *` |
| 1 小时 | `--interval 3600` | `0 * * * *` |

注意：

- Workers Cron 最小粒度是 1 分钟；官方不保证精确准点，可能延迟数秒。
- 建议 ≥ 5 分钟：保活不需要更高频率，且能留足 CPU 余量做 RSA 运算。
- 改完 `crons` 要重新 `npm run deploy` 才生效。
- 想临时多打一发而不等 Cron：`POST /api/keepalive`（等价上游 `--rounds 1`）。
- 单轮语义：一次 Cron = 一轮 `desktopUptime` + `machineConnect`，与上游"每轮重建客户端"不同（本项目复用同一客户端实例，更省 CPU）。

---

## 7. 行为差异与修复清单

**修复（3 项，见 §2）**：RSA 公钥占位符可诊断、canonical 做 RFC3986 编码、私钥可配置 + uptime 双形态兼容。

**有意变更（4 项）**：

1. **状态从文件改 KV**：`data/*.json` → `state:*` 键；未绑 KV 时回退进程内 `Map`（`/api/status` 标 `storage:"memory"`）。
2. **新增可观测状态**：`state:machines`（桌面缓存）、`state:lastRun`（最近一轮结果）、`state:logs`（最近 50 条日志），面板只展示最近 20 条。
3. **新增自检接口**：`POST /api/diagnose` 把"服务端是否接受签名"变成可判定的结论，代替人工看日志。
4. **新增自动重登**：`ECLOUD_USERNAME/PASSWORD` + `AUTO_RELOGIN`，解决 Serverless 无 TTY 时"token 过期只能人工重登"的运维痛点；重登后最多重跑 1 次，避免死循环。

其余细小差异（解密失败改为抛错而非静默截断、`--rounds` 语义收敛为单轮等）见
[`docs/PORTING.md`](docs/PORTING.md) §7。

---

## 8. 已知限制

- **必须自备真实公钥**：上游内置值不可解析，不配置 `ECLOUD_RSA_PUBLIC_KEY` 一定无法保活。
- **短信二次验证未实现**：`30002009` / `30002060` / `30002063` 只给出人话提示（与上游一致），需先在官方客户端完成验证。
- **没有 refresh token**：`accessToken` 过期只能重登；无 `ECLOUD_USERNAME/PASSWORD` 时需手动 `POST /api/login`。
- **不配私钥读不到 uptime 字段**：响应保持加密形态，面板显示"运行时长未知"，但这不影响保活请求本身生效。
- **KV 最终一致**：`state:logs` 是"读-改-写"，并发写可能丢日志；仅作为诊断线索，不做审计。
- **未移植 `/machine/pushConnectEventData`**：上游 README 提到但代码里也没有实现，缺少协议细节，不臆造。
- **`settingValue` 解密需要自备 hex blob**：该能力仅用于重新分析客户端配置，不参与保活。
- 云电脑侧的关机策略由服务端决定，保活频率过低仍可能被判定离线。

---

## 9. 目录结构

```
src/
├── index.js                Worker 入口：fetch 路由 + scheduled(cron)
├── config.js               env → 不可变 config（含密钥校验与告警）
├── store.js                state:* 存储抽象（KV / 内存回退）
├── keepalive.js            单轮保活编排、formatUptime、自动重登
├── api.js                  /api/* 处理器
├── dashboard.js            内联管理面板
└── ecloud/
    ├── constants.js        协议常量 + 上游占位符公钥
    ├── signature.js        RFC3986 编码、UTC+8 时间戳、canonical、签名
    ├── rsa.js              PEM/DER 解析、BigInt 模幂、PKCS#1 v1.5 分块加解密
    ├── client.js           EcloudClient（post + 6 个业务方法）
    └── setting-value.js    AES-256-CBC 解 settingValue hex blob
test/                       110 个用例（8 个文件），node:test，零网络
legacy/python/              上游原始实现（只读参照）
docs/ANALYSIS.md            上游分析与三处缺陷的实测复核
docs/PORTING.md             移植方案与行为差异
docs/VERIFY.md              部署后验证手册
```

---

## 10. 免责声明

本项目**仅供学习与研究**（协议逆向、Serverless 加密栈移植）。

- 请遵守中国移动云电脑的服务条款与所在地法律法规；由使用本项目产生的一切后果（账号被限制、
  服务被终止、费用争议等）由使用者自行承担。
- 仓库不含任何真实账号、密码或用户密钥；协议常量来自公开客户端的逆向分析。
- 作者不对服务端接口变更、可用性或数据丢失作任何保证。

## License

[MIT](LICENSE) —— 保留上游作者与移植者的版权行。
