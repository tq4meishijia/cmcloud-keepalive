# 移植说明：Python CLI → Cloudflare Workers

> 上游：[`XM040523/ecloud-cloudpc-keepalive`](https://github.com/XM040523/ecloud-cloudpc-keepalive) @ `e7faef9`
> 本实现：纯 ESM JavaScript，运行时零依赖，`wrangler deploy` 直接发布。
> 上游分析见 [`ANALYSIS.md`](ANALYSIS.md)，部署验证见 [`VERIFY.md`](VERIFY.md)。

---

## 1. 移植原则

1. **协议层逐字节对齐**：常量、时间戳语义、签名拼接、RSA 分块、请求体字段顺序全部照抄，不做"优化"。
2. **只替换运行时**：文件系统 → KV，常驻循环 → Cron，`input()` → HTTP，其余行为保持不变。
3. **阻塞缺陷必须修**：上游快照在真实网关上开箱不可用（见 §7.1），不修就等于没移植功能。
4. **不臆造接口**：短信二次验证、`pushConnectEventData` 缺协议细节，只保留提示，不猜实现。
5. **可测性优先**：时钟、HTTP、客户端工厂、日志全部可注入，`npm test` 零网络。

---

## 2. 运行时差异映射（Python 对象 → Workers 对象）

| 上游 Python | 本实现 JavaScript | 说明 |
|---|---|---|
| `requests.Session()` | `fetch(url, init)` | 无连接复用；每请求新建 `AbortSignal.timeout(30000)` |
| `resp.raise_for_status()` | `if (!response.ok) throw new EcloudError(..., {status, body})` | 错误体截断前 500 字符 |
| `datetime.now(timezone(timedelta(hours=8)))` | `new Date(Date.now() + 8*3600e3).toISOString()` | 不依赖运行环境时区 |
| `uuid.uuid4().hex` | `crypto.randomUUID().replace(/-/g, "")` / `randomNonce(16)` | 32 位小写十六进制 |
| `hashlib.sha256(...).hexdigest()` | `crypto.subtle.digest("SHA-256", bytes)` | 手写 hex 转换 |
| `hmac.new(key, msg, hashlib.sha1)` | `crypto.subtle.importKey("raw", k, {name:"HMAC",hash:"SHA-1"})` + `sign` | Web Crypto 不提供同步 HmacSHA1 |
| `base64.b64encode/b64decode` | `btoa/atob` + `Uint8Array` | `btoa` 分 32 KiB 片，避免参数上限 |
| `json.dumps(obj, separators=(",",":"))` | `JSON.stringify(obj)` | 输出一致，键序按插入序 |
| `RSA.import_key(pem)` | `parsePublicKey` / `parsePrivateKey`（手工 DER） | 见 §3 |
| `PKCS1_v1_5.new(key).encrypt` | `rsaEncryptPkcs1v15`（`BigInt` modPow） | Web Crypto 只有 RSA-OAEP |
| `PKCS1_v1_5.new(key).decrypt` | `rsaDecryptPkcs1v15` | 填充非法改抛错，见 §7.3 |
| `AES.new(key, MODE_CBC, iv)` + `unpad` | `crypto.subtle.decrypt({name:"AES-CBC"})` | Web Crypto 自动剥 PKCS#7 并在非法时抛错 |
| `os.path.join(__file__, "data")` | KV 绑定 `KEEPALIVE_KV`（键前缀 `state:`） | 无 KV 时回退模块级 `Map` |
| `print(...)` | `console.log` + `state:logs` | `wrangler tail` 可实时观察 |
| `argparse` + `input()` | `POST /api/login`、`POST /api/select` + 面板 | 无 TTY |
| `while True: time.sleep(interval)` | `[triggers].crons` | 见 §5 |
| `sys.exit(1)` | `{ok:false, stage, error}` 结构化返回 | 不杀进程，Cron 不抛错 |

---

## 3. 加密栈映射

| 能力 | 上游 | 本实现 | 备注 |
|---|---|---|---|
| HmacSHA1 | `hmac` + `hashlib.sha1` | `crypto.subtle` HMAC/SHA-1 | 签名前缀 `BC_SIGNATURE&` |
| SHA-256 | `hashlib.sha256` | `crypto.subtle.digest` | canonical 摘要 |
| RSA PKCS#1 v1.5 加密 | `pycryptodome` | `src/ecloud/rsa.js` 自实现 | Workers 无此算法 |
| RSA PKCS#1 v1.5 解密 | `pycryptodome` | 同上 | 只解析 n/e/d，不做 CRT |
| DER 解析 | `pycryptodome` | 80 行 `readTLV` + 结构嗅探 | 支持 SPKI / PKCS#1 / PKCS#8 |
| 模幂 | C 实现 | `BigInt` 平方-乘（MSB 起） | 单块 1024-bit 解密 < 20ms（实测 ~16ms） |
| AES-256-CBC | `pycryptodome` | `crypto.subtle` | 仅用于 settingValue |

RSA 关键参数：

- 明文分块 `k - 11`（k=128 → 117 B），密文分块 `k`（128 B）；**从密钥位长推导**而非硬编码，
  这样即使误配 2048-bit 密钥也不会产生错位块。
- 填充：`EM = 00 || 02 || PS || 00 || M`，`PS` 长 `k - 3 - mLen`，随机源 `crypto.getRandomValues`
  且**过滤 0x00**（必要时重抽）。
- 去填充校验：`EM[0]==0x00 && EM[1]==0x02`、首个 `0x00` 分隔符位置 `>= 10`（即 PS ≥ 8 字节）。

---

## 4. 存储映射

| 上游文件 | 本实现 KV 键 | 内容 |
|---|---|---|
| `data/device.json` | `state:device` | `{deviceUid, deviceId, deviceName:"Ecloud-Keepalive", osType:"linux", osVersion:"5.10.134", arch:"x86_64", clientVersion, companyCode}` |
| `data/credentials.json` | `state:credentials` | `{username, accessToken, savedAt}`（savedAt 为 UTC+8 文本） |
| `data/selected_instance.json` | `state:selected` | `{instanceId, machineId, machineName}` |
| —（新增） | `state:machines` | `{items:[{instanceId,machineId,machineName,status}], fetchedAt}` |
| —（新增） | `state:lastRun` | `{ts, ok, uptimeSeconds, uptimeText, connectStatus, tokenExpired, error}` |
| —（新增） | `state:logs` | 最近 50 条 `{ts, level, msg}` |
| —（新增） | `state:probe` | 自检写探测键，用完即删 |

差异说明：

- 设备指纹**首次生成后固化**（与上游 `load_or_create_device_config` 语义一致）。
- 未绑定 `KEEPALIVE_KV` 时使用**模块级** `Map`（不是每请求新建，否则状态立刻丢失）；
  `/api/status` 的 `storage` 字段会标 `memory`，面板显示"进程内存（仅调试）"。
- `state:logs` 是读-改-写，KV 无原子追加，并发写可能丢日志——只作为诊断线索，不做审计。

---

## 5. 调度映射

| 上游 | 本实现 |
|---|---|
| `python main.py desktop-keepalive --loop --interval 300` | Cron `*/5 * * * *`（`wrangler.toml`） |
| `python main.py desktop-keepalive --rounds 1` | `POST /api/keepalive` |
| `python main.py login` | `POST /api/login`（或面板登录表单） |
| 交互式选桌面（`input()` 序号） | `POST /api/select {instanceId}`（或面板下拉） |
| `--rounds N`（可循环 N 次） | 不移植：Workers 无常驻进程，N 次 = 等 N 个 Cron 周期 |
| token 过期后 `sys.exit(1)` 等人工介入 | `AUTO_RELOGIN` + `ECLOUD_USERNAME/PASSWORD` 自动重登，最多重跑 1 次 |

`--interval` ↔ cron 对照表见 [README §6](../README.md#6-cron-与-interval-映射)。

---

## 6. 逐文件对应关系

| 上游 | 本实现 | 说明 |
|---|---|---|
| `protocol.py:35-52` 常量 | `src/ecloud/constants.js` | 含 `UPSTREAM_RSA_PUBLIC_KEY_PEM` 占位符 |
| `protocol.py:69-78` 时间戳 | `src/ecloud/signature.js` `utc8Timestamp` / `utc8NowText` | |
| `protocol.py:85-122` 签名 | `src/ecloud/signature.js` `buildSignatureParams` / `canonicalize` / `computeSignature` / `buildSignedQuery` | **修掉缺陷 B** |
| `protocol.py:125-155` RSA | `src/ecloud/rsa.js` | 自实现，含 `validatePublicKey` / `validatePrivateKey` |
| `protocol.py:158-180` settingValue | `src/ecloud/setting-value.js` | `deriveSettingKey` / `decryptSettingValue` |
| `protocol.py:187-210` 设备指纹 | `src/store.js` `createDeviceFingerprint` / `ensureDevice` | 文件 → KV |
| `protocol.py:217-355` `EcloudHTTP` | `src/ecloud/client.js` `EcloudClient` | 去掉文件系统耦合，状态由外部注入 |
| `main.py:26-33` banner | `src/dashboard.js` | 变成管理面板头部 |
| `main.py:35-141` `cmd_login` | `src/keepalive.js` `login` + `src/api.js` `/api/login` | 返回结构化结果，不 `sys.exit` |
| `main.py:144-221` `cmd_desktop_keepalive` | `src/keepalive.js` `runKeepaliveRound` + `src/index.js` `scheduled` | 单轮函数 + Cron 驱动 |
| `main.py:224-238` `format_uptime` | `src/keepalive.js` `formatUptime` | 逐字对齐，见下表 |
| `main.py:241-269` argparse | `src/index.js` 路由 + `wrangler.toml` | |
| — | `src/config.js` | 上游无配置层，全部硬编码 |
| — | `src/api.js` | 上游无 HTTP 层（CLI） |

`formatUptime` 对齐用例（`npm test` 已锁定）：

| 输入 | 输出 |
|---|---|
| `0` | `0秒` |
| `59` | `59秒` |
| `60` | `1分钟0秒` |
| `3600` | `1小时0秒` |
| `3661` | `1小时1分钟1秒` |
| `86400` | `1天0秒` |
| `90061` | `1天1小时1分钟1秒` |

---

## 7. 行为差异表

### 7.1 三个阻塞级缺陷的修复

| 编号 | 上游 | 本实现 | 影响面 |
|---|---|---|---|
| A | 内置公钥不可解析，任何请求在 `RSA.import_key` 抛错 | 占位符改名保留；运行时取 `ECLOUD_RSA_PUBLIC_KEY`；`validatePublicKey` 强校验（外层 SEQUENCE 长度必须等于 DER 总长）；不可解析时抛 `RSA_KEY_INVALID` 并携带"请配置 ECLOUD_RSA_PUBLIC_KEY" | `EcloudClient.getPublicKey`、`/api/diagnose`、`/api/status.warnings` |
| B | canonical 未做 URL 编码 → `400 INVALID_PARAMETER` | `canonicalize()` 对键和值都做 RFC3986 编码（冒号 → `%3A`）；两组黄金向量逐字符锁进 `test/signature.test.js` | 全部请求 |
| C | 私钥从不传入，解密分支是死代码；`uptimeSeconds` 恒 0 | `ECLOUD_RSA_PRIVATE_KEY` 可配（PKCS#1/PKCS#8）；未配时返回 `{_encrypted:true}` 且上层给出"响应已加密"状态；`extractUptime` 兼容 `body.uptimeSeconds`（数字）与 `body`（字符串） | 响应解析、`/api/keepalive`、面板 |

### 7.2 四项有意变更

| # | 变更 | 原因 |
|---|---|---|
| 1 | 状态从 `data/*.json` 改为 KV + 内存回退 | Workers 无可写文件系统 |
| 2 | 新增 `state:machines` / `state:lastRun` / `state:logs` | 上游"保活是否生效"无法从日志判断（缺陷 C 的连带后果），必须补可观测性 |
| 3 | 新增 `POST /api/diagnose` | 把"服务端是否接受签名"变成可判定结论，替代人工比对 |
| 4 | 新增自动重登（`ECLOUD_USERNAME/PASSWORD` + `AUTO_RELOGIN`） | Serverless 无 TTY，上游"过期即退出"的模型不可运维；重登后最多重跑 1 次防死循环 |

### 7.3 其余细小差异

| 项 | 上游 | 本实现 | 原因 |
|---|---|---|---|
| 解密失败处理 | 遇到非法块 `break`，丢弃剩余块，返回"半截 JSON" | 抛 `RSA_DECRYPT_FAILED` | 半截 JSON 只会变成难查的 `JSONDecodeError` |
| 分块大小 | 硬编码 117 / 128 | 由密钥位长推导（`k-11` / `k`） | 误配 2048-bit 密钥时不产生错位块 |
| 每轮客户端 | 每轮 `EcloudHTTP(...)` 重建、重读 `device.json` | 复用同一实例（惰性解析 PEM 并缓存） | 省 CPU，Workers 有 10ms~50ms CPU 预算 |
| `--rounds N` | 非 `--loop` 时 `rounds` 实际无效（恒 1 轮，上游瑕疵） | 语义收敛为"一次调用 = 一轮"，多轮交给 Cron | 避免继承瑕疵 |
| 设备指纹 | `uuid4()` 两次 | 相同 | |
| 日志 | 仅 `print` | `console` + `state:logs`（50 条环形缓冲） | `wrangler tail` 之外的留痕 |
| 账号展示 | 明文打印 | 掩码 `ab***yz` + token 末 6 位 | 面板可能被他人看到 |
| 时钟注入 | 无 | `now()` 可注入 | 让"UTC+8 跨日""过期判定"可测 |
| 全局 `fetch` 调用 | `requests.Session`（无此问题） | 构造时 `fetchImpl.bind(globalThis)` | workerd 的 `fetch` 要求 `this` 为全局作用域，否则 `Illegal invocation` |

### 7.4 一个只在真实部署暴露的坑：全局 `fetch` 的 `this`

Workers 的全局 `fetch` 是 WebIDL 全局操作，**要求调用时 `this` 指向全局作用域**。
如果把全局 `fetch` 存进对象属性、再以方法形式调用：

```js
this.fetchImpl = fetch;            // 存起来
await this.fetchImpl(url, init);   // 等价 fetch.call(this, …) → workerd 抛 Illegal invocation
```

workerd 会报：

```
Illegal invocation: function called with incorrect `this` reference.
```

这个坑在本地完全复现不了：

- Node 的 `fetch` 不校验 `this`；
- 单元测试注入的假 fetch 通常是箭头函数，本来就不关心 `this`。

因此 `src/ecloud/client.js` 在**构造时**就把 fetch 归一化成
`fetchImpl.bind(globalThis)`（见 `resolveFetch`），调用点用什么形式都安全；
`test/client.test.js` 里有一条回归用例，用一个**普通 function** 模拟 workerd
的严格校验（`this !== globalThis` 就抛 `Illegal invocation`），确保这个 bug 不会复发。

### 7.5 为可测性引入的注入点（不影响生产行为）

`runKeepaliveRound` / `login` 接受三个可选参数：

- `config`：跳过 `loadConfig(env)`，直接给配置对象；
- `makeClient(options)`：替换 `new EcloudClient(...)` 的工厂；
- `log(level, message)`：替换默认的"控制台 + `state:logs`"日志器。

生产调用（`src/index.js`）只传 `{env, state, now}`，全部走默认实现。

---

## 8. 未移植项及原因

| 上游能力 | 状态 | 原因 |
|---|---|---|
| `/machine/pushConnectEventData`（连接事件上报） | 未移植 | 上游 README 提及但代码未实现，缺请求体字段定义；不臆造协议 |
| 短信二次验证（`30002009/30002060/30002063`） | 未实现，只给提示 | 上游同样只 `print` 提示；短信接口未在客户端二进制中定性，属于 4A/MFA 范畴 |
| refresh token 续期 | 不存在 | 上游没有该机制，网关也未暴露；只能重登 |
| `--rounds` / `--interval` / `--loop` CLI 参数 | 语义映射 | `--interval` → cron，`--rounds 1` → `POST /api/keepalive`；无常驻进程可循环 |
| `data/*.json` 文件读写 | 改为 KV | 无文件系统 |
| 交互式序号选择 | 改为 `instanceId` | 无 TTY |
| `settingValue` 解密的 hex blob 内置 | 只保留函数 | 上游仓库里也没有该 blob；README 已注明需自备 |

---

## 9. 验收自检结果

| 检查项 | 结果 |
|---|---|
| `npm install` | 成功，只装 `wrangler`（58 个包，含其依赖） |
| `npm test` | 110 用例全通过，0 skip |
| `node --check src/**/*.js` | 11 个文件全部通过 |
| `npx wrangler deploy --dry-run --outdir=.dryrun` | 通过，Total Upload 102.42 KiB / gzip 27.36 KiB |
| 产物纯净度 | `.dryrun/index.js` 中 `node:` 引用 0 处、`require(` 0 处 |
| 敏感信息 | 仓库无任何真实账号/密码/用户密钥；仅保留上游占位符公钥 |
