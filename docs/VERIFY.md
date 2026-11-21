# 部署验证手册

从零到"确认保活已生效"的完整命令序列，每步都给出**预期输出**与**失败判据**。
命令基于 Git Bash / macOS / Linux；Windows PowerShell 只需把 `curl -s` 换 `curl.exe -s`、`\` 续行换反引号。

约定：

```bash
export WORKER_URL="https://cmcloud-keepalive.<你的子域>.workers.dev"   # 部署后 wrangler 会打印
export ADMIN_TOKEN="<你设置的 ADMIN_TOKEN>"                            # 未设置则留空，下面的 -H 可省略
```

---

## 阶段 0：本地自检（不联网、不花钱）

### 0.1 环境

```bash
node -v && npm -v
```

预期：`v22.x` / `10.x`（Node ≥ 20 即可）。

### 0.2 语法检查

```bash
for f in $(find src -name '*.js'); do node --check "$f" || echo "FAIL $f"; done
```

预期：**无输出**（脚本只在失败时打印）。

### 0.3 单元测试

```bash
npm test
```

预期（尾部）：

```
# tests 110
# suites 0
# pass 110
# fail 0
# cancelled 0
# skipped 0
```

失败判据：出现任何 `# fail N`（N>0）或 `# skipped`。重点看这几条：
- `黄金向量 1：/user/getSysTime（无 AccessToken）` —— 签名修复的证据；
- `validatePublicKey 对上游占位符必须返回 ok:false` —— 缺陷 A 的证据；
- `反向：Node 公钥加密 → 本实现私钥解密（PKCS#8）` —— RSA 自实现的正确性；
- `性能：单块 1024-bit 私钥解密 < 100ms` —— Workers CPU 预算；
- `fetchImpl 不依赖调用点的 this（workerd Illegal invocation 回归）` —— 全局 `fetch` 必须
  `bind(globalThis)`，这是**只有真实部署才暴露**的坑（Node 与箭头函数假 fetch 都掩盖它）。

### 0.4 打包自检

```bash
npx wrangler deploy --dry-run --outdir=.dryrun
```

预期（尾部）：

```
Total Upload: 103.41 KiB / gzip: 27.66 KiB
Your worker has access to the following bindings:
- KV Namespaces:
  - KEEPALIVE_KV: 00000000000000000000000000000000
- Vars:
  - AUTO_RELOGIN: "true"
--dry-run: exiting now.
```

> 体积随 wrangler 版本略有浮动，落在 `100~105 KiB / gzip 27~28 KiB` 即正常；关键是
> `--dry-run: exiting now.` 且没有 error。

产物纯净度：

```bash
grep -c "node:" .dryrun/index.js   # 预期 0
grep -o 'require("[^"]*")' .dryrun/index.js | sort -u   # 预期无输出
```

> `wrangler@3` 会提示"有新版本 4.x"，属正常提示，不影响部署；如需升级：
> `npm i -D wrangler@4` 后重跑 0.4。

### 0.5 本地起服务（可选）

```bash
npx wrangler dev
# 另开一个终端：
curl -s http://127.0.0.1:8787/api/health
curl -s http://127.0.0.1:8787/api/status | head -c 400
```

预期：`{"ok":true,"name":"cmcloud-keepalive","version":"1.0.0","time":"..."}`；
`/api/status` 的 `storage` 字段为 `"kv"`——本地 `wrangler dev` 会按 `wrangler.toml` 里的
`[[kv_namespaces]]` 起一份本地 KV；只有删掉该绑定（或 KV 不可用）时才会回退到 `"memory"`，
那时状态会随 isolate 回收而丢失，只适合临时调试。

---

## 阶段 1：创建资源与写入密钥

### 1.1 登录 Cloudflare

```bash
npx wrangler login
npx wrangler whoami
```

预期：打印账号邮箱与 account id。

### 1.2 创建 KV namespace

```bash
npx wrangler kv namespace create KEEPALIVE_KV
```

预期：

```
✅ Created namespace "cmcloud-keepalive-KEEPALIVE_KV" with id "<32 位 id>"
```

把这个 id 填进 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "KEEPALIVE_KV"
id = "<32 位 id>"          # 替换掉 00000000000000000000000000000000
```

**失败判据**：忘记替换 id → 部署报 `KV namespace ... is not valid`。

### 1.3 写入 secret

```bash
npx wrangler secret put ECLOUD_RSA_PUBLIC_KEY    # 必填
npx wrangler secret put ECLOUD_RSA_PRIVATE_KEY   # 可选，但强烈建议
npx wrangler secret put ADMIN_TOKEN              # 强烈建议
npx wrangler secret put ECLOUD_USERNAME          # 可选（自动重登）
npx wrangler secret put ECLOUD_PASSWORD          # 可选
```

粘贴 PEM 后按 `Ctrl-D`（Windows：`Ctrl-Z` 回车）。核对：

```bash
npx wrangler secret list
```

预期：列出上面写入的名字（**不会显示值**）。

> 公共值也可以放 `wrangler.toml` 的 `[vars]`，例如 `ECLOUD_INSTANCE_ID = "xxx"`；
> PEM 与密码只能走 `secret put`。

---

## 阶段 2：部署

```bash
npm run deploy
```

预期：

```
Uploaded cmcloud-keepalive (x.xx sec)
Deployed cmcloud-keepalive triggers
  https://cmcloud-keepalive.<子域>.workers.dev
  schedule: */5 * * * *
```

记下 URL：

```bash
export WORKER_URL="https://cmcloud-keepalive.<子域>.workers.dev"
```

### 2.1 面板可打开

```bash
curl -s -o /dev/null -w "%{http_code} %{content_type}\n" "$WORKER_URL/"
```

预期：`200 text/html; charset=utf-8`。

浏览器打开 `$WORKER_URL/`，应看到：
- 左上角项目名与版本 `v1.0.0`、健康点（几秒内变绿）；
- 三张卡片：凭证 / 选中桌面 / 最近保活（初始多为 `—`）；
- "配置告警"区列出 `ECLOUD_RSA_PUBLIC_KEY` 或 `ADMIN_TOKEN` 相关提醒（未配时）。

在右上角 `ADMIN_TOKEN` 输入框填入 token（存 `localStorage`），后续请求会自动带
`Authorization: Bearer`。

### 2.2 健康检查

```bash
curl -s "$WORKER_URL/api/health"
```

预期：

```json
{"ok":true,"name":"cmcloud-keepalive","version":"1.0.0","time":"2026-11-21 23:58:01"}
```

`time` 是 **UTC+8** 文本。若时间差 8 小时，说明只是时区理解问题，不影响签名
（签名用的 `Timestamp` 也是 UTC+8 语义）。

---

## 阶段 3：登录与自检（判定核心）

### 3.1 登录

```bash
curl -s -X POST "$WORKER_URL/api/login" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username":"<账号>","password":"<密码>"}'
```

成功预期：

```json
{"ok":true,"username":"<账号>","machines":[{"instanceId":"...","machineId":"...","machineName":"...","status":"Running"}],"selected":{...}}
```

失败预期（都是 `200` + `ok:false`，`hint` 说明原因）：

| `errorCode` | `hint` 含义 | 处理 |
|---|---|---|
| `30002009` | 未授信设备，需短信验证 | 先在官方客户端完成设备授信 |
| `30002060` | 需二次验证 | 在官方客户端完成短信验证 |
| `30002063` | 增强安全策略 | 同上 |
| 其他 | 账号或密码错误 | 核对凭据 |

**失败判据**：`ECLOUD_REQUEST_FAILED` 且 `error` 里是 `HTTP 400 ... INVALID_PARAMETER` →
说明本实现的 canonical 编码或时钟有问题，回到 `npm test` 检查黄金向量；若 `HTTP 4xx`
内容提到 `accessTicket`，则是账号侧状态问题。

若 `error` 里是 `HTTP 500 ...`，见 §3.2 的**三态判读**——那说明签名已通过、只是公钥与服务端私钥
不配对，**不要**当成网关故障。

### 3.2 自检（**关键判定**）

```bash
curl -s -X POST "$WORKER_URL/api/diagnose" -H "Authorization: Bearer $ADMIN_TOKEN"
```

理想情况：五项全绿（`ok:true`）：

```json
{
  "ok": true,
  "checks": [
    {"name":"publicKey","ok":true,"detail":"公钥可解析（1024 bit，来源：env）"},
    {"name":"privateKey","ok":true,"detail":"私钥可解析（1024 bit）"},
    {"name":"signature","ok":true,"detail":"签名与请求体均被接受"},
    {"name":"kv","ok":true,"detail":"KEEPALIVE_KV 读写正常"},
    {"name":"token","ok":true,"detail":"凭证保存于 2026-11-21 23:58:01（UTC+8）；..."}
  ]
}
```

未配私钥时 `signature` 也应为 `true`，detail 为：

```
签名已被服务端接受；响应已加密（未配置私钥，无法读取业务体）
```

**这一条就是"签名修复生效"的客观证据**：服务端返回 200 而不是 400。

**三态判读（服务端只靠状态码区分，不返回业务错误体）**：

| 服务端返回 | 含义 | 下一步 |
|---|---|---|
| `200` | 签名 + 请求体均被接受（最理想） | 继续走 3.1 登录 / 阶段 4 保活 |
| `400 INVALID_PARAMETER` | 签名不合格（canonical 编码 / 时钟偏移） | 回 `npm test` 检查黄金向量；核对 Workers 时钟 |
| `500 Internal Server Error` | **签名已通过**，但请求体解不开 → `ECLOUD_RSA_PUBLIC_KEY` 与服务端私钥不配对（或该密钥不属于当前客户端版本） | 换回真实公钥；**不要**当成"网关挂了" |

> **为什么这条检查重要**：它是**唯一不需要账号密码就能验证整条协议栈正确性**的手段——
> 签名算法、canonical 编码、UTC+8 时间戳、RSA 填充、请求体结构，全部都在这一发请求里被服务端检验。
> 而且**配错公钥时它给的是 500 而不是 400**：`400 INVALID_PARAMETER` 才代表签名有问题，
> `500` 代表签名已过、只是服务端用自己的私钥解不开 body。所以看到 500 先怀疑密钥，不要怀疑签名实现。

对应的验收口径见 **附录 B 的「三层口径」**：第 2 层（500）是**可诊断的配置错误**，
不会因为 `signature.ok === false` 就把整项判为验收不通过——判定标准是 `detail` 是否给出了正确的下一步。

失败对照表：

| `checks[].name` | `detail` | 含义与处理 |
|---|---|---|
| `publicKey` | 当前公钥不可解析（疑似上游占位符），请配置 ECLOUD_RSA_PUBLIC_KEY | 没配真实公钥，或粘贴被截断。重新 `wrangler secret put` |
| `privateKey` | ECLOUD_RSA_PRIVATE_KEY 不可解析 | 私钥格式不对或与公钥不配对；删除该 secret 至少能恢复保活请求 |
| `signature` | 签名被拒绝：检查 Timestamp 时钟偏移或 canonical 编码 | 服务端返回 400 `INVALID_PARAMETER`。Workers 时钟一般准确，优先怀疑公钥/环境 |
| `signature` | 网关返回 HTTP 500：签名已通过服务端校验，但请求体无法解密——通常是 ECLOUD_RSA_PUBLIC_KEY 与服务端私钥不配对… | 签名没问题，**公钥不对**：换回与该客户端版本配对的公钥；别当网关故障排查 |
| `signature` | 网关不可达: … | 出口网络问题或网关变更；`wrangler tail` 看完整错误 |
| `signature` | 无法发起请求：公钥不可解析 | 同 `publicKey` 项 |
| `kv` | 未绑定 KEEPALIVE_KV：… | 只在本地 `wrangler dev` 可接受；线上必须绑 KV |
| `token` | 未登录：… | 先走 3.1 登录，或配 `ECLOUD_USERNAME/PASSWORD` |

---

## 阶段 4：手动触发一轮保活

```bash
curl -s -X POST "$WORKER_URL/api/keepalive" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{}'
```

成功预期：

```json
{"ts":"2026-11-21 23:59:12","ok":true,"stage":"done","uptimeSeconds":49134,
 "uptimeText":"13小时38分钟54秒","connectStatus":0,"tokenExpired":false,"error":null}
```

> 注意 `uptimeText` 的两种形态：
> - 服务端返回**数字**字段时，文本由本实现用 `formatUptime()` 生成，`49134 → "13小时38分钟54秒"`
>   （带"分钟"两字，规则与上游 `main.py:224-238` 一致）；
> - 服务端直接返回**字符串** `body` 时（实测形态），文本**原样透传**，可能是 `"13小时38分54秒"`，
>   此时 `uptimeSeconds` 为 `null`。两种都正常，不要按其中一种去校另一种。

判定细则：

| 现象 | 含义 |
|---|---|
| `ok:true` + `connectStatus:0` + `uptimeText` 有值 | 完全成功 |
| `ok:true` + `uptimeText:"13小时38分54秒"`（`uptimeSeconds:null`） | 服务端返回字符串形态，正常（缺陷 C 的兼容分支） |
| `ok:false` + `note:"response-encrypted-需配置私钥"` | 签名与请求都被接受，但读不到业务字段；配私钥即可看到 uptime |
| `ok:false` + `stage:"credentials"` | 没登录且没配自动重登；走 3.1 |
| `ok:false` + `stage:"machines"` | 账号下没有桌面实例，或 token 无权限 |
| `ok:false` + `tokenExpired:true` | token 真过期；配 `ECLOUD_USERNAME/PASSWORD` 后自动恢复 |
| `ok:false` + `stage:"uptime"` / `"connect"` | 上游报错，`error` 里有 HTTP 状态与响应片段 |

连打两次间隔 ≥ 5 秒，`uptimeSeconds`（或 `uptimeText`）应该**递增**——这是"服务端确实在为
该会话累计在线时长"的直接证据，也就是保活生效的证据。

### 4.1 核对 `/api/status` 字段

```bash
curl -s "$WORKER_URL/api/status" -H "Authorization: Bearer $ADMIN_TOKEN"
```

逐项核对：

| 字段 | 期望 | 说明 |
|---|---|---|
| `configured.username` | `<账号掩码>` 或 `null` | 掩码形如 `ab***yz`，**绝不回显完整账号/密钥** |
| `configured.token` | `true` | 是否已拿到 accessToken |
| `configured.publicKey` | `true` | 公钥可解析 |
| `configured.privateKey` | `true`/`false` | 是否配置了私钥（可选） |
| `configured.instanceId` | 配置值或 `""` | `ECLOUD_INSTANCE_ID` |
| `configured.kv` | `true` | 线上必须为 `true` |
| `configured.authDisabled` | `false` | 为 `true` 说明没配 `ADMIN_TOKEN`，接口裸奔 |
| `credentials.savedAt` | UTC+8 文本 | 最近一次登录时间 |
| `credentials.tokenTail` | 6 位 | token 末 6 位，用于对账 |
| `selected` | `{instanceId,machineId,machineName}` | 当前保活目标 |
| `machines.items` | 数组 | 桌面列表缓存 |
| `lastRun` | 最近一轮结果 | 与 4 的结果一致 |
| `logs` | ≤ 50 条 | 最近日志 |
| `warnings` | 数组 | 配置告警（未配 token/公钥/账号密码时非空） |
| `storage` | `"kv"` | 线上必须为 `kv`，不能是 `memory` |

---

## 阶段 5：观察 Cron 自动执行

```bash
npx wrangler tail --format pretty
```

每 5 分钟应出现一组：

```
[keepalive] 第 1 轮成功｜Uptime: 13小时44分02秒｜Connect: 0
[keepalive] cron */5 * * * * 完成：ok=true uptime=13小时44分02秒 connect=0
```

若上一轮失败，会看到 `第 1 轮失败（machines）｜…` 这类行，原因与 `stage` 对应。

同时刷新 `/api/status`，`lastRun.ts` 会按 5 分钟步进，`logs` 里累积 `cron 触发：*/5 * * * *`。

**失败判据**：`wrangler tail` 里出现 `[cron] 保活轮次异常`（这只会在极端情况下出现，
因为 `scheduled` 内部已三层捕获）→ 说明有代码级异常，把整行贴出来定位。

---

## 阶段 6：回滚与清理

### 6.1 回滚到上一版本

```bash
npx wrangler deployments list      # 找到上一个 Version ID
npx wrangler rollback              # 交互式选择；或：
npx wrangler rollback <VERSION_ID>
```

回滚后重跑阶段 2.2 与阶段 4，确认旧版本行为。

### 6.2 撤销某个密钥

```bash
npx wrangler secret delete ECLOUD_RSA_PRIVATE_KEY
```

删掉私钥后退回"响应加密但保活仍生效"的状态（`/api/diagnose` 的 `privateKey` 变 `true`、
`signature` detail 变"响应已加密"）。

### 6.3 彻底清理

```bash
npx wrangler delete                                  # 删除 Worker（含 Cron）
npx wrangler kv namespace delete --namespace-id <id> # 删除 KV（状态一起没）
npx wrangler secret list                             # 确认无残留
```

---

## 附录 A：常见问题速查

| 症状 | 最可能原因 | 处理 |
|---|---|---|
| 部署报 KV namespace 无效 | `wrangler.toml` 里还是 32 个 0 | 填真实 id（1.2） |
| `/api/*` 全 401 | 面板/命令里的 `ADMIN_TOKEN` 与 secret 不一致 | `wrangler secret put ADMIN_TOKEN` 重设，或在面板重新保存 |
| `publicKey` 检查失败 | 没配公钥 / PEM 被截断 / 用了 PKCS#1 以外的奇怪格式 | 重新粘贴完整 `-----BEGIN PUBLIC KEY-----` 块 |
| 登录返回 `INVALID_PARAMETER` | 极少见：出口 IP 被风控 | 重试；仍失败则换环境验证 |
| `connectStatus` 非 0 但 `ok:true` | 不可能同时出现（`ok` 由 `connectStatus===0` 决定）；若出现请记录 bug | — |
| `signature` 的 detail 里出现 `Illegal invocation` | 用了全局 `fetch` 未绑定 `this` 的旧版本 | 升级到当前版本：`EcloudClient` 构造时已 `bind(globalThis)`（见 PORTING §7.4） |
| 面板一直转圈无数据 | 未填 `ADMIN_TOKEN` 但后端强制校验 | 在输入框填 token 后点"保存" |
| `storage:"memory"` | 线上没绑 KV | 绑 KV 并重新部署 |
| 每 5 分钟但桌面仍关机 | 服务端关机策略更激进 / 该实例已被回收 | 缩短 cron 到 `*/1 * * * *`，或确认实例状态 |

## 附录 B：判定清单

> **总原则：验收看的是「`detail` 是否给出了正确的下一步」，而不是「`ok` 是否全绿」。**
> `/api/diagnose` 的 `ok` 只表示"五项全部通过"，公钥没配好时它本来就该是 `false`；
> 关键是 `detail` 有没有把原因和处理办法说清楚。

- [ ] `npm test` 显示 `# pass 110 # fail 0 # skipped 0`
- [ ] `npx wrangler deploy --dry-run` 输出 `Total Upload: ~103 KiB`
- [ ] `GET /api/health` 返回 `ok:true` 且 `time` 为 UTC+8
- [ ] `POST /api/diagnose` 的 `signature` 检查符合下面「三层口径」中的**任意一层**
      （三种情况下 `detail` 都**不得**出现 `Illegal invocation`——出现即说明跑的是未绑定 `this` 的旧包）：

      1. **配到与服务端配对的公钥** → HTTP 200 → `signature.ok === true`，detail 为
         「签名与请求体均被接受」或「签名已被服务端接受；响应已加密（未配置私钥…）」；
      2. **公钥可解析但未配对** → HTTP 500 → `signature.ok === false`，detail 必须含
         「签名已通过服务端校验」与「不配对」。这是**可诊断的配置错误**，不算验收失败，
         但必须继续修密钥，否则保活无法工作；
      3. **公钥不可解析** → `signature.ok === false`，detail 含「无法发起请求：公钥不可解析」。
- [ ] `POST /api/keepalive` 返回 `ok:true`、`connectStatus:0`、uptime 有值
- [ ] 连打两次保活 uptime **递增**
- [ ] `/api/status` 的 `configured.kv === true`、`configured.authDisabled === false`、`storage === "kv"`
- [ ] `wrangler tail` 里每 5 分钟有一条 `cron */5 * * * * 完成：ok=true`
- [ ] `/api/status` 里没有任何完整密钥或完整账号（只有掩码与 token 末 6 位）
