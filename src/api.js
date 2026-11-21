/**
 * `/api/*` 处理器（JSON in / JSON out）。
 *
 * 状态码约定（`docs/VERIFY.md` 与 README 的 API 表同步此口径）：
 *   - `200` 业务执行完成，**包含 `ok:false` 的业务失败**（登录被拒、保活失败、未登录）
 *   - `400` 请求体非法（非 JSON 对象 / 缺字段 / instanceId 不存在）
 *   - `401` `ADMIN_TOKEN` 校验失败
 *   - `404` / `405` 路由不存在 / 方法不允许
 *   - `502` 已经打到上游网关但通信失败（网络错误 / 非 2xx / 解密失败）
 *   - `500` 未预期异常
 *
 * @module api
 */

import { loadConfig } from "./config.js";
import { EcloudClient, EcloudError } from "./ecloud/client.js";
import { RSA_KEY_INVALID, validatePrivateKey, validatePublicKey } from "./ecloud/rsa.js";
import { utc8NowText } from "./ecloud/signature.js";
import { describeError, login as loginFlow, runKeepaliveRound } from "./keepalive.js";

const JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
});

const UTF8_ENCODER = new TextEncoder();

/**
 * 构造 JSON 响应。
 *
 * @param {unknown} data 响应体（会被 JSON.stringify）。
 * @param {number} [status] HTTP 状态码。
 * @param {Record<string, string>|null} [extraHeaders] 额外响应头（如 405 的 `Allow`）。
 * @returns {Response} 响应。
 */
function jsonResponse(data, status = 200, extraHeaders = null) {
  const headers = extraHeaders ? { ...JSON_HEADERS, ...extraHeaders } : JSON_HEADERS;
  return new Response(JSON.stringify(data), { status, headers });
}

/**
 * 恒定时间字符串比较，避免用 `===` 比较 token 带来的时序侧信道。
 *
 * @param {string} left 左侧字符串。
 * @param {string} right 右侧字符串。
 * @returns {boolean} 是否相等。
 */
export function constantTimeEqual(left, right) {
  const a = UTF8_ENCODER.encode(String(left));
  const b = UTF8_ENCODER.encode(String(right));
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

/**
 * 账号掩码：只暴露首尾字符。
 *
 * @param {string} username 账号。
 * @returns {string} 掩码后的账号。
 */
function maskUsername(username) {
  const text = String(username ?? "");
  if (text === "") return "";
  if (text.length <= 2) return `${text[0]}***`;
  if (text.length <= 6) return `${text.slice(0, 1)}***${text.slice(-1)}`;
  return `${text.slice(0, 2)}***${text.slice(-2)}`;
}

/**
 * 读取并校验 JSON 请求体（空体视为 `{}`）。
 *
 * @param {Request} request 请求。
 * @returns {Promise<{value: Record<string, unknown>}|{error: string}>} 结果。
 */
async function readJsonBody(request) {
  let text;
  try {
    text = await request.text();
  } catch (error) {
    return { error: `读取请求体失败：${describeError(error)}` };
  }
  if (text.trim() === "") return { value: {} };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { error: "请求体不是合法 JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { error: "请求体必须是 JSON 对象" };
  }
  return { value: parsed };
}

/**
 * `ADMIN_TOKEN` 鉴权。未配置 token 时放行（并在 `/api/status` 标 `authDisabled`）。
 *
 * @param {Request} request 请求。
 * @param {object} config 配置。
 * @returns {Response|null} 拒绝时返回 401 响应，否则 null。
 */
function authorize(request, config) {
  if (config.adminToken === "") return null;
  const header = String(request.headers.get("Authorization") ?? "").trim();
  const matched = /^Bearer\s+(.+)$/i.exec(header);
  if (!matched) {
    return jsonResponse({ ok: false, error: "缺少 Authorization: Bearer <ADMIN_TOKEN>" }, 401);
  }
  if (!constantTimeEqual(matched[1], config.adminToken)) {
    return jsonResponse({ ok: false, error: "ADMIN_TOKEN 不正确" }, 401);
  }
  return null;
}

/**
 * 拉取当前凭证中的 accessToken。
 *
 * @param {object} state StateStore。
 * @returns {Promise<{credentials: object|null, accessToken: string}>} 凭证与 token。
 */
async function loadCredentials(state) {
  const credentials = await state.getCredentials();
  const accessToken = typeof credentials?.accessToken === "string" ? credentials.accessToken : "";
  return { credentials, accessToken };
}

/**
 * 构造一个带 token 的协议客户端。
 *
 * @param {object} options 参数。
 * @param {object} options.config 配置。
 * @param {string} options.accessToken 访问令牌。
 * @param {() => Date} options.now 时钟。
 * @param {{deviceUid?: string}} options.device 设备指纹。
 * @returns {EcloudClient} 客户端。
 */
function createClient({ config, accessToken, now, device }) {
  return new EcloudClient({ config, deviceUid: device?.deviceUid ?? "", accessToken, now });
}

/**
 * 校验并保存选中桌面；缓存未命中时刷新一次列表。
 *
 * @param {object} options 参数。
 * @param {object} options.state StateStore。
 * @param {object} options.config 配置。
 * @param {() => Date} options.now 时钟。
 * @param {string} options.instanceId 目标实例 ID。
 * @returns {Promise<{ok: boolean, selected?: object, error?: string}>} 结果。
 */
async function selectInstance({ state, config, now, instanceId }) {
  const { accessToken } = await loadCredentials(state);
  const cached = await state.getMachines();
  let hit = (cached?.items ?? []).find((item) => item.instanceId === instanceId);

  if (!hit && accessToken !== "") {
    const device = await state.ensureDevice();
    const client = createClient({ config, accessToken, now, device });
    try {
      const stored = await state.setMachines(await client.getDeviceInfo());
      hit = stored.items.find((item) => item.instanceId === instanceId);
    } catch (error) {
      return { ok: false, error: `刷新桌面列表失败：${describeError(error)}` };
    }
  }

  if (!hit) {
    return {
      ok: false,
      error: `桌面列表中不存在 instanceId=${instanceId}${
        accessToken === "" ? "（当前未登录，无法刷新列表）" : ""
      }`,
    };
  }
  const selected = {
    instanceId: hit.instanceId,
    machineId: hit.machineId,
    machineName: hit.machineName,
  };
  await state.setSelected(selected);
  return { ok: true, selected };
}

/**
 * 把 getSysTime 的失败翻译成人话。
 *
 * 三态判读是这里的关键（服务端只用状态码区分，不返回业务错误体）：
 *   - `200`                → 签名 + 请求体均被接受；
 *   - `400 INVALID_PARAMETER` → 签名不合格（canonical 编码 / 时钟偏移）；
 *   - `5xx`                → **签名已通过**，服务端拿自己的私钥解不开请求体 →
 *                            `ECLOUD_RSA_PUBLIC_KEY` 与服务端私钥不配对。
 *
 * 429/403 之类的其他状态才归到"网关异常"。
 *
 * 导出是为了让回归用例能直接锁住三态文案（`test/client.test.js`）。
 *
 * @param {unknown} error 异常。
 * @returns {string} 诊断文案。
 */
export function describeSignatureFailure(error) {
  if (error instanceof EcloudError) {
    if (error.code === RSA_KEY_INVALID) {
      return `无法发起请求：公钥不可解析，请先配置 ECLOUD_RSA_PUBLIC_KEY（${error.message}）`;
    }
    const body = `${error.body ?? ""} ${error.message}`;
    if (error.status === 400 && /INVALID_PARAMETER/i.test(body)) {
      return "签名被拒绝：检查 Timestamp 时钟偏移或 canonical 编码";
    }
    if (error.status >= 500 && error.status < 600) {
      // 实测：合法但服务端不配对的 1024-bit 公钥会得到 500，而不是 400。
      // 此时 400 INVALID_PARAMETER 那条路不会命中，若落到通用分支会被误读成"网关挂了"。
      return (
        `网关返回 HTTP ${error.status}：签名已通过服务端校验，但请求体无法解密——` +
        "通常是 ECLOUD_RSA_PUBLIC_KEY 与服务端私钥不配对（或该密钥不属于当前客户端版本）。" +
        `原文：${(error.body || error.message).slice(0, 200)}`
      );
    }
    if (error.status) {
      return `网关返回 HTTP ${error.status}：${(error.body || error.message).slice(0, 200)}`;
    }
  }
  return `网关不可达: ${describeError(error)}`;
}

/** `GET /api/health`。 */
async function handleHealth({ config, now }) {
  return jsonResponse({
    ok: true,
    name: config.name,
    version: config.version,
    time: utc8NowText(now()),
  });
}

/** `GET /api/status`。 */
async function handleStatus({ state, config, now }) {
  const [credentials, selected, machines, lastRun, logs] = await Promise.all([
    state.getCredentials(),
    state.getSelected(),
    state.getMachines(),
    state.getLastRun(),
    state.getLogs(),
  ]);
  const accessToken = typeof credentials?.accessToken === "string" ? credentials.accessToken : "";

  return jsonResponse({
    ok: true,
    time: utc8NowText(now()),
    storage: state.kind,
    configured: {
      username: config.username === "" ? null : maskUsername(config.username),
      token: accessToken !== "",
      publicKey: config.publicKeyValid,
      privateKey: config.privateKeyConfigured,
      instanceId: config.instanceId,
      kv: state.kind === "kv",
      authDisabled: config.adminToken === "",
    },
    credentials: credentials
      ? {
          username: maskUsername(credentials.username ?? ""),
          savedAt: credentials.savedAt ?? null,
          tokenTail: accessToken.slice(-6),
        }
      : null,
    selected: selected ?? null,
    machines: machines ?? { items: [], fetchedAt: null },
    lastRun: lastRun ?? null,
    logs,
    warnings: config.warnings,
  });
}

/** `POST /api/login`。 */
async function handleLogin({ request, state, config, now }) {
  const body = await readJsonBody(request);
  if (body.error) return jsonResponse({ ok: false, error: body.error }, 400);

  const username = String(body.value.username ?? "").trim();
  const password = String(body.value.password ?? "");
  if (username === "" || password === "") {
    return jsonResponse({ ok: false, error: "username 与 password 均不能为空" }, 400);
  }

  const result = await loginFlow({ config, state, now, username, password });
  return jsonResponse(result, 200);
}

/** `POST /api/refresh`。 */
async function handleRefresh({ state, config, now }) {
  const { accessToken } = await loadCredentials(state);
  if (accessToken === "") {
    return jsonResponse({ ok: false, error: "未登录：请先 POST /api/login" }, 200);
  }
  const device = await state.ensureDevice();
  const client = createClient({ config, accessToken, now, device });
  try {
    const stored = await state.setMachines(await client.getDeviceInfo());
    const selected = await state.getSelected();
    return jsonResponse({
      ok: true,
      machines: stored.items,
      fetchedAt: stored.fetchedAt,
      selected: selected ?? null,
    });
  } catch (error) {
    return jsonResponse({ ok: false, error: describeError(error) }, 502);
  }
}

/** `POST /api/select`。 */
async function handleSelect({ request, state, config, now }) {
  const body = await readJsonBody(request);
  if (body.error) return jsonResponse({ ok: false, error: body.error }, 400);

  const instanceId = String(body.value.instanceId ?? "").trim();
  if (instanceId === "") {
    return jsonResponse({ ok: false, error: "instanceId 不能为空" }, 400);
  }

  const result = await selectInstance({ state, config, now, instanceId });
  if (!result.ok) return jsonResponse({ ok: false, error: result.error }, 400);
  return jsonResponse({ ok: true, selected: result.selected });
}

/** `POST /api/keepalive`。 */
async function handleKeepalive({ request, state, config, now, env }) {
  const body = await readJsonBody(request);
  if (body.error) return jsonResponse({ ok: false, error: body.error }, 400);

  const instanceId = String(body.value.instanceId ?? "").trim();
  if (instanceId !== "") {
    const picked = await selectInstance({ state, config, now, instanceId });
    if (!picked.ok) return jsonResponse({ ok: false, error: picked.error }, 400);
  }

  const result = await runKeepaliveRound({ env, state, now, config });
  return jsonResponse(result, 200);
}

/** `POST /api/logout`。 */
async function handleLogout({ state }) {
  await state.clearCredentials();
  return jsonResponse({ ok: true });
}

/** `POST /api/diagnose`。 */
async function handleDiagnose({ state, config, now }) {
  /** @type {Array<{name: string, ok: boolean, detail: string}>} */
  const checks = [];

  // ① 公钥可解析
  const publicKey = validatePublicKey(config.rsaPublicKey);
  checks.push({
    name: "publicKey",
    ok: publicKey.ok,
    detail: publicKey.ok
      ? `公钥可解析（${publicKey.bits} bit，来源：${config.publicKeySource}）`
      : `当前公钥不可解析（疑似上游占位符），请配置 ECLOUD_RSA_PUBLIC_KEY：${publicKey.error}`,
  });

  // ② 私钥可解析（可选能力，未配置不算失败）
  if (!config.privateKeyConfigured) {
    checks.push({
      name: "privateKey",
      ok: true,
      detail:
        "未配置 ECLOUD_RSA_PRIVATE_KEY（可选）：响应体保持加密形态，保活请求本身不受影响，" +
        "但无法读出 uptime 业务字段",
    });
  } else {
    const privateKey = validatePrivateKey(config.rsaPrivateKey);
    checks.push({
      name: "privateKey",
      ok: privateKey.ok,
      detail: privateKey.ok
        ? `私钥可解析（${privateKey.bits} bit）`
        : `ECLOUD_RSA_PRIVATE_KEY 不可解析：${privateKey.error}`,
    });
  }

  // ③ 签名是否被服务端接受
  const { credentials, accessToken } = await loadCredentials(state);
  let device;
  try {
    device = await state.ensureDevice();
  } catch {
    device = { deviceUid: "" };
  }
  try {
    const client = createClient({ config, accessToken, now, device });
    const result = await client.getSysTime();
    if (result?._encrypted === true) {
      checks.push({
        name: "signature",
        ok: true,
        detail: "签名已被服务端接受；响应已加密（未配置私钥，无法读取业务体）",
      });
    } else {
      checks.push({ name: "signature", ok: true, detail: "签名与请求体均被接受" });
    }
  } catch (error) {
    checks.push({ name: "signature", ok: false, detail: describeSignatureFailure(error) });
  }

  // ④ 存储可写
  const probe = await state.probe();
  checks.push({ name: "kv", ok: probe.ok, detail: probe.detail });

  // ⑤ token 有效期粗判
  if (accessToken === "") {
    checks.push({
      name: "token",
      ok: false,
      detail:
        "未登录：请 POST /api/login，或配置 ECLOUD_USERNAME / ECLOUD_PASSWORD 走自动重登",
    });
  } else {
    checks.push({
      name: "token",
      ok: true,
      detail:
        `凭证保存于 ${credentials?.savedAt ?? "未知时间"}（UTC+8）；` +
        `上游无 refresh token，过期后需重登（AUTO_RELOGIN=${config.autoRelogin}）`,
    });
  }

  return jsonResponse({
    ok: checks.every((check) => check.ok),
    checks,
    time: utc8NowText(now()),
    warnings: config.warnings,
  });
}

/** 路由表：路径 → 方法 → 处理器。 */
const ROUTES = Object.freeze({
  "/api/health": { GET: handleHealth },
  "/api/status": { GET: handleStatus },
  "/api/login": { POST: handleLogin },
  "/api/refresh": { POST: handleRefresh },
  "/api/select": { POST: handleSelect },
  "/api/keepalive": { POST: handleKeepalive },
  "/api/logout": { POST: handleLogout },
  "/api/diagnose": { POST: handleDiagnose },
});

/** 无需鉴权的路径。 */
const PUBLIC_PATHS = new Set(["/api/health"]);

/**
 * 处理 `/api/*` 请求。
 *
 * @param {object} options 参数。
 * @param {Request} options.request 请求。
 * @param {Record<string, unknown>} [options.env] Workers env。
 * @param {object} options.state StateStore。
 * @param {() => Date} [options.now] 时钟。
 * @returns {Promise<Response>} 响应。
 */
export async function handleApiRequest({ request, env = {}, state, now = () => new Date() }) {
  if (!state) throw new TypeError("handleApiRequest 需要 state");
  const url = new URL(request.url);
  const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : url.pathname;
  const method = String(request.method ?? "GET").toUpperCase();

  const route = ROUTES[path];
  if (!route) {
    return jsonResponse({ ok: false, error: `未知接口：${method} ${path}` }, 404);
  }
  const handler = route[method];
  if (typeof handler !== "function") {
    const allowed = Object.keys(route);
    // RFC 9110 §15.5.6：405 响应必须生成 Allow 头，否则客户端无法自行纠错。
    return jsonResponse(
      { ok: false, error: `方法不允许：${method} ${path}`, allow: allowed },
      405,
      { Allow: allowed.join(", ") },
    );
  }

  const config = loadConfig(env);
  if (!PUBLIC_PATHS.has(path)) {
    const denied = authorize(request, config);
    if (denied) return denied;
  }

  return handler({ request, state, config, now, env, url });
}
