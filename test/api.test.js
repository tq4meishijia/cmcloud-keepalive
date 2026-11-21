/**
 * `/api/*` 处理器测试。
 *
 * 全部通过 `Request` 对象调用 `handleApiRequest`，用内存 StateStore 注入状态，
 * 不发任何真实网络请求（公钥不可解析的场景会在加密阶段就失败，天然不联网）。
 */

import assert from "node:assert/strict";
import test from "node:test";

import { handleApiRequest } from "../src/api.js";
import { MemoryKv, StateStore } from "../src/store.js";

const FIXED_NOW = () => new Date("2026-01-02T03:04:05Z");
const ADMIN_TOKEN = "s3cret-token";
const AUTH_ENV = Object.freeze({ ADMIN_TOKEN });
/** 末 6 位为 `123456`，用于校验脱敏。 */
const FULL_TOKEN = "abcdefghijklmnop123456";
/** 掩码后应为 `13***00`。 */
const FULL_USERNAME = "13800138000";

/**
 * 造一个独立的内存状态仓库，避免用例之间互相污染。
 *
 * @returns {StateStore} 状态仓库。
 */
function createState() {
  return new StateStore({ kv: new MemoryKv(), kind: "memory", now: FIXED_NOW });
}

/**
 * 构造请求对象。
 *
 * @param {string} path 路径。
 * @param {object} [options] 选项。
 * @param {string} [options.method] 方法。
 * @param {unknown} [options.body] 请求体（对象自动 JSON 序列化，字符串原样）。
 * @param {string} [options.token] 设置 `Authorization: Bearer <token>`。
 * @param {Record<string, string>} [options.headers] 额外请求头。
 * @returns {Request} 请求。
 */
function buildRequest(path, { method = "GET", body, token, headers = {} } = {}) {
  const requestHeaders = { ...headers };
  if (token !== undefined) {
    requestHeaders.Authorization = `Bearer ${token}`;
  }
  const init = { method, headers: requestHeaders };
  if (body !== undefined) {
    init.body = typeof body === "string" ? body : JSON.stringify(body);
    requestHeaders["Content-Type"] = "application/json";
  }
  return new Request(`https://worker.example${path}`, init);
}

/**
 * 发一次 API 调用并解析 JSON。
 *
 * @param {string} path 路径。
 * @param {object} [options] 请求选项（见 buildRequest）。
 * @param {object} [context] 上下文。
 * @param {Record<string, unknown>} [context.env] Workers env。
 * @param {StateStore|null} [context.state] 状态仓库。
 * @returns {Promise<{status: number, headers: Headers, text: string, json: any}>} 结果。
 */
async function callApi(path, options = {}, { env = AUTH_ENV, state = null } = {}) {
  const response = await handleApiRequest({
    request: buildRequest(path, options),
    env,
    state: state ?? createState(),
    now: FIXED_NOW,
  });
  const text = await response.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: response.status, headers: response.headers, text, json };
}

/**
 * 静音保活日志，避免污染测试输出。
 *
 * @param {object} t node:test 上下文。
 */
function silenceConsole(t) {
  const original = { log: console.log, warn: console.warn, error: console.error };
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
  t.after(() => {
    console.log = original.log;
    console.warn = original.warn;
    console.error = original.error;
  });
}

test("鉴权：无 Authorization / 错误 token / Bearer 后无空白 → 401", async () => {
  const noHeader = await callApi("/api/status");
  assert.equal(noHeader.status, 401);
  assert.match(noHeader.json.error, /缺少 Authorization/);

  const wrongToken = await callApi("/api/status", { token: "wrong-token" });
  assert.equal(wrongToken.status, 401);
  assert.match(wrongToken.json.error, /不正确/);

  // `Bearer` 与 token 之间必须有空白，否则不匹配 Bearer 方案
  const missingSpace = await callApi("/api/status", {
    headers: { Authorization: `Bearer${ADMIN_TOKEN}` },
  });
  assert.equal(missingSpace.status, 401);

  const bareScheme = await callApi("/api/status", { headers: { Authorization: "Bearer" } });
  assert.equal(bareScheme.status, 401);

  const trailingSpaces = await callApi("/api/status", {
    headers: { Authorization: "Bearer     " },
  });
  assert.equal(trailingSpaces.status, 401);
});

test("鉴权：小写 bearer 接受（与实现的 /i 匹配一致）", async () => {
  const res = await callApi("/api/status", { headers: { Authorization: `bearer ${ADMIN_TOKEN}` } });
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
});

test("GET /api/health 免鉴权；ADMIN_TOKEN 为空时全部放行并标 authDisabled", async () => {
  const health = await callApi("/api/health", {}, { env: {} });
  assert.equal(health.status, 200);
  assert.equal(health.json.ok, true);
  assert.equal(health.json.name, "cmcloud-keepalive");
  assert.match(health.json.time, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);

  const status = await callApi("/api/status", {}, { env: {} });
  assert.equal(status.status, 200);
  assert.equal(status.json.configured.authDisabled, true);
  assert.ok(
    status.json.warnings.some((warning) => warning.includes("ADMIN_TOKEN")),
    "未配置 ADMIN_TOKEN 时必须给出告警",
  );
});

test("/api/status 脱敏：不回显完整 token，账号只留掩码", async () => {
  const state = createState();
  await state.setCredentials({
    username: FULL_USERNAME,
    accessToken: FULL_TOKEN,
    savedAt: "2026-01-02 11:04:05",
  });

  const res = await callApi(
    "/api/status",
    { token: ADMIN_TOKEN },
    { env: { ADMIN_TOKEN, ECLOUD_USERNAME: FULL_USERNAME }, state },
  );

  assert.equal(res.status, 200);
  assert.equal(res.json.credentials.tokenTail, "123456");
  assert.equal(res.json.credentials.username, "13***00");
  assert.equal(res.json.configured.username, "13***00");
  assert.equal(res.text.includes(FULL_TOKEN), false, "完整 accessToken 不得出现在响应体里");
  assert.equal(res.text.includes(FULL_USERNAME), false, "完整账号不得出现在响应体里");
  assert.equal(res.text.includes("***"), true);
});

test("请求体边界：非法 JSON → 400", async () => {
  const res = await callApi("/api/select", { method: "POST", body: "{oops", token: ADMIN_TOKEN });
  assert.equal(res.status, 400);
  assert.match(res.json.error, /不是合法 JSON/);
});

test("请求体边界：数组 / 字符串 / null / 数字 都不是合法对象 → 400", async () => {
  const bodies = ["[1,2]", '"just-a-string"', "null", "42"];
  for (const body of bodies) {
    const res = await callApi("/api/select", { method: "POST", body, token: ADMIN_TOKEN });
    assert.equal(res.status, 400, `body=${body} 应被拒绝`);
    assert.match(res.json.error, /必须是 JSON 对象/);
  }
});

test("/api/select：缺 instanceId → 400；不存在的 instanceId → 400", async () => {
  const missing = await callApi("/api/select", { method: "POST", body: {}, token: ADMIN_TOKEN });
  assert.equal(missing.status, 400);
  assert.match(missing.json.error, /instanceId 不能为空/);

  const ghost = await callApi("/api/select", {
    method: "POST",
    body: { instanceId: "i-404" },
    token: ADMIN_TOKEN,
  });
  assert.equal(ghost.status, 400);
  assert.match(ghost.json.error, /不存在 instanceId=i-404/);
});

test("路由：未知接口 404；方法不允许 405 且带 Allow 头", async () => {
  const unknown = await callApi("/api/nope", { token: ADMIN_TOKEN });
  assert.equal(unknown.status, 404);
  assert.match(unknown.json.error, /未知接口/);

  const wrongMethod = await callApi("/api/status", { method: "POST", token: ADMIN_TOKEN });
  assert.equal(wrongMethod.status, 405);
  // RFC 9110：405 响应必须带 Allow 头
  assert.equal(wrongMethod.headers.get("Allow"), "GET");
  assert.deepEqual(wrongMethod.json.allow, ["GET"]);

  const loginGet = await callApi("/api/login", { token: ADMIN_TOKEN });
  assert.equal(loginGet.status, 405);
  assert.equal(loginGet.headers.get("Allow"), "POST");
});

test("路由：尾部斜杠容错，/api/status/ 等同 /api/status", async () => {
  const res = await callApi("/api/status/", { token: ADMIN_TOKEN });
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, true);
});

test("/api/diagnose：公钥不可解析时签名检查指向公钥而不是网络", async (t) => {
  silenceConsole(t);
  const res = await callApi("/api/diagnose", { method: "POST", token: ADMIN_TOKEN });

  assert.equal(res.status, 200);
  const checks = res.json.checks;
  assert.equal(Array.isArray(checks), true);
  assert.equal(checks.length, 5, "五项检查必须齐全");

  const publicKey = checks.find((check) => check.name === "publicKey");
  assert.equal(publicKey.ok, false);
  assert.match(
    publicKey.detail,
    /当前公钥不可解析（疑似上游占位符），请配置 ECLOUD_RSA_PUBLIC_KEY/,
  );

  const signature = checks.find((check) => check.name === "signature");
  assert.equal(signature.ok, false);
  assert.match(signature.detail, /无法发起请求：公钥不可解析/);
  assert.doesNotMatch(signature.detail, /网关不可达/, "公钥问题不能被报成网络问题");

  assert.equal(checks.find((check) => check.name === "kv").ok, true);
  assert.equal(checks.find((check) => check.name === "token").ok, false);
  assert.equal(res.json.ok, false);
});

test("/api/keepalive：未登录且无环境凭证 → 200 + ok:false + stage=credentials，且不泄露堆栈", async (t) => {
  silenceConsole(t);
  const res = await callApi("/api/keepalive", { method: "POST", body: {}, token: ADMIN_TOKEN });

  assert.equal(res.status, 200, "业务失败仍返回 200，用 ok 字段表达");
  assert.equal(res.json.ok, false);
  assert.equal(res.json.stage, "credentials");
  assert.match(res.json.error, /ECLOUD_USERNAME/);

  // 响应体只应有可读文案，不应带堆栈或源码路径
  assert.doesNotMatch(res.text, /\n\s+at\s/, "响应里不能带堆栈");
  assert.doesNotMatch(res.text, /node_modules|\.js:\d+:\d+/);
  assert.doesNotMatch(res.text, /Error:\s*\n/);
});

test("/api/refresh：未登录 → 200 + ok:false", async () => {
  const res = await callApi("/api/refresh", { method: "POST", token: ADMIN_TOKEN });
  assert.equal(res.status, 200);
  assert.equal(res.json.ok, false);
  assert.match(res.json.error, /未登录/);
});

test("/api/logout：清除凭证后 /api/status 不再有 credentials", async () => {
  const state = createState();
  await state.setCredentials({
    username: FULL_USERNAME,
    accessToken: FULL_TOKEN,
    savedAt: "2026-01-02 11:04:05",
  });

  const before = await callApi("/api/status", { token: ADMIN_TOKEN }, { state });
  assert.notEqual(before.json.credentials, null);

  const logout = await callApi("/api/logout", { method: "POST", token: ADMIN_TOKEN }, { state });
  assert.equal(logout.status, 200);
  assert.equal(logout.json.ok, true);

  const after = await callApi("/api/status", { token: ADMIN_TOKEN }, { state });
  assert.equal(after.json.credentials, null);
  assert.equal(after.json.configured.token, false);
});
