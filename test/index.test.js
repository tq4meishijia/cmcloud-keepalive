/**
 * Worker 入口测试：`fetch` 路由与 `scheduled`（Cron）。
 *
 * 重点覆盖两件"线上才会疼"的事：
 *   1. 页面不泄露任何密钥材料；
 *   2. Cron 无论存储多坏都不 reject（Cron 抛错会污染 Workers 指标）。
 */

import assert from "node:assert/strict";
import test from "node:test";

import worker from "../src/index.js";

const CRON = "*/5 * * * *";

/**
 * 构造一个可控的假 KV。
 *
 * @param {object} [options] 选项。
 * @param {Promise<void>|null} [options.gate] 若提供，`put` 会等它 resolve 后再写入，
 *   用来证明 `scheduled` 是"立即返回 + 后台完成"。
 * @returns {{map: Map<string, string>, get: Function, put: Function, delete: Function}} 假 KV。
 */
function createFakeKv({ gate = null } = {}) {
  const map = new Map();
  return {
    map,
    async get(key) {
      return map.has(key) ? map.get(key) : null;
    },
    async put(key, value) {
      if (gate) await gate;
      map.set(key, String(value));
    },
    async delete(key) {
      map.delete(key);
    },
  };
}

/**
 * 发一个指向 Worker 的请求。
 *
 * @param {string} path 路径。
 * @param {object} [options] 选项。
 * @param {string} [options.method] 方法。
 * @param {Record<string, unknown>} [options.env] Workers env。
 * @returns {Promise<Response>} 响应。
 */
function callWorker(path, { method = "GET", env = {} } = {}) {
  return worker.fetch(new Request(`https://worker.example${path}`, { method }), env);
}

/**
 * 静音 Worker 日志。
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

test("GET / 返回面板 HTML，且不含密钥材料", async () => {
  const response = await callWorker("/");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type"), /text\/html/);

  const html = await response.text();
  assert.match(html, /cmcloud-keepalive/);
  assert.match(html, /ADMIN_TOKEN/);
  // 页面自身绝不内联密钥
  assert.equal(html.includes("BEGIN"), false, "页面不能出现 PEM 头");
  assert.equal(html.includes("accessToken"), false, "页面不能出现 token 字段名/明文");
  assert.equal(html.includes("PRIVATE KEY"), false);
});

test("GET /zzz → 404 JSON；POST / → 405", async () => {
  const notFound = await callWorker("/zzz");
  assert.equal(notFound.status, 404);
  assert.match(notFound.headers.get("content-type"), /application\/json/);
  const body = await notFound.json();
  assert.equal(body.ok, false);
  assert.match(body.error, /未知路径/);

  const wrongMethod = await callWorker("/", { method: "POST" });
  assert.equal(wrongMethod.status, 405);
  assert.match((await wrongMethod.json()).error, /方法不允许/);
});

test("GET /api/health 经 Worker 路由后仍免鉴权", async () => {
  const response = await callWorker("/api/health", { env: { ADMIN_TOKEN: "s3cret" } });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.ok, true);
  assert.equal(body.name, "cmcloud-keepalive");
});

test("scheduled：KV 全挂时也不 reject（Cron 抛错会污染 Workers 指标）", async (t) => {
  silenceConsole(t);
  const brokenKv = {
    get() {
      throw new Error("KV get failed");
    },
    put() {
      throw new Error("KV put failed");
    },
    delete() {
      throw new Error("KV delete failed");
    },
  };

  await assert.doesNotReject(
    () => worker.scheduled({ cron: CRON }, { KEEPALIVE_KV: brokenKv }),
    "存储完全不可用时 scheduled 也必须正常返回",
  );
});

test("scheduled：写入一条 ok:false 的 state:lastRun 与 cron 日志", async (t) => {
  silenceConsole(t);
  const kv = createFakeKv();

  await worker.scheduled({ cron: CRON }, { KEEPALIVE_KV: kv });

  const lastRunRaw = kv.map.get("state:lastRun");
  assert.ok(lastRunRaw, "必须写入 state:lastRun");
  const lastRun = JSON.parse(lastRunRaw);
  assert.equal(lastRun.ok, false, "未登录时应记录为失败");
  assert.match(lastRun.error, /ECLOUD_USERNAME|未登录/);
  assert.equal(lastRun.connectStatus, "unknown");

  const logs = JSON.parse(kv.map.get("state:logs"));
  assert.ok(Array.isArray(logs) && logs.length > 0, "必须写入 state:logs");
  assert.ok(
    logs.some((entry) => entry.msg.includes("cron 触发")),
    "日志里应能看到 cron 触发记录",
  );
});

test("scheduled：有 ctx.waitUntil 时立即返回，任务在后台完成", async (t) => {
  silenceConsole(t);

  let release;
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const kv = createFakeKv({ gate });

  let captured = null;
  const ctx = {
    waitUntil(promise) {
      captured = promise;
    },
  };

  const returned = await worker.scheduled({ cron: CRON }, { KEEPALIVE_KV: kv }, ctx);

  assert.equal(returned, undefined, "scheduled 应立即返回，不阻塞 Cron 调度器");
  assert.ok(captured && typeof captured.then === "function", "任务必须交给 ctx.waitUntil");
  assert.equal(kv.map.has("state:lastRun"), false, "此刻任务应尚未完成（被 gate 挡住）");

  release();
  await captured;

  assert.equal(kv.map.has("state:lastRun"), true, "放行后任务应完成并落盘");
  const lastRun = JSON.parse(kv.map.get("state:lastRun"));
  assert.equal(lastRun.ok, false);
});
