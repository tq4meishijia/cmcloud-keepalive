/**
 * 保活编排测试：假 store（真 StateStore + 内存 KV）+ 假客户端，零网络。
 *
 * 覆盖任务书 §8.5 要求的五个场景，外加 formatUptime 逐项对齐上游、
 * 加密响应降级、非 token 类错误码等边界。
 */

import assert from "node:assert/strict";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import {
  extractUptime,
  formatUptime,
  hintForLoginError,
  pickMachine,
  runKeepaliveRound,
} from "../src/keepalive.js";
import { MemoryKv, StateStore } from "../src/store.js";

const FIXED_NOW = () => new Date("2026-01-02T03:04:05Z");
const SAVED_AT = "2026-01-02 11:04:05";

/**
 * 造一个独立的内存状态仓库（每个用例互不干扰）。
 *
 * @returns {StateStore} 状态仓库。
 */
function createState() {
  return new StateStore({ kv: new MemoryKv(), kind: "memory", now: FIXED_NOW });
}

/**
 * 造一个脚本化的客户端工厂，并记录调用轨迹。
 *
 * @param {object} script 各方法的返回值/实现。
 * @returns {{factory: Function, trace: object}} 工厂与轨迹。
 */
function createFactory(script) {
  const trace = { loginCalls: [], uptimeCalls: [], connectCalls: [], deviceInfoCalls: 0 };
  const factory = (options) => ({
    async loginWithPassword(username, password) {
      trace.loginCalls.push({ username, password, token: options.accessToken });
      return typeof script.loginWithPassword === "function"
        ? script.loginWithPassword(username, password)
        : (script.loginWithPassword ?? {});
    },
    async verifyAccessTicket(ticket) {
      trace.ticket = ticket;
      return typeof script.verifyAccessTicket === "function"
        ? script.verifyAccessTicket(ticket)
        : (script.verifyAccessTicket ?? {});
    },
    async getDeviceInfo() {
      trace.deviceInfoCalls += 1;
      return typeof script.getDeviceInfo === "function"
        ? script.getDeviceInfo(options.accessToken)
        : (script.getDeviceInfo ?? []);
    },
    async desktopUptime(instanceId) {
      trace.uptimeCalls.push(instanceId);
      if (typeof script.desktopUptime === "function") {
        return script.desktopUptime(instanceId, options.accessToken);
      }
      return script.desktopUptime ?? {};
    },
    async machineConnect(instanceId, machineId) {
      trace.connectCalls.push({ instanceId, machineId, token: options.accessToken });
      if (typeof script.machineConnect === "function") {
        return script.machineConnect(instanceId, machineId, options.accessToken);
      }
      return script.machineConnect ?? { errorCode: 0 };
    },
  });
  return { factory, trace };
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

test("formatUptime 与上游 main.py:224-238 完全一致", () => {
  assert.equal(formatUptime(0), "0秒");
  assert.equal(formatUptime(1), "1秒");
  assert.equal(formatUptime(59), "59秒");
  assert.equal(formatUptime(60), "1分钟0秒");
  assert.equal(formatUptime(3600), "1小时0秒");
  assert.equal(formatUptime(3661), "1小时1分钟1秒");
  assert.equal(formatUptime(86400), "1天0秒");
  assert.equal(formatUptime(90061), "1天1小时1分钟1秒");
  // 异常输入不抛错，统一落到 "0秒"
  assert.equal(formatUptime(-5), "0秒");
  assert.equal(formatUptime(Number.NaN), "0秒");
  assert.equal(formatUptime(undefined), "0秒");
  assert.equal(formatUptime(12.9), "12秒");
});

test("extractUptime 兼容数字字段、字符串 body 与加密响应", () => {
  assert.deepEqual(extractUptime({ body: { uptimeSeconds: 3661 } }), {
    uptimeSeconds: 3661,
    uptimeText: "1小时1分钟1秒",
    note: null,
  });
  assert.deepEqual(extractUptime({ body: "13小时38分54秒" }), {
    uptimeSeconds: null,
    uptimeText: "13小时38分54秒",
    note: null,
  });
  assert.deepEqual(extractUptime({ _encrypted: true, params: "xxx" }), {
    uptimeSeconds: null,
    uptimeText: null,
    note: "response-encrypted-需配置私钥",
  });
  assert.equal(extractUptime({}).note !== null, true);
  assert.equal(extractUptime(null).uptimeText, null);
});

test("hintForLoginError 覆盖三种短信验证错误码", () => {
  assert.match(hintForLoginError("30002009", "x"), /未授信设备/);
  assert.match(hintForLoginError("30002060", "x"), /二次验证/);
  assert.match(hintForLoginError("30002063", "x"), /增强安全策略/);
  assert.match(hintForLoginError("10001", "bad password"), /账号或密码错误/);
});

test("pickMachine 优先匹配 ECLOUD_INSTANCE_ID，否则取第一个", () => {
  const machines = [
    { instanceId: "i-1", machineId: "m-1", machineName: "A" },
    { instanceId: "i-2", machineId: "m-2", machineName: "B", status: "Running" },
  ];
  assert.equal(pickMachine(machines, "i-2").instanceId, "i-2");
  assert.equal(pickMachine(machines, "i-2").status, "Running");
  assert.equal(pickMachine(machines, "i-404").instanceId, "i-1");
  assert.equal(pickMachine(machines).instanceId, "i-1");
  // 服务端偶发返回数字型 id，需要归一成字符串
  assert.equal(pickMachine([{ instanceId: 42 }], "42").instanceId, "42");
  assert.throws(() => pickMachine([], "x"), /桌面列表为空/);
  assert.throws(() => pickMachine(null), /桌面列表为空/);
});

test("场景 ①：正常一轮（已有 token 与选中桌面）", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });

  const { factory, trace } = createFactory({
    desktopUptime: () => ({ body: { uptimeSeconds: 3661 } }),
    machineConnect: () => ({ errorCode: 0 }),
  });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, true);
  assert.equal(result.stage, "done");
  assert.equal(result.uptimeSeconds, 3661);
  assert.equal(result.uptimeText, "1小时1分钟1秒");
  assert.equal(result.connectStatus, 0);
  assert.equal(result.tokenExpired, false);
  assert.equal(result.error, null);
  assert.equal(result.attempt, 1);
  assert.equal(result.ts, SAVED_AT);

  assert.deepEqual(trace.uptimeCalls, ["i-1"]);
  assert.deepEqual(trace.connectCalls, [{ instanceId: "i-1", machineId: "m-1", token: "token-ok" }]);
  assert.equal(trace.deviceInfoCalls, 0, "已有选中桌面时不应重复拉列表");

  const lastRun = await state.getLastRun();
  assert.equal(lastRun.ok, true);
  assert.equal(lastRun.uptimeText, "1小时1分钟1秒");
  assert.equal(lastRun.ts, SAVED_AT);

  const logs = await state.getLogs();
  assert.ok(logs.length >= 1);
  assert.equal(logs.at(-1).level, "info");
});

test("场景 ②：无 token → 自动重登（含字符串 body 的 uptime 透传）", async (t) => {
  silenceConsole(t);
  const state = createState();
  const config = loadConfig({ ECLOUD_USERNAME: "user1", ECLOUD_PASSWORD: "pass1" });

  const { factory, trace } = createFactory({
    loginWithPassword: () => ({ body: { accessTicket: "ticket-1" } }),
    verifyAccessTicket: () => ({ body: { accessToken: "token-new" } }),
    getDeviceInfo: () => [
      { instanceId: "i-9", machineId: "m-9", machineName: "M9", status: "Running" },
    ],
    desktopUptime: () => ({ body: "13小时38分54秒" }),
    machineConnect: () => ({ errorCode: "0" }),
  });

  const result = await runKeepaliveRound({ state, config, makeClient: factory, now: FIXED_NOW });

  assert.equal(result.ok, true);
  assert.equal(result.uptimeSeconds, null);
  assert.equal(result.uptimeText, "13小时38分54秒");
  assert.equal(result.connectStatus, "0");

  assert.equal(trace.loginCalls.length, 1);
  assert.equal(trace.loginCalls[0].username, "user1");
  assert.equal(trace.ticket, "ticket-1");

  const credentials = await state.getCredentials();
  assert.equal(credentials.accessToken, "token-new");
  assert.equal(credentials.username, "user1");
  assert.equal(credentials.savedAt, SAVED_AT);

  const selected = await state.getSelected();
  assert.equal(selected.instanceId, "i-9");
  assert.equal(selected.machineId, "m-9");
  assert.equal(selected.machineName, "M9");

  const machines = await state.getMachines();
  assert.equal(machines.items.length, 1);
  assert.equal(machines.items[0].instanceId, "i-9");
  assert.equal(machines.fetchedAt, SAVED_AT);
});

test("场景 ③：token 过期 → 重登成功 → 自动重跑第 2 轮", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-stale", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });
  const config = loadConfig({ ECLOUD_USERNAME: "user", ECLOUD_PASSWORD: "pass" });

  const { factory, trace } = createFactory({
    loginWithPassword: () => ({ body: { accessTicket: "ticket-2" } }),
    verifyAccessTicket: () => ({ body: { accessToken: "token-fresh" } }),
    getDeviceInfo: () => [],
    desktopUptime: () => ({ body: { uptimeSeconds: 10 } }),
    machineConnect: (instanceId, machineId, token) =>
      token === "token-stale"
        ? { errorCode: "40010001", errorMsg: "accessToken expired" }
        : { errorCode: 0 },
  });

  const result = await runKeepaliveRound({ state, config, makeClient: factory, now: FIXED_NOW });

  assert.equal(result.ok, true);
  assert.equal(result.attempt, 2);
  assert.equal(result.connectStatus, 0);
  assert.equal(trace.loginCalls.length, 1);
  assert.equal(trace.connectCalls.length, 2, "过期那次 + 重登后那次");

  const credentials = await state.getCredentials();
  assert.equal(credentials.accessToken, "token-fresh");
});

test("场景 ③b：token 过期但 AUTO_RELOGIN=false → 直接报错不重登", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-stale", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });
  const config = loadConfig({
    ECLOUD_USERNAME: "user",
    ECLOUD_PASSWORD: "pass",
    AUTO_RELOGIN: "false",
  });

  const { factory, trace } = createFactory({
    desktopUptime: () => ({ body: { uptimeSeconds: 10 } }),
    machineConnect: () => ({ errorCode: "401", errorMsg: "token is expired" }),
  });

  const result = await runKeepaliveRound({ state, config, makeClient: factory, now: FIXED_NOW });

  assert.equal(result.ok, false);
  assert.equal(result.tokenExpired, true);
  assert.equal(result.stage, "connect");
  assert.match(result.error, /已过期/);
  assert.equal(trace.loginCalls.length, 0);
});

test("场景 ④：body 为字符串时原样透传，不做二次格式化", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });

  const { factory } = createFactory({
    desktopUptime: () => ({ body: "13小时38分54秒" }),
    machineConnect: () => ({ errorCode: 0 }),
  });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.uptimeText, "13小时38分54秒");
  assert.equal(result.uptimeSeconds, null);
  assert.equal((await state.getLastRun()).uptimeText, "13小时38分54秒");
});

test("场景 ⑤：桌面列表为空时报错并停在 machines 阶段", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });

  const { factory } = createFactory({ getDeviceInfo: () => [] });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "machines");
  assert.match(result.error, /未找到任何桌面实例/);

  const lastRun = await state.getLastRun();
  assert.equal(lastRun.ok, false);
  assert.equal(lastRun.connectStatus, "unknown");
});

test("未登录且未配置账号密码 → credentials 阶段失败", async (t) => {
  silenceConsole(t);
  const state = createState();
  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: createFactory({}).factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "credentials");
  assert.match(result.error, /ECLOUD_USERNAME/);
});

test("未登录且 AUTO_RELOGIN=false → 提示只能手动登录", async (t) => {
  silenceConsole(t);
  const state = createState();
  const config = loadConfig({
    ECLOUD_USERNAME: "user",
    ECLOUD_PASSWORD: "pass",
    AUTO_RELOGIN: "false",
  });
  const result = await runKeepaliveRound({
    state,
    config,
    makeClient: createFactory({}).factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "credentials");
  assert.match(result.error, /AUTO_RELOGIN=false/);
});

test("自动登录被服务端拒绝（错误码 30002060）→ login 阶段失败并给出人话提示", async (t) => {
  silenceConsole(t);
  const state = createState();
  const config = loadConfig({ ECLOUD_USERNAME: "user", ECLOUD_PASSWORD: "pass" });
  const { factory } = createFactory({
    loginWithPassword: () => ({ errorCode: "30002060", errorMsg: "need two factor" }),
  });

  const result = await runKeepaliveRound({ state, config, makeClient: factory, now: FIXED_NOW });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "login");
  assert.match(result.error, /二次验证/);
  assert.equal(await state.getCredentials(), null);
});

test("响应被加密（无私钥）→ uptime 降级 + connect 状态未知 + ok=false", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });

  const { factory } = createFactory({
    desktopUptime: () => ({ _encrypted: true, params: "cipher" }),
    machineConnect: () => ({ _encrypted: true, params: "cipher" }),
  });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.uptimeSeconds, null);
  assert.equal(result.uptimeText, null);
  assert.equal(result.note, "response-encrypted-需配置私钥");
  assert.equal(result.connectStatus, "unknown");
  assert.match(result.error, /ECLOUD_RSA_PRIVATE_KEY/);
});

test("会话登记返回非 token 类错误码 → ok=false 但 tokenExpired=false", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });

  const { factory } = createFactory({
    desktopUptime: () => ({ body: { uptimeSeconds: 5 } }),
    machineConnect: () => ({ errorCode: "50010001", errorMsg: "instance not running" }),
  });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.tokenExpired, false);
  assert.equal(result.connectStatus, "50010001");
  assert.match(result.error, /非 0 错误码/);
});

test("客户端抛错时 runKeepaliveRound 不抛异常，转成 uptime 阶段失败", async (t) => {
  silenceConsole(t);
  const state = createState();
  await state.setCredentials({ username: "user", accessToken: "token-ok", savedAt: SAVED_AT });
  await state.setSelected({ instanceId: "i-1", machineId: "m-1", machineName: "桌面1" });

  const { factory } = createFactory({
    desktopUptime: () => {
      throw new Error("ECLOUD_REQUEST_FAILED: 请求 /resource/desktopUptime 失败：network down");
    },
  });

  const result = await runKeepaliveRound({
    state,
    config: loadConfig({}),
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, false);
  assert.equal(result.stage, "uptime");
  assert.match(result.error, /network down/);
});

test("ECLOUD_INSTANCE_ID 优先于列表第一个", async (t) => {
  silenceConsole(t);
  const state = createState();
  const config = loadConfig({
    ECLOUD_INSTANCE_ID: "i-2",
    ECLOUD_USERNAME: "user",
    ECLOUD_PASSWORD: "pass",
  });

  const { factory } = createFactory({
    loginWithPassword: () => ({ body: { accessTicket: "t" } }),
    verifyAccessTicket: () => ({ body: { accessToken: "at" } }),
    getDeviceInfo: () => [
      { instanceId: "i-1", machineId: "m-1", machineName: "第一个" },
      { instanceId: "i-2", machineId: "m-2", machineName: "期望的" },
    ],
    desktopUptime: () => ({ body: { uptimeSeconds: 1 } }),
    machineConnect: () => ({ errorCode: 0 }),
  });

  // 登录后 login() 内部会自动选中；这里只验证最终选中项
  const result = await runKeepaliveRound({
    state,
    config,
    makeClient: factory,
    now: FIXED_NOW,
  });

  assert.equal(result.ok, true);
  const selected = await state.getSelected();
  assert.equal(selected.instanceId, "i-2");
  assert.equal(selected.machineName, "期望的");
});

test("入参缺失时抛出 TypeError（内部错误，不吞）", async () => {
  await assert.rejects(() => runKeepaliveRound({ config: loadConfig({}) }), TypeError);
});
