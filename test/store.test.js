/**
 * 状态存储测试。
 *
 * 覆盖：内存回退读写、日志环形缓冲截断到 50 条、KV 适配器（用假 KV 对象）、
 * 设备指纹固化、`state:` 前缀约定、`/api/diagnose` 的存储探测。
 */

import assert from "node:assert/strict";
import test from "node:test";

import {
  MAX_LOG_ENTRIES,
  MemoryKv,
  PROBE_KEY,
  STATE_KEYS,
  StateStore,
  createDeviceFingerprint,
  createStore,
} from "../src/store.js";

const FIXED_NOW = () => new Date("2026-01-02T03:04:05Z");
const TS = "2026-01-02 11:04:05";

/**
 * 会记录写入轨迹的假 KV，接口与 Cloudflare KV 最小交集一致。
 */
class RecordingKv {
  constructor() {
    this.map = new Map();
    this.puts = [];
    this.deletes = [];
    this.failOnPut = false;
  }

  async get(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }

  async put(key, value) {
    if (this.failOnPut) throw new Error("KV put 被拒绝");
    this.puts.push([key, value]);
    this.map.set(key, String(value));
  }

  async delete(key) {
    this.deletes.push(key);
    this.map.delete(key);
  }
}

/**
 * 造一个独立 StateStore。
 *
 * @param {object} [kv] KV 适配器。
 * @param {"kv"|"memory"} [kind] 存储种类。
 * @returns {StateStore} 仓库。
 */
function createState(kv = new MemoryKv(), kind = "memory") {
  return new StateStore({ kv, kind, now: FIXED_NOW });
}

test("所有键名都以 state: 前缀开头", () => {
  for (const key of Object.values(STATE_KEYS)) {
    assert.match(key, /^state:/);
  }
  assert.match(PROBE_KEY, /^state:/);
  assert.equal(new Set(Object.values(STATE_KEYS)).size, Object.values(STATE_KEYS).length);
});

test("MemoryKv 基本读写与删除", async () => {
  const kv = new MemoryKv();
  assert.equal(await kv.get("k"), null);
  await kv.put("k", "v");
  assert.equal(await kv.get("k"), "v");
  await kv.put("k", 123);
  assert.equal(await kv.get("k"), "123");
  await kv.delete("k");
  assert.equal(await kv.get("k"), null);
  assert.equal(kv.size, 0);
});

test("createStore 按是否绑定 KEEPALIVE_KV 选择实现", () => {
  const memory = createStore({}, { now: FIXED_NOW });
  assert.equal(memory.kind, "memory");
  assert.equal(memory.state.kind, "memory");

  const kv = createStore({ KEEPALIVE_KV: new RecordingKv() }, { now: FIXED_NOW });
  assert.equal(kv.kind, "kv");
  assert.equal(kv.state.kind, "kv");
});

test("getJson 对缺失键与损坏内容都返回 null", async () => {
  const kv = new RecordingKv();
  const state = createState(kv);
  assert.equal(await state.getJson("state:missing"), null);
  kv.map.set("state:broken", "{not json");
  assert.equal(await state.getJson("state:broken"), null);
  assert.equal(await state.getJson("state:empty"), null);
  kv.map.set("state:empty", "");
  assert.equal(await state.getJson("state:empty"), null);
});

test("putJson 写入 JSON 字符串且带 state: 前缀", async () => {
  const kv = new RecordingKv();
  const state = createState(kv);
  await state.putJson(STATE_KEYS.device, { a: 1 });
  assert.equal(kv.puts.length, 1);
  assert.equal(kv.puts[0][0], "state:device");
  assert.equal(kv.puts[0][1], '{"a":1}');
  assert.deepEqual(await state.getJson(STATE_KEYS.device), { a: 1 });
});

test("设备指纹首次生成后固化", async () => {
  const state = createState();
  const first = await state.ensureDevice();
  assert.match(first.deviceUid, /^[0-9a-f]{32}$/);
  assert.match(first.deviceId, /^[0-9a-f]{32}$/);
  assert.equal(first.deviceName, "Ecloud-Keepalive");
  assert.equal(first.osType, "linux");
  assert.equal(first.osVersion, "5.10.134");
  assert.equal(first.arch, "x86_64");
  assert.equal(first.clientVersion, "3.8.2");
  assert.equal(first.companyCode, "ECloud");

  const second = await state.ensureDevice();
  assert.equal(second.deviceUid, first.deviceUid);
  assert.equal(await state.getDevice().then((device) => device.deviceUid), first.deviceUid);
});

test("createDeviceFingerprint 每次生成不同 deviceUid", () => {
  const a = createDeviceFingerprint();
  const b = createDeviceFingerprint();
  assert.notEqual(a.deviceUid, b.deviceUid);
  assert.notEqual(a.deviceId, b.deviceId);
});

test("凭证读写与清除", async () => {
  const state = createState();
  assert.equal(await state.getCredentials(), null);

  await state.setCredentials({ username: "u", accessToken: "t", savedAt: TS });
  const credentials = await state.getCredentials();
  assert.deepEqual(credentials, { username: "u", accessToken: "t", savedAt: TS });

  await state.clearCredentials();
  assert.equal(await state.getCredentials(), null);
});

test("setCredentials 缺字段时补空值与当前时间", async () => {
  const state = createState();
  await state.setCredentials({ username: "u" });
  const credentials = await state.getCredentials();
  assert.equal(credentials.accessToken, "");
  assert.equal(credentials.savedAt, TS);
});

test("选中桌面读写只保留三个字段", async () => {
  const state = createState();
  assert.equal(await state.getSelected(), null);
  await state.setSelected({
    instanceId: "i-1",
    machineId: "m-1",
    machineName: "桌面1",
    extra: "应被丢弃",
  });
  assert.deepEqual(await state.getSelected(), {
    instanceId: "i-1",
    machineId: "m-1",
    machineName: "桌面1",
  });
});

test("桌面列表缓存做归一化并记录 fetchedAt", async () => {
  const state = createState();
  assert.equal(await state.getMachines(), null);

  const stored = await state.setMachines([
    { instanceId: "i-1", machineId: "m-1", machineName: "A", status: "Running", junk: true },
    { instanceId: 2, machineId: 3 },
  ]);
  assert.equal(stored.fetchedAt, TS);
  assert.deepEqual(stored.items, [
    { instanceId: "i-1", machineId: "m-1", machineName: "A", status: "Running" },
    { instanceId: "2", machineId: "3", machineName: "", status: null },
  ]);

  const cached = await state.getMachines();
  assert.equal(cached.fetchedAt, TS);
  assert.equal(cached.items.length, 2);
  // 非数组输入退化为空列表，不抛错
  assert.deepEqual((await state.setMachines(null)).items, []);
});

test("lastRun 归一化：缺字段补 null / unknown", async () => {
  const state = createState();
  assert.equal(await state.getLastRun(), null);

  const stored = await state.setLastRun({ ok: true, uptimeSeconds: 12, connectStatus: 0 });
  assert.deepEqual(stored, {
    ts: TS,
    ok: true,
    uptimeSeconds: 12,
    uptimeText: null,
    connectStatus: 0,
    tokenExpired: false,
    error: null,
  });

  const failed = await state.setLastRun({
    ok: false,
    uptimeSeconds: null,
    uptimeText: "13小时38分54秒",
    connectStatus: "500",
    tokenExpired: true,
    error: "boom",
    ts: "2026-01-02 12:00:00",
  });
  assert.equal(failed.uptimeSeconds, null);
  assert.equal(failed.uptimeText, "13小时38分54秒");
  assert.equal(failed.tokenExpired, true);
  assert.equal(failed.error, "boom");
  assert.equal(failed.ts, "2026-01-02 12:00:00");
});

test("日志环形缓冲截断到 50 条，保留最新的", async () => {
  const state = createState();
  assert.deepEqual(await state.getLogs(), []);

  for (let i = 1; i <= MAX_LOG_ENTRIES + 10; i += 1) {
    await state.appendLog("info", `log-${i}`);
  }
  const logs = await state.getLogs();
  assert.equal(logs.length, MAX_LOG_ENTRIES);
  assert.equal(logs[0].msg, "log-11");
  assert.equal(logs.at(-1).msg, `log-${MAX_LOG_ENTRIES + 10}`);
  assert.equal(logs[0].ts, TS);
  assert.equal(logs[0].level, "info");

  // 级别与文案都要原样保留
  await state.appendLog("error", "出错了");
  const after = await state.getLogs();
  assert.equal(after.at(-1).level, "error");
  assert.equal(after.at(-1).msg, "出错了");
  assert.equal(after.length, MAX_LOG_ENTRIES);
});

test("日志默认级别为 info", async () => {
  const state = createState();
  await state.appendLog(undefined, undefined);
  const logs = await state.getLogs();
  assert.equal(logs[0].level, "info");
  assert.equal(logs[0].msg, "");
});

test("probe：内存回退给出告警但视为可用", async () => {
  const state = createState();
  const result = await state.probe();
  assert.equal(result.ok, true);
  assert.match(result.detail, /KEEPALIVE_KV/);
});

test("probe：绑定 KV 时写入并清理探测键", async () => {
  const kv = new RecordingKv();
  const state = createState(kv, "kv");
  const result = await state.probe();
  assert.equal(result.ok, true);
  assert.match(result.detail, /KEEPALIVE_KV/);
  assert.equal(kv.puts.length, 1);
  assert.equal(kv.puts[0][0], PROBE_KEY);
  assert.deepEqual(kv.deletes, [PROBE_KEY]);
  assert.equal(kv.map.has(PROBE_KEY), false);
});

test("probe：KV 写入失败时 ok=false 并带上原因", async () => {
  const kv = new RecordingKv();
  kv.failOnPut = true;
  const state = createState(kv, "kv");
  const result = await state.probe();
  assert.equal(result.ok, false);
  assert.match(result.detail, /KEEPALIVE_KV 不可用/);
  assert.match(result.detail, /put 被拒绝/);
});

test("StateStore 构造参数校验", () => {
  assert.throws(() => new StateStore({}), TypeError);
  assert.throws(() => new StateStore({ kv: { get: () => null } }), TypeError);
});
