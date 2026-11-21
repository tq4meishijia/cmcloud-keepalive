/**
 * 状态存储抽象：KV 优先，未绑定 KV 时回退到进程内 Map。
 *
 * 上游把 `data/credentials.json`、`data/device.json`、`data/selected_instance.json`
 * 直接写在文件系统里（`protocol.py:58-62`）；Workers 没有可写文件系统，因此：
 *
 *   data/credentials.json        → state:credentials
 *   data/device.json             → state:device
 *   data/selected_instance.json  → state:selected
 *   新增（可观测性）              → state:machines / state:lastRun / state:logs
 *
 * 回退用的 Map 是**模块级单例**：同一 isolate 内的多次请求共享它，
 * 因此 `wrangler dev` 不绑 KV 也能完整跑通面板与手动保活；isolate 回收后丢失。
 *
 * @module store
 */

import { CLIENT_VERSION, COMPANY_CODE } from "./ecloud/constants.js";
import { utc8NowText } from "./ecloud/signature.js";

/** KV 键名常量。 */
export const STATE_KEYS = Object.freeze({
  device: "state:device",
  credentials: "state:credentials",
  selected: "state:selected",
  machines: "state:machines",
  lastRun: "state:lastRun",
  logs: "state:logs",
});

/** 日志环形缓冲上限（与任务书一致：最近 50 条）。 */
export const MAX_LOG_ENTRIES = 50;

/** `/api/diagnose` 的 KV 写探测键。 */
export const PROBE_KEY = "state:probe";

/**
 * 内存 KV 适配器：接口与 Cloudflare KV 的最小交集保持一致
 * （`get` 返回字符串或 null，`put` / `delete` 返回 Promise）。
 */
export class MemoryKv {
  constructor() {
    /** @type {Map<string, string>} */
    this.map = new Map();
  }

  /**
   * @param {string} key 键。
   * @returns {Promise<string|null>} 值。
   */
  async get(key) {
    return this.map.has(key) ? this.map.get(key) : null;
  }

  /**
   * @param {string} key 键。
   * @param {string} value 值。
   * @returns {Promise<void>} 完成。
   */
  async put(key, value) {
    this.map.set(key, String(value));
  }

  /**
   * @param {string} key 键。
   * @returns {Promise<void>} 完成。
   */
  async delete(key) {
    this.map.delete(key);
  }

  /** @returns {number} 当前键数量（仅调试用）。 */
  get size() {
    return this.map.size;
  }
}

/**
 * 模块级回退存储：同一 isolate 内共享，等价于"单进程内状态"。
 * 放在模块作用域是有意为之——每个请求新建 Map 会导致状态丢失。
 */
const fallbackKv = new MemoryKv();

/**
 * 生成设备指纹（对应上游 `protocol.py:187-198`）。
 *
 * @returns {{deviceUid: string, deviceId: string, deviceName: string, osType: string, osVersion: string, arch: string, clientVersion: string, companyCode: string}} 设备指纹。
 */
export function createDeviceFingerprint() {
  return {
    deviceUid: crypto.randomUUID().replace(/-/g, ""),
    deviceId: crypto.randomUUID().replace(/-/g, ""),
    deviceName: "Ecloud-Keepalive",
    osType: "linux",
    osVersion: "5.10.134",
    arch: "x86_64",
    clientVersion: CLIENT_VERSION,
    companyCode: COMPANY_CODE,
  };
}

/**
 * 把桌面列表裁剪成统一结构（丢弃服务端的其余字段，避免状态膨胀）。
 *
 * @param {Array<Record<string, unknown>>} items 原始 machineList。
 * @returns {Array<{instanceId: string, machineId: string, machineName: string, status: unknown}>} 裁剪后的列表。
 */
function normalizeMachines(items) {
  if (!Array.isArray(items)) return [];
  return items.map((item) => ({
    instanceId: String(item?.instanceId ?? ""),
    machineId: String(item?.machineId ?? ""),
    machineName: String(item?.machineName ?? ""),
    status: item?.status ?? null,
  }));
}

/**
 * 带类型化访问器的状态仓库。
 *
 * 所有读写都是「JSON 字符串 ↔ 对象」，键名统一带 `state:` 前缀。
 */
export class StateStore {
  /**
   * @param {object} options 构造参数。
   * @param {{get: Function, put: Function, delete: Function}} options.kv KV 适配器。
   * @param {"kv"|"memory"} [options.kind] 存储种类，会透出到 `/api/status`。
   * @param {() => Date} [options.now] 时钟，用于生成日志时间戳。
   */
  constructor({ kv, kind = "memory", now = () => new Date() } = {}) {
    if (!kv || typeof kv.get !== "function" || typeof kv.put !== "function") {
      throw new TypeError("StateStore 需要提供 get/put 的 KV 适配器");
    }
    this.kv = kv;
    this.kind = kind;
    this.now = now;
  }

  /**
   * 读 JSON。
   *
   * @param {string} key 键。
   * @returns {Promise<unknown|null>} 解析结果；键不存在或内容损坏时返回 null。
   */
  async getJson(key) {
    const raw = await this.kv.get(key);
    if (raw === null || raw === undefined || raw === "") return null;
    try {
      return JSON.parse(raw);
    } catch {
      // 内容损坏不应让整轮保活崩掉：当作"没有状态"，上层会重建。
      return null;
    }
  }

  /**
   * 写 JSON。
   *
   * @param {string} key 键。
   * @param {unknown} value 值（会被 JSON.stringify）。
   * @returns {Promise<void>} 完成。
   */
  async putJson(key, value) {
    await this.kv.put(key, JSON.stringify(value));
  }

  /**
   * 删除键。
   *
   * @param {string} key 键。
   * @returns {Promise<void>} 完成。
   */
  async remove(key) {
    await this.kv.delete(key);
  }

  /**
   * 读设备指纹。
   *
   * @returns {Promise<object|null>} 设备指纹。
   */
  async getDevice() {
    const device = await this.getJson(STATE_KEYS.device);
    return device && typeof device === "object" ? device : null;
  }

  /**
   * 读设备指纹，不存在则生成并固化（对应上游 `load_or_create_device_config`）。
   *
   * @returns {Promise<object>} 设备指纹。
   */
  async ensureDevice() {
    const existing = await this.getDevice();
    if (existing?.deviceUid) return existing;
    const fingerprint = createDeviceFingerprint();
    await this.putJson(STATE_KEYS.device, fingerprint);
    return fingerprint;
  }

  /**
   * 读凭证。
   *
   * @returns {Promise<{username?: string, accessToken?: string, savedAt?: string}|null>} 凭证。
   */
  async getCredentials() {
    const creds = await this.getJson(STATE_KEYS.credentials);
    return creds && typeof creds === "object" ? creds : null;
  }

  /**
   * 写凭证。
   *
   * @param {{username: string, accessToken: string, savedAt: string}} credentials 凭证。
   * @returns {Promise<void>} 完成。
   */
  async setCredentials(credentials) {
    await this.putJson(STATE_KEYS.credentials, {
      username: String(credentials?.username ?? ""),
      accessToken: String(credentials?.accessToken ?? ""),
      savedAt: String(credentials?.savedAt ?? utc8NowText(this.now())),
    });
  }

  /**
   * 清除凭证（保留设备指纹与桌面选择）。
   *
   * @returns {Promise<void>} 完成。
   */
  async clearCredentials() {
    await this.remove(STATE_KEYS.credentials);
  }

  /**
   * 读选中桌面。
   *
   * @returns {Promise<{instanceId?: string, machineId?: string, machineName?: string}|null>} 选中桌面。
   */
  async getSelected() {
    const selected = await this.getJson(STATE_KEYS.selected);
    return selected && typeof selected === "object" ? selected : null;
  }

  /**
   * 写选中桌面。
   *
   * @param {{instanceId: string, machineId?: string, machineName?: string}} selected 选中桌面。
   * @returns {Promise<void>} 完成。
   */
  async setSelected(selected) {
    await this.putJson(STATE_KEYS.selected, {
      instanceId: String(selected?.instanceId ?? ""),
      machineId: String(selected?.machineId ?? ""),
      machineName: String(selected?.machineName ?? ""),
    });
  }

  /**
   * 读桌面列表缓存。
   *
   * @returns {Promise<{items: Array<object>, fetchedAt: string}|null>} 缓存。
   */
  async getMachines() {
    const cached = await this.getJson(STATE_KEYS.machines);
    if (!cached || typeof cached !== "object") return null;
    return { items: normalizeMachines(cached.items), fetchedAt: String(cached.fetchedAt ?? "") };
  }

  /**
   * 写桌面列表缓存。
   *
   * @param {Array<Record<string, unknown>>} items 原始 machineList。
   * @returns {Promise<{items: Array<object>, fetchedAt: string}>} 实际写入的内容。
   */
  async setMachines(items) {
    const payload = { items: normalizeMachines(items), fetchedAt: utc8NowText(this.now()) };
    await this.putJson(STATE_KEYS.machines, payload);
    return payload;
  }

  /**
   * 读最近一次保活结果。
   *
   * @returns {Promise<object|null>} lastRun。
   */
  async getLastRun() {
    const lastRun = await this.getJson(STATE_KEYS.lastRun);
    return lastRun && typeof lastRun === "object" ? lastRun : null;
  }

  /**
   * 写最近一次保活结果。
   *
   * @param {object} entry 结果对象。
   * @returns {Promise<object>} 实际写入的内容。
   */
  async setLastRun(entry) {
    const payload = {
      ts: String(entry?.ts ?? utc8NowText(this.now())),
      ok: Boolean(entry?.ok),
      uptimeSeconds: typeof entry?.uptimeSeconds === "number" ? entry.uptimeSeconds : null,
      uptimeText: typeof entry?.uptimeText === "string" ? entry.uptimeText : null,
      connectStatus: entry?.connectStatus ?? "unknown",
      tokenExpired: Boolean(entry?.tokenExpired),
      error: entry?.error ?? null,
    };
    await this.putJson(STATE_KEYS.lastRun, payload);
    return payload;
  }

  /**
   * 读日志。
   *
   * @returns {Promise<Array<{ts: string, level: string, msg: string}>>} 日志（旧 → 新）。
   */
  async getLogs() {
    const logs = await this.getJson(STATE_KEYS.logs);
    return Array.isArray(logs) ? logs : [];
  }

  /**
   * 追加一条日志，超过 {@link MAX_LOG_ENTRIES} 条时丢弃最旧的。
   *
   * KV 无原子追加，并发写可能丢日志——对"最近 50 条诊断线索"这一用途可接受，
   * 已在 `docs/PORTING.md` 记录。
   *
   * @param {string} level 级别：`info` / `warn` / `error`。
   * @param {string} message 文案。
   * @returns {Promise<Array<{ts: string, level: string, msg: string}>>} 写入后的日志。
   */
  async appendLog(level, message) {
    const logs = await this.getLogs();
    logs.push({
      ts: utc8NowText(this.now()),
      level: String(level || "info"),
      msg: String(message ?? ""),
    });
    const trimmed = logs.slice(-MAX_LOG_ENTRIES);
    await this.putJson(STATE_KEYS.logs, trimmed);
    return trimmed;
  }

  /**
   * 存储可用性探测（供 `/api/diagnose`）。
   *
   * @returns {Promise<{ok: boolean, detail: string}>} 探测结果。
   */
  async probe() {
    if (this.kind !== "kv") {
      return {
        ok: true,
        detail: "未绑定 KEEPALIVE_KV：正在使用进程内存储，仅适合本地 wrangler dev；线上部署必须绑定 KV，否则状态会在实例回收后丢失",
      };
    }
    const token = `probe-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    try {
      await this.kv.put(PROBE_KEY, token);
      const readBack = await this.kv.get(PROBE_KEY);
      if (readBack !== null && readBack !== token) {
        return { ok: false, detail: `KEEPALIVE_KV 写入后读回不一致（期望 ${token}，实际 ${readBack}）` };
      }
      try {
        await this.kv.delete(PROBE_KEY);
      } catch {
        // 清理失败不影响结论。
      }
      return {
        ok: true,
        detail:
          readBack === token
            ? "KEEPALIVE_KV 读写正常"
            : "KEEPALIVE_KV 写入成功（本次读取为空，KV 为最终一致，属正常现象）",
      };
    } catch (error) {
      return {
        ok: false,
        detail: `KEEPALIVE_KV 不可用：${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }
}

/**
 * 根据 env 创建状态仓库：绑定 `KEEPALIVE_KV` 则用 KV，否则回退内存。
 *
 * @param {Record<string, unknown>} [env] Workers env。
 * @param {object} [options] 选项。
 * @param {() => Date} [options.now] 时钟。
 * @returns {{state: StateStore, kind: "kv"|"memory"}} 仓库与存储种类。
 */
export function createStore(env = {}, { now = () => new Date() } = {}) {
  const binding = env?.KEEPALIVE_KV;
  if (binding && typeof binding.get === "function" && typeof binding.put === "function") {
    return { state: new StateStore({ kv: binding, kind: "kv", now }), kind: "kv" };
  }
  return { state: new StateStore({ kv: fallbackKv, kind: "memory", now }), kind: "memory" };
}
