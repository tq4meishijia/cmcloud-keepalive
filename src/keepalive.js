/**
 * 保活编排（对应上游 `main.py` 的 `cmd_login` / `cmd_desktop_keepalive`）。
 *
 * 上游是 `while True: sleep(interval)` + 交互式 `input()`；Workers 没有常驻进程，
 * 因此拆成两个可被 Cron / HTTP 反复调用的纯函数：
 *
 *   - {@link login}：账号密码 → accessTicket → accessToken → 落盘 + 自动选中桌面
 *   - {@link runKeepaliveRound}：单轮保活（uptime + connect），token 过期时最多重登重跑一次
 *
 * 所有外部依赖（时钟、客户端、存储）都可注入，测试不需要真实网络。
 *
 * @module keepalive
 */

import { loadConfig } from "./config.js";
import { EcloudClient } from "./ecloud/client.js";
import { utc8NowText } from "./ecloud/signature.js";

/** 单轮保活最多尝试次数（含首轮），防止 token 失效时无限重登。 */
export const MAX_ROUND_ATTEMPTS = 2;

/**
 * 秒数 → 中文运行时长，逐字符对齐上游 `main.py:224-238`。
 *
 * 规则：天/小时/分钟为 0 时省略该段，"秒"永远输出。
 *
 * @param {number} seconds 秒数。
 * @returns {string} 例如 `1天1小时1分钟1秒`；非法输入返回 `0秒`。
 * @example
 * formatUptime(0);      // "0秒"
 * formatUptime(60);     // "1分钟0秒"
 * formatUptime(90061);  // "1天1小时1分钟1秒"
 */
export function formatUptime(seconds) {
  const numeric = Number(seconds);
  if (!Number.isFinite(numeric)) return "0秒";
  const total = Math.max(0, Math.trunc(numeric));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const restSeconds = total % 60;

  let text = "";
  if (days > 0) text += `${days}天`;
  if (hours > 0) text += `${hours}小时`;
  if (minutes > 0) text += `${minutes}分钟`;
  return `${text}${restSeconds}秒`;
}

/**
 * 把异常转成 "错误码: 信息" 形式文本。
 *
 * @param {unknown} error 异常。
 * @returns {string} 可诊断文本。
 */
export function describeError(error) {
  if (error instanceof Error) {
    const code = typeof error.code === "string" && error.code !== "" ? `${error.code}: ` : "";
    return `${code}${error.message}`;
  }
  return String(error);
}

/**
 * 登录失败错误码 → 人话提示（对齐上游 `main.py:63-68`，只提示、不实现短信流程）。
 *
 * @param {unknown} errorCode 服务端 errorCode。
 * @param {unknown} errorMsg 服务端 errorMsg。
 * @returns {string} 提示文案。
 */
export function hintForLoginError(errorCode, errorMsg) {
  switch (String(errorCode ?? "")) {
    case "30002009":
      return "未授信设备，需要短信验证：请先在官方客户端完成设备授信（上游同样未实现短信流程）";
    case "30002060":
      return "需要二次验证，请检查手机短信并在官方客户端完成验证（上游未实现短信流程）";
    case "30002063":
      return "触发增强安全策略，需要短信验证（上游未实现短信流程）";
    default:
      return `登录失败：账号或密码错误（errorCode=${errorCode ?? "无"}, errorMsg=${errorMsg ?? "无"}）`;
  }
}

/**
 * 构造日志函数：同时写 Workers 控制台（`wrangler tail` 可见）与 `state:logs`。
 *
 * 日志写入失败不会中断保活流程，只在控制台告警。
 *
 * @param {object} state `StateStore` 实例（提供 appendLog）。
 * @param {((level: string, message: string) => unknown)|null} log 外部注入的日志函数。
 * @returns {(level: string, message: string) => Promise<void>} 日志函数。
 */
function createLogger(state, log) {
  const emitToConsole = (level, message) => {
    const line = `[keepalive] ${message}`;
    if (level === "error") {
      console.error(line);
    } else if (level === "warn") {
      console.warn(line);
    } else {
      console.log(line);
    }
  };

  if (typeof log === "function") {
    return async (level, message) => {
      try {
        await log(level, message);
      } catch (error) {
        emitToConsole("warn", `写日志失败：${describeError(error)}`);
      }
    };
  }

  return async (level, message) => {
    emitToConsole(level, message);
    if (!state || typeof state.appendLog !== "function") return;
    try {
      await state.appendLog(level, message);
    } catch (error) {
      emitToConsole("warn", `写 state:logs 失败：${describeError(error)}`);
    }
  };
}

/**
 * 从桌面列表中挑目标桌面：优先 `ECLOUD_INSTANCE_ID`，否则第一个。
 *
 * @param {Array<Record<string, unknown>>} machines 原始 machineList。
 * @param {string} [preferredInstanceId] 期望的实例 ID。
 * @returns {{instanceId: string, machineId: string, machineName: string, status: unknown}} 选中项。
 */
export function pickMachine(machines, preferredInstanceId = "") {
  const normalized = (Array.isArray(machines) ? machines : []).map((item) => ({
    instanceId: String(item?.instanceId ?? ""),
    machineId: String(item?.machineId ?? ""),
    machineName: String(item?.machineName ?? ""),
    status: item?.status ?? null,
  }));
  if (normalized.length === 0) {
    throw new Error("桌面列表为空，无法选择实例");
  }
  if (preferredInstanceId) {
    const matched = normalized.find((item) => item.instanceId === preferredInstanceId);
    if (matched) return matched;
  }
  return normalized[0];
}

/**
 * 解析运行时长响应。
 *
 * 三种形态都要兼容（上游缺陷 C 的连带问题）：
 *   1. `{ body: { uptimeSeconds: 123 } }` → 数字
 *   2. `{ body: "13小时38分54秒" }`        → 直接作为文本（README 实测就是这个形态）
 *   3. `{ params: "<密文>" }` 有私钥缺失   → 已被 client 转成 `{_encrypted:true}`
 *
 * @param {Record<string, unknown>|null|undefined} result 响应对象。
 * @returns {{uptimeSeconds: number|null, uptimeText: string|null, note: string|null}} 解析结果。
 */
export function extractUptime(result) {
  if (result && result._encrypted === true) {
    return { uptimeSeconds: null, uptimeText: null, note: "response-encrypted-需配置私钥" };
  }
  const body = result?.body;
  if (typeof body === "string") {
    return { uptimeSeconds: null, uptimeText: body, note: null };
  }
  if (typeof body === "number" && Number.isFinite(body)) {
    return { uptimeSeconds: body, uptimeText: formatUptime(body), note: null };
  }
  if (body && typeof body === "object") {
    const raw = body.uptimeSeconds;
    if (typeof raw === "number" && Number.isFinite(raw)) {
      return { uptimeSeconds: raw, uptimeText: formatUptime(raw), note: null };
    }
    if (typeof raw === "string" && raw.trim() !== "") {
      const numeric = Number(raw);
      if (Number.isFinite(numeric)) {
        return { uptimeSeconds: numeric, uptimeText: formatUptime(numeric), note: null };
      }
      return { uptimeSeconds: null, uptimeText: raw, note: null };
    }
  }
  return {
    uptimeSeconds: null,
    uptimeText: null,
    note: "响应中未找到运行时长字段（body 缺失或结构未知）",
  };
}

/**
 * 拉取桌面列表并落盘，同时自动选中一个（登录后与首轮保活共用）。
 *
 * @param {object} options 参数。
 * @param {{getDeviceInfo: Function}} options.client 已带 token 的客户端。
 * @param {object} options.state StateStore。
 * @param {string} [options.preferredInstanceId] 期望实例 ID。
 * @param {(level: string, message: string) => Promise<void>} options.emit 日志函数。
 * @returns {Promise<{ok: boolean, machines: Array<object>, selected?: object, error?: string}>} 结果。
 */
async function refreshMachines({ client, state, preferredInstanceId = "", emit }) {
  const machines = await client.getDeviceInfo();
  if (!Array.isArray(machines) || machines.length === 0) {
    return { ok: false, machines: [], error: "未找到任何桌面实例（服务端返回空 machineList）" };
  }
  const selected = pickMachine(machines, preferredInstanceId);
  await state.setMachines(machines);
  await state.setSelected(selected);
  if (preferredInstanceId && selected.instanceId !== preferredInstanceId) {
    await emit(
      "warn",
      `ECLOUD_INSTANCE_ID=${preferredInstanceId} 不在桌面列表中，已回退到 ${
        selected.machineName || selected.instanceId
      }`,
    );
  }
  return { ok: true, machines, selected };
}

/**
 * 登录：账号密码 → accessTicket → accessToken → 落盘 → 刷新并选中桌面。
 *
 * 对应上游 `main.py:35-141`（`cmd_login`），差异在于不再 `input()`、不再 `sys.exit()`，
 * 而是返回结构化结果供 HTTP 层使用。
 *
 * @param {object} options 参数。
 * @param {object} options.config `loadConfig(env)` 的结果。
 * @param {object} options.state StateStore。
 * @param {() => Date} [options.now] 时钟。
 * @param {((level: string, message: string) => unknown)|null} [options.log] 外部日志函数。
 * @param {object|null} [options.device] 已加载的设备指纹（避免重复读存储）。
 * @param {((options: object) => object)|null} [options.makeClient] 客户端工厂（测试注入）。
 * @param {string} [options.username] 覆盖 config.username。
 * @param {string} [options.password] 覆盖 config.password。
 * @returns {Promise<{ok: boolean, errorCode?: unknown, hint?: string, username?: string, machines?: Array<object>, selected?: object|null, warning?: string}>} 结果。
 */
export async function login({
  config,
  state,
  now = () => new Date(),
  log = null,
  device = null,
  makeClient = null,
  username = "",
  password = "",
}) {
  const emit = createLogger(state, log);
  const account = String(username || config.username || "").trim();
  const secret = String(password || config.password || "");
  if (account === "" || secret === "") {
    return {
      ok: false,
      errorCode: null,
      hint: "缺少账号或密码：请 POST /api/login 提供，或配置 ECLOUD_USERNAME / ECLOUD_PASSWORD",
    };
  }

  const fingerprint = device || (await state.ensureDevice());
  const factory = makeClient || ((options) => new EcloudClient({ config, now, ...options }));
  const anonymous = factory({ accessToken: "", deviceUid: fingerprint.deviceUid });

  // Step 1: 密码登录，换 accessTicket。
  let ticketResponse;
  try {
    ticketResponse = await anonymous.loginWithPassword(account, secret);
  } catch (error) {
    await emit("error", `登录请求失败：${describeError(error)}`);
    return { ok: false, errorCode: null, hint: `登录请求失败：${describeError(error)}` };
  }

  const accessTicket = ticketResponse?.body?.accessTicket;
  if (!accessTicket) {
    const hint = hintForLoginError(ticketResponse?.errorCode, ticketResponse?.errorMsg);
    await emit("error", hint);
    return { ok: false, errorCode: ticketResponse?.errorCode ?? null, hint };
  }

  // Step 2: accessTicket → accessToken。
  let tokenResponse;
  try {
    tokenResponse = await anonymous.verifyAccessTicket(accessTicket);
  } catch (error) {
    await emit("error", `兑换 accessToken 失败：${describeError(error)}`);
    return { ok: false, errorCode: null, hint: `兑换 accessToken 失败：${describeError(error)}` };
  }

  const accessToken = tokenResponse?.body?.accessToken;
  if (!accessToken) {
    const hint = `兑换 accessToken 失败：服务端未返回 body.accessToken（errorCode=${
      tokenResponse?.errorCode ?? "无"
    }）`;
    await emit("error", hint);
    return { ok: false, errorCode: tokenResponse?.errorCode ?? null, hint };
  }

  // Step 3: 落盘凭证。
  const savedAt = utc8NowText(now());
  await state.setCredentials({ username: account, accessToken, savedAt });
  await emit("info", `登录成功：${account}（accessToken 已保存，末 6 位 ${accessToken.slice(-6)}）`);

  // Step 4: 刷新桌面列表并自动选中。
  const authed = factory({ accessToken, deviceUid: fingerprint.deviceUid });
  try {
    const refreshed = await refreshMachines({
      client: authed,
      state,
      preferredInstanceId: config.instanceId,
      emit,
    });
    if (!refreshed.ok) {
      await emit("warn", refreshed.error);
      return {
        ok: true,
        username: account,
        machines: [],
        selected: null,
        warning: refreshed.error,
      };
    }
    await emit(
      "info",
      `已选中桌面：${refreshed.selected.machineName || "未命名"} (instanceId=${refreshed.selected.instanceId})`,
    );
    return {
      ok: true,
      username: account,
      machines: refreshed.machines,
      selected: refreshed.selected,
    };
  } catch (error) {
    const warning = `登录成功，但刷新桌面列表失败：${describeError(error)}`;
    await emit("warn", warning);
    return { ok: true, username: account, machines: [], selected: null, warning };
  }
}

/**
 * 执行一轮保活。
 *
 * 流程（对应任务书 §4.3）：
 *   1. 读 credentials / selected / device
 *   2. 无 token → 可自动重登则登录，否则失败
 *   3. 无选中桌面 → 拉列表、选中并落盘
 *   4. `desktopUptime` → 解析运行时长
 *   5. `machineConnect` → 取 errorCode
 *   6. 判定 token 过期 → 重登后重跑（最多 {@link MAX_ROUND_ATTEMPTS} 次）
 *   7. 写 `state:lastRun` 与 `state:logs`，返回结果
 *
 * 设计约束：**本函数不抛异常**（除入参缺失），所有失败都转成 `{ok:false, stage, error}`，
 * 这样 Cron 的 `scheduled` 永远不会因业务失败而抛错污染 Workers 指标。
 *
 * @param {object} options 参数。
 * @param {Record<string, unknown>} [options.env] Workers env（用于 loadConfig）。
 * @param {object} options.state StateStore。
 * @param {() => Date} [options.now] 时钟。
 * @param {((level: string, message: string) => unknown)|null} [options.log] 外部日志函数。
 * @param {object|null} [options.config] 已装载配置（优先于 env）。
 * @param {((options: object) => object)|null} [options.makeClient] 客户端工厂（测试注入）。
 * @param {number} [options.attempt] 当前尝试序号（内部递归用）。
 * @returns {Promise<{ok: boolean, stage: string, uptimeSeconds: number|null, uptimeText: string|null, connectStatus: unknown, tokenExpired: boolean, error: string|null, note: string|null, attempt: number, ts: string}>} 轮次结果。
 */
export async function runKeepaliveRound({
  env = {},
  state,
  now = () => new Date(),
  log = null,
  config = null,
  makeClient = null,
  attempt = 1,
}) {
  if (!state || typeof state.getCredentials !== "function") {
    throw new TypeError("runKeepaliveRound 需要 state（由 createStore(env) 生成）");
  }
  const cfg = config || loadConfig(env);
  const emit = createLogger(state, log);
  const factory = makeClient || ((options) => new EcloudClient({ config: cfg, now, ...options }));

  /**
   * 统一收口：写 lastRun + 写日志 + 返回结构化结果。
   *
   * @param {object} result 阶段结果。
   * @returns {Promise<object>} 最终结果。
   */
  const finish = async (result) => {
    const entry = {
      ts: utc8NowText(now()),
      ok: Boolean(result.ok),
      stage: result.stage || "done",
      uptimeSeconds: typeof result.uptimeSeconds === "number" ? result.uptimeSeconds : null,
      uptimeText: typeof result.uptimeText === "string" ? result.uptimeText : null,
      connectStatus: result.connectStatus ?? "unknown",
      tokenExpired: Boolean(result.tokenExpired),
      error: result.error ?? null,
      note: result.note ?? null,
      attempt,
    };
    try {
      await state.setLastRun(entry);
    } catch (error) {
      await emit("warn", `写入 state:lastRun 失败：${describeError(error)}`);
    }
    const summary = entry.ok
      ? `第 ${entry.attempt} 轮成功｜Uptime: ${entry.uptimeText ?? "未知"}｜Connect: ${entry.connectStatus}`
      : `第 ${entry.attempt} 轮失败（${entry.stage}）｜${entry.error ?? "未提供原因"}`;
    await emit(entry.ok ? "info" : "error", summary);
    return entry;
  };

  // ---- 阶段 0：读取基础状态 ----
  let device;
  try {
    device = await state.ensureDevice();
  } catch (error) {
    return finish({ ok: false, stage: "store", error: `读取设备指纹失败：${describeError(error)}` });
  }

  let credentials;
  let selected;
  try {
    credentials = await state.getCredentials();
    selected = await state.getSelected();
  } catch (error) {
    return finish({ ok: false, stage: "store", error: `读取状态失败：${describeError(error)}` });
  }

  let accessToken = typeof credentials?.accessToken === "string" ? credentials.accessToken : "";

  // ---- 阶段 1：确保有 accessToken ----
  if (accessToken === "") {
    if (!cfg.autoRelogin) {
      return finish({
        ok: false,
        stage: "credentials",
        error: "未登录且 AUTO_RELOGIN=false：只能手动 POST /api/login",
      });
    }
    if (cfg.username === "" || cfg.password === "") {
      return finish({
        ok: false,
        stage: "credentials",
        error: "未登录且未配置 ECLOUD_USERNAME / ECLOUD_PASSWORD：无法自动重登，请手动 POST /api/login",
      });
    }
    await emit("info", "未找到 accessToken，尝试自动登录…");
    const loginResult = await login({ config: cfg, state, now, log: emit, device, makeClient });
    if (!loginResult.ok) {
      return finish({
        ok: false,
        stage: "login",
        error: loginResult.hint || "自动登录失败",
      });
    }
    credentials = await state.getCredentials();
    accessToken = typeof credentials?.accessToken === "string" ? credentials.accessToken : "";
    selected = await state.getSelected();
    if (accessToken === "") {
      return finish({
        ok: false,
        stage: "login",
        error: "登录流程返回成功，但 state:credentials 中没有 accessToken",
      });
    }
  }

  // ---- 阶段 2：确保有选中桌面 ----
  const client = factory({ accessToken, deviceUid: device.deviceUid });
  if (!selected || typeof selected.instanceId !== "string" || selected.instanceId === "") {
    await emit("info", "未找到选中桌面，正在拉取桌面列表…");
    let refreshed;
    try {
      refreshed = await refreshMachines({
        client,
        state,
        preferredInstanceId: cfg.instanceId,
        emit,
      });
    } catch (error) {
      return finish({ ok: false, stage: "machines", error: `拉取桌面列表失败：${describeError(error)}` });
    }
    if (!refreshed.ok) {
      return finish({ ok: false, stage: "machines", error: refreshed.error });
    }
    selected = refreshed.selected;
  }

  // ---- 阶段 3：查询运行时长 ----
  let uptimeResult;
  try {
    uptimeResult = await client.desktopUptime(selected.instanceId);
  } catch (error) {
    return finish({
      ok: false,
      stage: "uptime",
      error: `desktopUptime 失败（instanceId=${selected.instanceId}）：${describeError(error)}`,
    });
  }
  const uptime = extractUptime(uptimeResult);
  if (uptime.note) {
    await emit("warn", `运行时长解析降级：${uptime.note}`);
  }

  // ---- 阶段 4：会话登记 ----
  let connectResult;
  try {
    connectResult = await client.machineConnect(selected.instanceId, selected.machineId);
  } catch (error) {
    return finish({
      ok: false,
      stage: "connect",
      uptimeSeconds: uptime.uptimeSeconds,
      uptimeText: uptime.uptimeText,
      note: uptime.note,
      error: `machineConnect 失败（instanceId=${selected.instanceId}）：${describeError(error)}`,
    });
  }

  const connectEncrypted = connectResult?._encrypted === true;
  const connectStatus = connectEncrypted ? "unknown" : (connectResult?.errorCode ?? "unknown");
  const connectMessage = String(connectResult?.errorMsg ?? "");
  const tokenExpired =
    !connectEncrypted && String(connectStatus) !== "0" && /token|expire/i.test(connectMessage);

  // ---- 阶段 5：token 过期 → 重登后重跑（最多一次） ----
  if (tokenExpired) {
    if (attempt < MAX_ROUND_ATTEMPTS && cfg.autoRelogin && cfg.username !== "" && cfg.password !== "") {
      await emit(
        "warn",
        `accessToken 疑似过期（errorCode=${connectStatus}, errorMsg=${connectMessage || "无"}），重登后重跑第 ${
          attempt + 1
        } 轮`,
      );
      const relogin = await login({ config: cfg, state, now, log: emit, device, makeClient });
      if (!relogin.ok) {
        return finish({
          ok: false,
          stage: "relogin",
          uptimeSeconds: uptime.uptimeSeconds,
          uptimeText: uptime.uptimeText,
          connectStatus,
          tokenExpired: true,
          note: uptime.note,
          error: `token 已过期且重登失败：${relogin.hint || "原因未知"}`,
        });
      }
      return runKeepaliveRound({ env, state, now, log, config: cfg, makeClient, attempt: attempt + 1 });
    }
    return finish({
      ok: false,
      stage: "connect",
      uptimeSeconds: uptime.uptimeSeconds,
      uptimeText: uptime.uptimeText,
      connectStatus,
      tokenExpired: true,
      note: uptime.note,
      error: `accessToken 已过期（errorCode=${connectStatus}）：${connectMessage || "无错误信息"}${
        cfg.autoRelogin && cfg.username !== "" && cfg.password !== ""
          ? "；已达重试上限"
          : "；未配置自动重登"
      }`,
    });
  }

  // ---- 阶段 6：正常收敛 ----
  const ok = !connectEncrypted && String(connectStatus) === "0";
  let error = null;
  if (connectEncrypted) {
    error = "会话登记响应已加密，无法确认状态：未配置 ECLOUD_RSA_PRIVATE_KEY";
  } else if (!ok) {
    error = `会话登记返回非 0 错误码：${connectStatus}${connectMessage ? `（${connectMessage}）` : ""}`;
  }

  return finish({
    ok,
    stage: "done",
    uptimeSeconds: uptime.uptimeSeconds,
    uptimeText: uptime.uptimeText,
    connectStatus,
    tokenExpired: false,
    note: uptime.note,
    error,
  });
}
